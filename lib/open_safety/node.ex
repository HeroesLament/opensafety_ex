defmodule OpenSafety.Node do
  @moduledoc """
  One safety node: the object dictionary, SPDO, SNMTS and SSDOS wired
  together, with the frame dispatch of `SSCprocess.c` and the startup of
  `SSC_InitAll`.

  This is the black-channel-facing surface. The transport hands every
  received frame to `process/3` and sends what it returns; the owner calls
  `tick/2` periodically with the current consecutive time.

  ## Dispatch (SSC)

  By frame ID, `id &&& 0x39`:

    * `0x28` SNMT request -> `OpenSafety.SNMTS`
    * `0x38` SSDO request (also slim 0x3A) -> `OpenSafety.SSDOS`
    * `0x29` / `0x39` SNMT / SSDO responses (also slim 0x3B) ->
      `OpenSafety.SCM` when the node runs one (`:scm` option); otherwise
      `:no_snmt_master` / `:no_ssdo_client`, as a C build without
      `EPLS_cfg_SCM`

  SPDO frames (0x30..0x35) go to `OpenSafety.SPDO`; in the C stack the
  application's SHNF routes them there rather than the SSC.

  ## Tick

  `tick/2` runs, in this order, what a C main loop calls every cycle:
  `SNMTS_TimerCheck`, then on an SCM node `OpenSafety.SCM.tick/3` with
  the management frames left, then `SPDO_CheckRxTimeout`,
  `SPDO_BuildTxSpdo`.

  ## Statistics

  Every node keeps an `OpenSafety.SERR` (`stats/1`, or the `:serr` pid in
  `services/1` for the C-style getters). The dispatch here counts what
  the SSC and SFS count: frames that fail to decode, and SNMT/SSDO frames
  whose processing fails (`:acyc_reject`).

  ## Messages to the owner

  Every service reports to the node's owner directly:
  `{:opensafety_snmts, _, _}`, `{:opensafety_ssdos, _, _}`,
  `{:opensafety_spdo, _, _, _}`, on an SCM node `{:opensafety_scm, _, _}`,
  `{:opensafety_snmtm, _, _}` and `{:opensafety_ssdoc, _, _}`, and
  `{:opensafety_ssc, node, {:error, code, info}}` from the dispatch here.

  ## Options

    * `:objects` - the SOD (see `OpenSafety.SOD`); must contain the objects
      SNMTS and SSDOS use (see their docs)
    * `:spdo_config` - `:options` (default) or `:sod`, the SPDO
      configuration source (`OpenSafety.SPDO`'s `:config`)
    * `:tx`, `:rx` - SPDO configs (see `OpenSafety.SPDO`)
    * `:owner` - default: caller
    * `:param_set_processed`, `:max_tx_spdo` - passed to SNMTS
    * `:max_pyld`, `:max_pyld_fast` - passed to SSDOS
    * `:frame2_first` - wire order (see `OpenSafety.Frame`)
    * `:scm` - run an SCM on this node: a keyword list of
      `OpenSafety.SCM` options (`:sod` and `:owner` are this node's), or
      `true` for the defaults. Activate it with `scm_activate/1`.
  """

  use GenServer

  import Bitwise

  alias OpenSafety.{Frame, SCM, SERR, SNMTS, SPDO, SSDOS}
  alias OpenSafety.SOD.Server, as: SOD

  @snmt_req 0x28
  @snmt_resp 0x29
  @ssdo_req 0x38
  @ssdo_resp 0x39

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "One received frame. Returns `{:ok, frames_to_send}`."
  def process(node, ct, bin), do: GenServer.call(node, {:process, ct, bin})

  @doc """
  One cycle at consecutive time `ct`: timers, SCT watchdog, Tx SPDOs.
  `free_mngt` is the number of management frames that may be sent
  (SNMTS_TimerCheck's `pb_numFreeMngtFrms`). Returns frames to send.
  """
  def tick(node, ct, free_mngt \\ 1), do: GenServer.call(node, {:tick, ct, free_mngt})

  @doc "All non-zero error statistics (`OpenSafety.SERR.stats/1`)."
  def stats(node), do: SERR.stats(services(node).serr)

  @doc "The service pids: `%{sod:, spdo:, snmts:, ssdos:, scm:, serr:}` (`scm` may be nil)."
  def services(node), do: GenServer.call(node, :services)

  # Application API, delegated.
  def perform_trans_pre_op(node, ct), do: SNMTS.perform_trans_pre_op(services(node).snmts, ct)
  def pass_param_chksum_valid(node, v), do: SNMTS.pass_param_chksum_valid(services(node).snmts, v)

  def enter_op_state(node, e, g \\ 0, c \\ 0),
    do: SNMTS.enter_op_state(services(node).snmts, e, g, c)

  def sn_state(node), do: SNMTS.sn_state(services(node).snmts)
  def put_data(node, tx_no, bin), do: SPDO.put_data(services(node).spdo, tx_no, bin)
  def data_changed(node, tx_no), do: SPDO.data_changed(services(node).spdo, tx_no)
  def conn_valid(node), do: SPDO.conn_valid(services(node).spdo)
  def rx_status(node, rx_no, ct), do: SPDO.rx_status(services(node).spdo, rx_no, ct)
  def scm_activate(node), do: SCM.activate(services(node).scm)
  def scm_deactivate(node), do: SCM.deactivate(services(node).scm)
  def scm_operator_ack(node, hdl), do: SCM.operator_ack(services(node).scm, hdl)
  def scm_sn_fail_ack(node, hdl, g, c), do: SCM.sn_fail_ack(services(node).scm, hdl, g, c)
  def scm_reset_node_guarding(node), do: SCM.reset_node_guarding(services(node).scm)

  @impl true
  def init(opts) do
    owner = Keyword.fetch!(opts, :owner)
    f2f = Keyword.get(opts, :frame2_first, false)

    {:ok, sod} = SOD.start_link(Keyword.fetch!(opts, :objects))

    case check_sdn(sod) do
      :ok ->
        start_services(opts, owner, f2f, sod)

      {:error, code, info} ->
        send(owner, {:opensafety_ssc, self(), {:error, code, info}})
        {:stop, {:sdn, code, info}}
    end
  end

  # SDN_Init / getCheckSdn: 0x1200/1 must exist and be readable without a
  # callback.
  defp check_sdn(sod) do
    case SOD.attr_get(sod, 0x1200, 1) do
      {:ok, _h, %{attr: attr}} ->
        if :bef_rd in attr, do: {:error, :attr_inv, 0x1200_0100}, else: :ok

      {:error, _, abort} ->
        {:error, :attr_inv, abort}
    end
  end

  defp start_services(opts, owner, f2f, sod) do
    {:ok, serr} = SERR.start_link()

    spdo =
      SPDO.start_link(
        sod: sod,
        owner: owner,
        serr: serr,
        config: Keyword.get(opts, :spdo_config, :options),
        tx: Keyword.get(opts, :tx, []),
        rx: Keyword.get(opts, :rx, []),
        frame2_first: f2f
      )

    case spdo do
      {:ok, spdo} -> start_rest(opts, owner, f2f, sod, serr, spdo)
      {:error, reason} -> {:stop, reason}
    end
  end

  defp start_rest(opts, owner, f2f, sod, serr, spdo) do
    # Before SNMTS, which drives it for SCM SET TO STOP / SET TO OP.
    scm =
      case Keyword.get(opts, :scm) do
        nil ->
          nil

        false ->
          nil

        scm_opts ->
          scm_opts = if scm_opts == true, do: [], else: scm_opts
          {:ok, scm} = SCM.start_link(Keyword.merge(scm_opts, sod: sod, owner: owner, serr: serr))
          scm
      end

    snmts_opts =
      [sod: sod, spdo: spdo, scm: scm, owner: owner] ++
        Keyword.take(opts, [:param_set_processed, :max_tx_spdo])

    {:ok, snmts} = SNMTS.start_link(snmts_opts)

    ssdos_opts =
      [sod: sod, snmts: snmts, owner: owner] ++ Keyword.take(opts, [:max_pyld, :max_pyld_fast])

    {:ok, ssdos} = SSDOS.start_link(ssdos_opts)

    {:ok,
     %{
       sod: sod,
       spdo: spdo,
       snmts: snmts,
       ssdos: ssdos,
       scm: scm,
       serr: serr,
       owner: owner,
       f2f: f2f
     }}
  end

  @impl true
  def handle_call(:services, _from, s),
    do: {:reply, Map.take(s, [:sod, :spdo, :snmts, :ssdos, :scm, :serr]), s}

  def handle_call({:process, ct, bin}, _from, s) do
    out =
      case Frame.decode(bin, udid(s), frame2_first: s.f2f) do
        {:ok, f} ->
          dispatch(s, ct, f)

        # processStateDeSer: counted by SFS, not as a reject.
        {:error, reason} ->
          :ok = SERR.count_decode(s.serr, reason)
          error(s, :decode, reason)
      end

    {:reply, {:ok, Enum.map(out, &encode(s, &1))}, s}
  end

  def handle_call({:tick, ct, free_mngt}, _from, s) do
    snmts = SNMTS.timer_check(s.snmts, ct, free_mngt)

    scm =
      if s.scm do
        {_free, frames} = SCM.tick(s.scm, ct, max(free_mngt - length(snmts), 0))
        frames
      else
        []
      end

    mngt = Enum.map(snmts ++ scm, &encode(s, &1))
    :ok = SPDO.check_timeout(s.spdo, ct)
    spdo = SPDO.build(s.spdo, ct)
    {:reply, mngt ++ spdo, s}
  end

  # processStateReqProc
  defp dispatch(s, ct, %Frame{id: id} = f) do
    cond do
      id >= 0x30 and id <= 0x35 ->
        _ = SPDO.process(s.spdo, ct, f)
        []

      (id &&& 0x39) == @snmt_req ->
        reply(s, SNMTS.process_request(s.snmts, ct, f))

      (id &&& 0x39) == @ssdo_req ->
        reply(s, SSDOS.process_request(s.ssdos, f))

      (id &&& 0x39) in [@snmt_resp, @ssdo_resp] and s.scm != nil ->
        case SCM.process_response(s.scm, ct, f) do
          {true, frames} -> frames
          {false, frames} -> reject(s) ++ frames
        end

      (id &&& 0x39) == @snmt_resp ->
        reject(s) ++ error(s, :no_snmt_master, id)

      (id &&& 0x39) == @ssdo_resp ->
        reject(s) ++ error(s, :no_ssdo_client, id)

      true ->
        reject(s) ++ error(s, :rx_teltyp_inv, id)
    end
  end

  defp reply(_s, {:reply, f}), do: [f]
  defp reply(_s, :noreply), do: []
  defp reply(s, :rejected), do: reject(s)

  # SSC_ProcessSNMTSSDOFrame: processing failed, frame rejected.
  defp reject(s) do
    :ok = SERR.count_common(s.serr, :acyc_reject)
    []
  end

  defp encode(s, f) do
    {:ok, bin} = Frame.encode(f, udid(s), frame2_first: s.f2f)
    bin
  end

  # SF2 is coded with the SCM's UDID (0x1200/4) once assigned; SNMT frames
  # are not coded, so the value before assignment does not matter.
  defp udid(s) do
    case SOD.get(s.sod, 0x1200, 4) do
      {:ok, <<_::binary-size(6)>> = u} -> u
      _ -> <<0::48>>
    end
  end

  defp error(s, code, info) do
    send(s.owner, {:opensafety_ssc, self(), {:error, code, info}})
    []
  end
end
