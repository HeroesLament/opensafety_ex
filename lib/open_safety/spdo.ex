defmodule OpenSafety.SPDO do
  @moduledoc """
  SPDO layer of one safety node: `SPDOmain.c` as a `gen_statem`.

  ## States

    * `:pre_operational` - SPDOs inactive; received SPDOs are ignored
      without error and nothing is built (`o_spdoRunning` false).
    * `:operational` - entered with `set_to_op/2`, which resets every Tx
      and Rx SPDO (`SPDO_SetToOp`); `set_to_pre_op/1` leaves it
      (`SPDO_SetToPreOp`). SNMT drives these transitions.

  Each Tx SPDO is an `OpenSafety.SPDO.Tx` and each Rx SPDO an
  `OpenSafety.SPDO.Rx`, linked to this process. Calls only go downward
  (this process to Rx to Tx, or this process to Tx), so the call graph has
  no cycles and every operation runs in the C stack's order.

  ## Configuration

  Two sources:

    * `config: :options` (default) - `:tx` / `:rx` lists of config maps
      (see `OpenSafety.SPDO.Tx` and `OpenSafety.SPDO.Rx`); process data
      through `put_data/3`.
    * `config: :sod` - the C's way (`SPDO_InitAll`, see
      `OpenSafety.SPDO.Config`): SPDOs, communication parameters and
      mappings come from the object dictionary given as `:sod`. Tx process
      data is read from the mapped objects, Rx process data written into
      them; the application signals new data with `data_changed/2`. The
      parameters and mappings are read again at `activate_mapping/1`.

  ## Time

  Every operation takes the consecutive time `ct` (any 32-bit counter, in
  whatever tick the configuration's times are expressed in). Nothing here
  reads a clock: the owner ticks it, which is what makes the layer
  testable in lockstep against the C stack.

  ## Operations (C equivalents)

    * `process/3` - `SPDO_ProcessRxSpdo`, one received frame
    * `build/3` - `SPDO_BuildTxSpdo`: TRes pass, TReq pass, data pass
    * `build_one/3` - `SPDO_BuildTxSpdoIx`: the same for one Tx SPDO and
      the Rx SPDO that synchronizes over it, at most one frame
    * `check_timeout/2` - `SPDO_CheckRxTimeout`, the SCT watchdog
    * `put_data/3` (options) / `data_changed/2` - `SPDO_TxDataChanged`
    * `rx_status/3` - `SPDO_GetRxSpdoStatus`
    * `conn_valid/1` - the connection-valid bit field and statistic
    * `activate_mapping/1` - `SPDO_ActivateTxSpdoMapping` and
      `SPDO_ActivateRxSpdoMapping`

  ## Events

  Sent to the owner as `{:opensafety_spdo, node, rx_no, event}`, with
  `event` as documented in `OpenSafety.SPDO.Rx`, or with `rx_no` nil for
  node-level errors (`{:error, :unknown_sdn, sdn}`, `{:error,
  :invalid_id, id}`, `{:error, :decode, reason}`, activation and
  configuration errors).

  ## Options for start_link/1

    * `:config` - `:options` or `:sod`, see above
    * `:sod` - the node's `OpenSafety.SOD.Server`; when given, the SDN
      (0x1200/1) and the SCM's UDID (0x1200/4) are read from it on every
      use, as `SDN_GetSdn` does, so SNMT assignment takes effect at once
    * `:sdn` - static safety domain number, without `:sod`
    * `:scm_udid` - static six-byte UDID of the SCM, without `:sod`
    * `:owner` - pid for events (default: caller)
    * `:tx` - list of Tx SPDO configs, SPDO number = position (1-based)
    * `:rx` - list of Rx SPDO configs, likewise
    * `:frame2_first` - wire order, see `OpenSafety.Frame` (default false)
    * `:serr` - `OpenSafety.SERR`: `:cyc_reject` for SPDOs of another
      domain or for which there is no Rx SPDO, decode failures, and every
      Rx SPDO's own counters (see `OpenSafety.SPDO.Rx`)
  """

  @behaviour :gen_statem

  import Bitwise

  alias OpenSafety.{Frame, SERR}
  alias OpenSafety.SPDO.{Config, Rx, Tx}

  # k_FRAME_MASK_SPDO_TYPE
  @type_mask 0x36
  @id_data 0x30
  @id_treq 0x32
  @id_tres 0x34

  @max_budget 255
  @max_sadr 0x3FF

  ## API

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    :gen_statem.start_link(__MODULE__, opts, [])
  end

  def set_to_op(node, ct), do: :gen_statem.call(node, {:set_to_op, ct})
  def set_to_pre_op(node), do: :gen_statem.call(node, :set_to_pre_op)

  @doc "Process one received SPDO frame (wire binary or decoded `Frame`)."
  def process(node, ct, frame), do: :gen_statem.call(node, {:process, ct, frame})

  @doc "Build the frames due at `ct`, at most `budget`. Returns wire binaries."
  def build(node, ct, budget \\ @max_budget), do: :gen_statem.call(node, {:build, ct, budget})

  @doc """
  SPDO_BuildTxSpdoIx: the three passes for Tx SPDO `tx_no` only (and the
  Rx SPDO synchronizing over it), at most one frame. `{1, [bin]}` if a
  frame was built, else `{0, []}`.
  """
  def build_one(node, ct, tx_no), do: :gen_statem.call(node, {:build_one, ct, tx_no})

  def check_timeout(node, ct), do: :gen_statem.call(node, {:check, ct})

  @doc "New Tx process data (configuration from options)."
  def put_data(node, tx_no, bin), do: :gen_statem.call(node, {:put_data, tx_no, bin})

  @doc "SPDO_TxDataChanged: send Tx SPDO `tx_no` at the next build."
  def data_changed(node, tx_no), do: :gen_statem.call(node, {:data_changed, tx_no})

  def rx_status(node, rx_no, ct), do: :gen_statem.call(node, {:rx_status, rx_no, ct})

  @doc """
  `{bits, edges}`: the connection-valid bit field (bit `rx_no - 1`) and,
  per Rx SPDO, how often its connection went from valid to invalid.
  """
  def conn_valid(node), do: :gen_statem.call(node, :conn_valid)

  @doc """
  SPDO_ActivateTxSpdoMapping / SPDO_ActivateRxSpdoMapping, in the C's
  order: every Tx SPDO address unique and valid (SPDO_AddTAdr) and its
  mapping complete (SPDO_TxMappActivate); then every Rx SPDO the only one
  synchronizing over its Tx SPDO (SPDO_ConsSmConnect), its source address
  unique and not one of ours (SPDO_AddSAdr), that Tx SPDO active
  (SPDO_TxSpdoIdxExists), and its mapping complete. Returns `:ok`,
  `{:error, :tx}` or `{:error, :rx}`; SNMTS answers the latter two with
  SN FAIL.
  """
  def activate_mapping(node), do: :gen_statem.call(node, :activate_mapping)

  ## gen_statem

  @impl true
  def callback_mode, do: :state_functions

  @impl true
  def init(opts) do
    sod = Keyword.get(opts, :sod)
    sdn = Keyword.get(opts, :sdn, 1)
    serr = Keyword.get(opts, :serr)
    mode = Keyword.get(opts, :config, :options)
    owner = Keyword.fetch!(opts, :owner)

    cfgs =
      case mode do
        :options -> {:ok, %{tx: Keyword.get(opts, :tx, []), rx: Keyword.get(opts, :rx, [])}}
        :sod -> Config.init(sod)
      end

    case cfgs do
      {:ok, %{tx: tx_cfgs, rx: rx_cfgs}} ->
        d = %{
          mode: mode,
          sod: sod,
          sdn: sdn,
          udid: Keyword.get(opts, :scm_udid, <<0::48>>),
          owner: owner,
          serr: serr,
          f2f: Keyword.get(opts, :frame2_first, false),
          tx: [],
          rx: [],
          sync: %{},
          conn: %{},
          n_proc_tx: length(tx_cfgs)
        }

        d = start_spdos(d, tx_cfgs, rx_cfgs)
        {:ok, :pre_operational, %{d | conn: default_conn(d.rx)}}

      {:error, code, info} ->
        send(owner, {:opensafety_spdo, self(), nil, {:error, code, info}})
        {:stop, {:spdo_init, code, info}}
    end
  end

  defp start_spdos(d, tx_cfgs, rx_cfgs) do
    Enum.each(d.tx ++ d.rx, &:gen_statem.stop(&1.pid))
    sdn = d.sdn
    extra = if d.mode == :sod, do: %{sod: d.sod}, else: %{}

    tx =
      number(tx_cfgs)
      |> Enum.map(fn {no, cfg} ->
        {:ok, pid} = Tx.start_link(Map.merge(cfg, extra), sdn)
        %{no: no, pid: pid, sadr: cfg.sadr, cfg: cfg}
      end)

    rx =
      number(rx_cfgs)
      |> Enum.map(fn {no, cfg} ->
        {:ok, pid} = Rx.start_link(Map.merge(cfg, Map.merge(extra, %{serr: d.serr, idx: no - 1})))
        %{no: no, pid: pid, sadr: cfg.sadr, tx_no: Map.get(cfg, :tx_spdo_no, 0), cfg: cfg}
      end)

    %{d | tx: tx, rx: rx, sync: Map.new(rx, fn r -> {r.no, false} end)}
  end

  # Before any activation: the first active Rx SPDO per Tx SPDO.
  defp default_conn(rx) do
    rx
    |> active()
    |> Enum.reverse()
    |> Map.new(fn r -> {r.tx_no, r.no} end)
  end

  ## States

  def pre_operational({:call, from}, {:set_to_op, ct}, d) do
    Enum.each(d.tx, fn t -> :ok = Tx.reset(t.pid, ct) end)
    d = reset_rx(d)
    {:next_state, :operational, d, [{:reply, from, :ok}]}
  end

  # Not running: frames ignored without error, nothing built or checked.
  def pre_operational({:call, from}, {:process, _ct, _frame}, d),
    do: {:next_state, :pre_operational, d, [{:reply, from, :ok}]}

  def pre_operational({:call, from}, {:build, _ct, _budget}, d),
    do: {:next_state, :pre_operational, d, [{:reply, from, []}]}

  def pre_operational({:call, from}, {:build_one, _ct, _tx_no}, d),
    do: {:next_state, :pre_operational, d, [{:reply, from, {0, []}}]}

  def pre_operational({:call, from}, {:check, _ct}, d),
    do: {:next_state, :pre_operational, d, [{:reply, from, :ok}]}

  def pre_operational(type, msg, d), do: common(:pre_operational, type, msg, d)

  def operational({:call, from}, :set_to_pre_op, d) do
    d = reset_rx(d)
    {:next_state, :pre_operational, d, [{:reply, from, :ok}]}
  end

  def operational({:call, from}, {:process, ct, frame}, d) do
    {reply, d} =
      case decode(frame, d) do
        {:ok, f} ->
          {:ok, dispatch(d, ct, f)}

        {:error, reason} ->
          :ok = SERR.count_decode(d.serr, reason)
          emit(d, nil, {:error, :decode, reason})
          {{:error, reason}, d}
      end

    {:next_state, :operational, d, [{:reply, from, reply}]}
  end

  def operational({:call, from}, {:build, ct, budget}, d) do
    {frames, d} = build_pass(d, ct, budget)
    {:next_state, :operational, d, [{:reply, from, encode_all(frames, d)}]}
  end

  def operational({:call, from}, {:build_one, ct, tx_no}, d) do
    {reply, d} =
      case find(d.tx, :no, tx_no) do
        t when t != nil and tx_no <= d.n_proc_tx ->
          {frames, d} = build_ix(d, ct, t)
          {{length(frames), encode_all(frames, d)}, d}

        _ ->
          emit(d, nil, {:error, :free_frame_ptr_1, 0})
          {{0, []}, d}
      end

    {:next_state, :operational, d, [{:reply, from, reply}]}
  end

  def operational({:call, from}, {:check, ct}, d) do
    d =
      Enum.reduce(d.rx, d, fn r, d ->
        {ev, :ok, ok} = Rx.check_timeout(r.pid, ct)
        rx_reply(d, r.no, ev, ok)
      end)

    {:next_state, :operational, d, [{:reply, from, :ok}]}
  end

  def operational(type, msg, d), do: common(:operational, type, msg, d)

  defp common(state, {:call, from}, {:put_data, tx_no, bin}, d) do
    reply =
      case find(d.tx, :no, tx_no) do
        nil -> {:error, :no_such_spdo}
        t -> Tx.put_data(t.pid, bin)
      end

    {:next_state, state, d, [{:reply, from, reply}]}
  end

  # SPDO_TxDataChanged, SPDO_NewData, SPDO_TxSpdoIdxExists
  defp common(state, {:call, from}, {:data_changed, tx_no}, d) do
    reply =
      cond do
        tx_no < 1 or tx_no > Config.max_tx() ->
          emit(d, nil, {:error, :tx_spdo_num_4, tx_no})
          {:error, :tx_spdo_num_4}

        true ->
          case tx_exists(d, tx_no - 1) do
            {:ok, t} ->
              Tx.data_changed(t.pid)

            {:error, code} ->
              emit(d, nil, {:error, code, tx_no - 1})
              {:error, code}
          end
      end

    {:next_state, state, d, [{:reply, from, reply}]}
  end

  defp common(state, {:call, from}, {:rx_status, rx_no, ct}, d) do
    {reply, d} =
      case find(d.rx, :no, rx_no) do
        nil ->
          {{:error, :no_such_spdo}, d}

        r ->
          {[], status, ok} = Rx.status(r.pid, ct)
          {status, put_in(d.sync[r.no], ok)}
      end

    {:next_state, state, d, [{:reply, from, reply}]}
  end

  defp common(state, {:call, from}, :conn_valid, d) do
    {bits, edges} =
      Enum.reduce(d.rx, {0, %{}}, fn r, {bits, edges} ->
        {valid, n} = Rx.conn_valid(r.pid)
        bits = if valid, do: bits ||| 1 <<< (r.no - 1), else: bits
        {bits, Map.put(edges, r.no, n)}
      end)

    {:next_state, state, d, [{:reply, from, {bits, edges}}]}
  end

  defp common(state, {:call, from}, :activate_mapping, d) do
    {reply, d} = activate(d)
    {:next_state, state, d, [{:reply, from, reply}]}
  end

  defp common(state, {:call, from}, {:set_to_op, _ct}, d),
    do: {:next_state, state, d, [{:reply, from, {:error, {:already, state}}}]}

  defp common(state, {:call, from}, :set_to_pre_op, d),
    do: {:next_state, state, d, [{:reply, from, {:error, {:already, state}}}]}

  ## Mapping activation (SPDOmain.c, SPDOassign.c)

  defp activate(d) do
    case reload(d) do
      {:ok, d} ->
        with {:ok, taddrs, tx_lens} <- activate_tx(d),
             {:ok, conn, rx_lens} <- activate_rx(d, taddrs) do
          d = if d.mode == :sod, do: restart_with_lens(d, tx_lens, rx_lens), else: d

          n_proc =
            d.tx |> Enum.filter(&(&1.sadr != 0)) |> Enum.map(& &1.no) |> Enum.max(fn -> 0 end)

          {:ok, %{d | conn: conn, n_proc_tx: n_proc}}
        else
          {:error, dir, code, info} ->
            emit(d, nil, {:error, code, info})
            {{:error, dir}, d}
        end

      {:error, dir, code, info, d} ->
        emit(d, nil, {:error, code, info})
        {{:error, dir}, d}
    end
  end

  # The C reads parameters through pointers and mapping entries as they are
  # written; here both are read again from the SOD.
  defp reload(%{mode: :options} = d), do: {:ok, d}

  defp reload(d) do
    reread = fn dir, spdos ->
      Enum.reduce_while(spdos, {:ok, []}, fn s, {:ok, acc} ->
        with {:ok, comm} <- Config.comm_para(d.sod, dir, s.cfg.comm),
             {:ok, mapping} <- Config.mapping(d.sod, dir, s.cfg.mapp) do
          {:cont, {:ok, [Map.merge(s.cfg, Map.put(comm, :mapping, mapping)) | acc]}}
        else
          {:error, code, info} -> {:halt, {:error, dir, code, info}}
        end
      end)
    end

    with {:ok, tx} <- reread.(:tx, d.tx),
         {:ok, rx} <- reread.(:rx, d.rx) do
      {:ok, start_spdos(d, Enum.reverse(tx), Enum.reverse(rx))}
    else
      {:error, dir, code, info} -> {:error, dir, code, info, d}
    end
  end

  defp activate_tx(d) do
    Enum.reduce_while(d.tx, {:ok, MapSet.new(), %{}}, fn t, {:ok, taddrs, lens} ->
      idx = t.no - 1

      cond do
        t.sadr != 0 and (t.sadr > @max_sadr or MapSet.member?(taddrs, t.sadr)) ->
          {:halt, {:error, :tx, :tadr, idx}}

        true ->
          taddrs = if t.sadr == 0, do: taddrs, else: MapSet.put(taddrs, t.sadr)

          case mapp_activate(d, :tx, idx, t.cfg) do
            {:ok, len} -> {:cont, {:ok, taddrs, Map.put(lens, t.no, len)}}
            {:error, code, info} -> {:halt, {:error, :tx, code, info}}
          end
      end
    end)
  end

  defp activate_rx(d, taddrs) do
    Enum.reduce_while(d.rx, {:ok, %{}, MapSet.new(), %{}}, fn r, {:ok, conn, saddrs, lens} ->
      idx = r.no - 1
      tx_no = if r.sadr != 0, do: r.tx_no, else: 0

      cond do
        # SPDO_ConsSmConnect: one Rx SPDO per Tx SPDO (SPDO_cfg_MAX_SYNC_RX_SPDO).
        tx_no >= 1 and tx_no <= Config.max_tx() and Map.has_key?(conn, tx_no) ->
          {:halt, {:error, :rx, :tx_no_rx_conn_1, tx_no - 1}}

        # SPDO_AddSAdr: not ours, not twice.
        r.sadr != 0 and
            (r.sadr > @max_sadr or MapSet.member?(taddrs, r.sadr) or
               MapSet.member?(saddrs, r.sadr)) ->
          {:halt, {:error, :rx, :sadr, idx}}

        true ->
          conn =
            if tx_no >= 1 and tx_no <= Config.max_tx(), do: Map.put(conn, tx_no, r.no), else: conn

          saddrs = if r.sadr == 0, do: saddrs, else: MapSet.put(saddrs, r.sadr)

          with :ok <- rx_tx_exists(d, r),
               {:ok, len} <- mapp_activate(d, :rx, idx, r.cfg) do
            {:cont, {:ok, conn, saddrs, Map.put(lens, r.no, len)}}
          else
            {:error, code, info} -> {:halt, {:error, :rx, code, info}}
          end
      end
    end)
    |> case do
      {:ok, conn, _saddrs, lens} -> {:ok, conn, lens}
      error -> error
    end
  end

  defp rx_tx_exists(_d, %{sadr: 0}), do: :ok

  defp rx_tx_exists(d, r) do
    case tx_exists(d, r.tx_no - 1) do
      {:ok, _} -> :ok
      {:error, code} -> {:error, code, r.tx_no - 1}
    end
  end

  # SPDO_TxSpdoIdxExists
  defp tx_exists(d, idx) do
    if idx < 0 or idx >= Config.max_tx() do
      {:error, :tx_spdo_num_3}
    else
      case find(d.tx, :no, idx + 1) do
        nil -> {:error, :tx_spdo_num_2}
        %{sadr: 0} -> {:error, :tx_spdo_num_1}
        t -> {:ok, t}
      end
    end
  end

  defp mapp_activate(%{mode: :sod}, dir, idx, cfg), do: Config.activate(dir, idx, cfg.mapping)
  defp mapp_activate(_d, _dir, _idx, cfg), do: {:ok, Map.get(cfg, :len, 0)}

  defp restart_with_lens(d, tx_lens, rx_lens) do
    tx = Enum.map(d.tx, fn t -> Map.put(t.cfg, :len, tx_lens[t.no]) end)
    rx = Enum.map(d.rx, fn r -> Map.put(r.cfg, :len, rx_lens[r.no]) end)
    start_spdos(d, tx, rx)
  end

  ## SPDO_ProcessRxSpdo dispatch

  defp dispatch(d, ct, %Frame{} = f) do
    cond do
      f.sdn != sdn(d) ->
        :ok = SERR.count_common(d.serr, :cyc_reject)
        emit(d, nil, {:error, :unknown_sdn, f.sdn})
        d

      (f.id &&& @type_mask) == @id_treq ->
        # ProcessTReq: the Tx SPDO it addresses answers it; the Rx SPDO
        # for its source takes its data.
        case find(d.tx, :sadr, f.tadr) do
          nil -> :ok
          t -> Enum.each(Tx.treq(t.pid, f), &emit(d, nil, &1))
        end

        rx_call(d, f.adr, fn r -> Rx.data(r.pid, ct, f) end)

      (f.id &&& @type_mask) == @id_tres ->
        for_us = find(d.tx, :sadr, f.tadr) != nil
        rx_call(d, f.adr, fn r -> Rx.tres(r.pid, ct, f, for_us) end)

      (f.id &&& @type_mask) == @id_data ->
        rx_call(d, f.adr, fn r -> Rx.data(r.pid, ct, f) end)

      true ->
        emit(d, nil, {:error, :invalid_id, f.id})
        d
    end
  end

  # SPDO_GetSpdoIdxForSAdr: the active Rx SPDO configured for this source;
  # none means the SPDO is not relevant here (SERR_k_CYC_REJECT).
  defp rx_call(d, adr, fun) do
    case find(active(d.rx), :sadr, adr) do
      nil ->
        :ok = SERR.count_common(d.serr, :cyc_reject)
        d

      r ->
        {ev, :ok, ok} = fun.(r)
        rx_reply(d, r.no, ev, ok)
    end
  end

  ## SPDO_BuildTxSpdo: three passes, in this order

  defp build_pass(d, ct, budget) do
    # 1. Time responses.
    {acc, budget} =
      Enum.reduce(d.tx, {[], budget}, fn t, {acc, budget} ->
        {frames, budget} = Tx.build_tres(t.pid, ct, conn_valid?(d, t.no), budget)
        {acc ++ frames, budget}
      end)

    # 2. Time requests, through each Rx SPDO's Tx SPDO.
    {acc, budget, d} =
      Enum.reduce(active(d.rx), {acc, budget, d}, fn r, {acc, budget, d} ->
        {frames, budget, d} = rx_build(d, ct, r, budget)
        {acc ++ frames, budget, d}
      end)

    # 3. Data.
    {acc, _budget} =
      Enum.reduce(d.tx, {acc, budget}, fn t, {acc, budget} ->
        {frames, budget} = Tx.build_data(t.pid, ct, conn_valid?(d, t.no), budget)
        {acc ++ frames, budget}
      end)

    {acc, d}
  end

  defp rx_build(d, ct, r, budget) do
    case find(d.tx, :no, r.tx_no) do
      nil ->
        {[], budget, d}

      t ->
        {ev, {frames, budget}, ok} = Rx.build(r.pid, ct, t.pid, conn_valid?(d, t.no), budget)
        {frames, budget, rx_reply(d, r.no, ev, ok)}
    end
  end

  # SPDO_BuildTxSpdoIx: one frame at most, for one Tx SPDO and the Rx SPDO
  # connected to it (aw_TxRxConn).
  defp build_ix(d, ct, t) do
    {frames, budget} = Tx.build_tres(t.pid, ct, conn_valid?(d, t.no), 1)

    {more, budget, d} =
      with 1 <- budget,
           rx_no when rx_no != nil <- d.conn[t.no],
           %{sadr: sadr} = r when sadr != 0 <- find(d.rx, :no, rx_no) do
        rx_build(d, ct, r, budget)
      else
        _ -> {[], budget, d}
      end

    frames = frames ++ more

    # With the frame spent this only frees the latched request (as pass 3).
    {data, _budget} = Tx.build_data(t.pid, ct, conn_valid?(d, t.no), budget)

    {frames ++ data, d}
  end

  # GetConnectionValid: the Rx SPDO synchronizing over this Tx SPDO, if
  # any, has completed time synchronization.
  defp conn_valid?(d, tx_no) do
    case d.conn[tx_no] do
      nil -> true
      rx_no -> Map.get(d.sync, rx_no, false)
    end
  end

  ## Helpers

  defp reset_rx(d) do
    Enum.each(d.rx, fn r -> {[], :ok, false} = Rx.reset(r.pid) end)
    %{d | sync: Map.new(d.rx, fn r -> {r.no, false} end)}
  end

  defp rx_reply(d, no, events, sync_ok) do
    Enum.each(events, &emit(d, no, &1))
    put_in(d.sync[no], sync_ok)
  end

  defp emit(d, rx_no, event), do: send(d.owner, {:opensafety_spdo, self(), rx_no, event})

  defp decode(%Frame{} = f, _d), do: {:ok, f}
  defp decode(bin, d) when is_binary(bin), do: Frame.decode(bin, udid(d), frame2_first: d.f2f)

  defp encode_all(frames, d) do
    sdn = sdn(d)
    Enum.map(frames, &encode(%{&1 | sdn: sdn}, d))
  end

  defp encode(f, d) do
    {:ok, bin} = Frame.encode(f, udid(d), frame2_first: d.f2f)
    bin
  end

  defp sdn(%{sod: nil, sdn: sdn}), do: sdn
  defp sdn(%{sod: sod}), do: sod_value(sod, 0x1200, 1, 0)

  defp udid(%{sod: nil, udid: udid}), do: udid
  defp udid(%{sod: sod}), do: sod_value(sod, 0x1200, 4, <<0::48>>)

  defp sod_value(sod, i, s, default) do
    case OpenSafety.SOD.Server.get(sod, i, s) do
      {:ok, v} -> v
      _ -> default
    end
  end

  defp active(spdos), do: Enum.filter(spdos, fn s -> s.sadr != 0 end)

  defp find(list, key, value), do: Enum.find(list, fn x -> Map.fetch!(x, key) == value end)

  defp number(cfgs), do: Enum.zip(1..max(length(cfgs), 1)//1, cfgs)
end
