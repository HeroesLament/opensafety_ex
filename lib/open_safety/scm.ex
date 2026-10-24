defmodule OpenSafety.SCM do
  @moduledoc """
  Safety Configuration Manager (`SCMmain.c`, `SCMbase.c`): configures,
  verifies, starts and guards the safety nodes listed in its own SOD.

  A `gen_statem` with the two states of the C `o_Stopped` flag,
  `:stopped` and `:active`, owning:

    * `OpenSafety.SNMTM` - the SNMT request slots
    * `OpenSafety.SSDOC` - the SSDO transfer slots
    * one `OpenSafety.SCM.SN` per configured safety node, the 26-state
      configuration machine

  ## Why the SNs are processes and the slots are not

  In C the SN state functions call the SNMTM/SSDOC request functions, and
  SNMTM/SSDOC call back into the SCM (`SCM_SNMTM_RespClbk`,
  `SCM_SsdocClbk`). As processes, calls only ever go one way: SCM -> SN ->
  SNMTM/SSDOC (and the SOD). SNMTM and SSDOC never call anyone; their
  "callbacks" come back as effects in the reply to whoever called them,
  and the SCM delivers those to the SN they belong to. No process ever
  calls one that may be calling it.

  ## Driving it

    * `process_response/3` - an SNMT (0x29 group) or SSDO (0x39 group)
      response addressed to the SCM; returns `{ok, frames}`: whether
      `SNMTM_ProcessResponse` / `SSDOC_ProcessResponse` succeeded, and the
      frames to send (the next segment of an SSDO transfer)
    * `tick/3` - once per cycle with the free management frames: SNMTM and
      SSDOC timeouts and retransmissions (`SNMTM_BuildRequest`,
      `SSDOC_BuildRequest`), then `SCM_Trigger` when active, which visits
      `:per_call` SNs round robin. Returns `{free, frames}`.

  The C leaves the order of those three to the application; here the
  repetitions come first, so timeouts they detect are seen by the SN in
  the same tick.

  ## Application interface

    * `activate/1` (`SCM_Activate`) - reads the configuration from the SOD
      and starts every SN machine from scratch; `deactivate/1`
    * `reset_node_guarding/1`, `operator_ack/2`, `sn_fail_ack/4`

  Callbacks (`SAPL_Scm*Clbk`) are messages to the owner,
  `{:opensafety_scm, scm, msg}`:

    * `{:node_status, sadr, old, new}` - statuses `:missing`, `:invalid`,
      `:wrong_sadr`, `:udid_mismatch`, `:wrong_param`, `:wrong_add_param`,
      `:valid`, `:ok` (also written to 0xC400+sn/5 as `SCM_k_NS_*`)
    * `{:udid_mismatch, sadr, udid, hdl}` - answer with `operator_ack/2`
      (ACM)
    * `{:sn_fail, sadr, group, code, hdl}` - answer with `sn_fail_ack/4`
    * `{:error, code, info}`

  The synchronous C callbacks are functions: `:process_sn`
  (`SAPL_ScmProcessSn`, `fn sadr -> boolean end`, default true) and
  `:revision_ok` (`SAPL_ScmRevisionNumberClbk`, `fn sadr, expected,
  received -> boolean end`, default equality).

  ## Objects used

  0x100C/1 guard time; 0x101B/1 configuration mode (0 ACM, 1 MCM);
  0x1200/1 SDN, /2 SCM SADR, /4 SCM UDID; 0x1201/1,2 SSDO timeout and
  retries; 0x1202/1,2 SNMT timeout and retries. Per SN `n` (from 0,
  until the first missing 0xC400+n/1): 0xC400+n /1 SADR, /2 vendor ID,
  /3 product code, /4 revision, /5 status (written), /7 parameter
  timestamp, /8 max SSDO payload, /9 poll interval, /10 parameter length
  and /11 parameter set (optional), /14 parameter checksum, /15 remote
  checksum buffer; 0xCC00+sadr /0 count, /1.. UDIDs; 0xC801+i/1 main
  SADR of additional SADR i+1, 0xC800+sadr/2 its Tx SPDO number;
  0xE400+n additional parameter sets.

  ## Deviation

  `SCM_Activate` clears the stopped flag even when the configuration
  cannot be read, and `SCM_Trigger` then divides by the number of nodes
  found. Here a failed activation stays `:stopped`.

  ## Options

    * `:sod` - `OpenSafety.SOD.Server` (required)
    * `:owner` - default: caller
    * `:max_nodes` - `SCM_cfg_MAX_NUM_OF_NODES`, also the SNMTM/SSDOC slot
      count (default 101)
    * `:per_call` - `SCM_cfg_NUM_OF_PROCESSED_NODES_PER_CALL` (default 1)
    * `:max_pyld` - passed to SSDOC
    * `:serr` - `OpenSafety.SERR`, passed to SNMTM and SSDOC
    * `:process_sn`, `:revision_ok` - see above
  """

  @behaviour :gen_statem

  import Bitwise

  alias OpenSafety.{Frame, SNMTM, SSDOC}
  alias OpenSafety.SCM.SN
  alias OpenSafety.SOD.Server, as: SOD

  @max_sadr 0x3FF

  ## API

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    :gen_statem.start_link(__MODULE__, opts, [])
  end

  @doc "SCM_Activate: `true` if at least one SN is configured."
  def activate(scm), do: :gen_statem.call(scm, :activate)

  @doc "SCM_Deactivate"
  def deactivate(scm), do: :gen_statem.call(scm, :deactivate)

  @doc "SCM_ResetNodeGuarding"
  def reset_node_guarding(scm), do: :gen_statem.call(scm, :reset_node_guarding)

  @doc "SCM_OperatorAck"
  def operator_ack(scm, hdl), do: :gen_statem.call(scm, {:operator_ack, hdl})

  @doc "SCM_SnFailAck"
  def sn_fail_ack(scm, hdl, group, code),
    do: :gen_statem.call(scm, {:sn_fail_ack, hdl, group, code})

  @doc "SNMTM_ProcessResponse / SSDOC_ProcessResponse: `{ok, frames_to_send}`."
  def process_response(scm, ct, %Frame{} = f), do: :gen_statem.call(scm, {:response, ct, f})

  @doc "Repetitions, timeouts and SCM_Trigger. Returns `{free, frames}`."
  def tick(scm, ct, free), do: :gen_statem.call(scm, {:tick, ct, free})

  @doc "`:stopped` or `:active`."
  def state(scm), do: :gen_statem.call(scm, :state)

  @doc "The SN machines: `[{hdl, sadr, pid}]`."
  def nodes(scm), do: :gen_statem.call(scm, :nodes)

  @doc "State and status of SN `hdl`: `{state, status}` or `nil`."
  def sn(scm, hdl) do
    case List.keyfind(nodes(scm), hdl, 0) do
      {_, _, pid} -> {SN.state(pid), SN.status(pid)}
      nil -> nil
    end
  end

  ## gen_statem

  @impl true
  def callback_mode, do: :state_functions

  @impl true
  def init(opts) do
    sod = Keyword.fetch!(opts, :sod)
    owner = Keyword.fetch!(opts, :owner)
    max = Keyword.get(opts, :max_nodes, 101)

    serr = Keyword.get(opts, :serr)
    {:ok, snmtm} = SNMTM.start_link(sod: sod, owner: owner, slots: max, serr: serr)

    {:ok, ssdoc} =
      SSDOC.start_link(
        [sod: sod, owner: owner, slots: max, serr: serr] ++ Keyword.take(opts, [:max_pyld])
      )

    d = %{
      sod: sod,
      owner: owner,
      snmtm: snmtm,
      ssdoc: ssdoc,
      max: max,
      per_call: Keyword.get(opts, :per_call, 1),
      process_sn: Keyword.get(opts, :process_sn, fn _sadr -> true end),
      revision_ok: Keyword.get(opts, :revision_ok, fn _sadr, exp, rec -> exp == rec end),
      sns: {},
      sadrs: {},
      idx: 0
    }

    {:ok, :stopped, d}
  end

  def stopped({:call, from}, msg, d), do: handle(:stopped, from, msg, d)
  def active({:call, from}, msg, d), do: handle(:active, from, msg, d)

  defp handle(_state, from, :activate, d) do
    {ok, d} = init_fsm(stop_sns(d))
    reply(if(ok, do: :active, else: :stopped), d, from, ok)
  end

  defp handle(_state, from, :deactivate, d), do: reply(:stopped, d, from, :ok)

  defp handle(state, from, :reset_node_guarding, d) do
    each_sn(d, &SN.deliver(&1, :reset_guarding))
    reply(state, d, from, :ok)
  end

  defp handle(state, from, {:operator_ack, hdl}, d) do
    r =
      cond do
        hdl >= d.max -> error(d, :param1_err, hdl) && false
        hdl >= tuple_size(d.sns) -> error(d, :param2_err, hdl) && false
        true -> SN.operator_ack(elem(d.sns, hdl))
      end

    reply(state, d, from, r)
  end

  defp handle(state, from, {:sn_fail_ack, hdl, group, code}, d) do
    r =
      cond do
        hdl >= d.max -> error(d, :param3_err, hdl) && false
        hdl >= tuple_size(d.sns) -> error(d, :param4_err, hdl) && false
        true -> SN.sn_fail_ack(elem(d.sns, hdl), group, code)
      end

    reply(state, d, from, r)
  end

  defp handle(state, from, {:response, ct, f}, d) do
    result =
      case f.id &&& 0x39 do
        0x29 ->
          {ok, effects} = SNMTM.process_response(d.snmtm, ct, f)
          deliver_snmtm(d, effects)
          {ok, []}

        0x39 ->
          {ok, frames, effects} = SSDOC.process_response(d.ssdoc, ct, f)
          deliver_ssdoc(d, effects)
          {ok, frames}

        _ ->
          error(d, :resp_id_inv, f.id)
          {false, []}
      end

    reply(state, d, from, result)
  end

  defp handle(state, from, {:tick, ct, free}, d) do
    {free, f1, effects} = SNMTM.build_request(d.snmtm, ct, free)
    deliver_snmtm(d, effects)
    {free, f2, effects} = SSDOC.build_request(d.ssdoc, ct, free)
    deliver_ssdoc(d, effects)

    {free, f3, d} =
      if state == :active and tuple_size(d.sns) > 0,
        do: trigger(d, ct, free, 0, []),
        else: {free, [], d}

    reply(state, d, from, {free, f1 ++ f2 ++ f3})
  end

  defp handle(state, from, :state, d), do: reply(state, d, from, state)

  defp handle(state, from, :nodes, d) do
    nodes =
      for i <- 0..(tuple_size(d.sns) - 1)//1,
          do: {i, elem(d.sadrs, i), elem(d.sns, i)}

    reply(state, d, from, nodes)
  end

  defp reply(state, d, from, r), do: {:next_state, state, d, [{:reply, from, r}]}

  ## SCM_Trigger: `per_call` SNs round robin; a failed SN ends the round.

  defp trigger(d, _ct, free, n, acc) when n >= d.per_call, do: {free, acc, d}

  defp trigger(d, ct, free, n, acc) do
    i = d.idx

    {ok, free, frames} =
      if d.process_sn.(elem(d.sadrs, i)),
        do: SN.trigger(elem(d.sns, i), ct, free),
        else: {true, free, []}

    d = %{d | idx: rem(i + 1, tuple_size(d.sns))}
    acc = acc ++ frames
    if ok, do: trigger(d, ct, free, n + 1, acc), else: {free, acc, d}
  end

  ## Effects from SNMTM and SSDOC, to the SN they belong to

  defp deliver_snmtm(d, effects) do
    Enum.each(effects, fn
      {:resp, reg, tadr, sdn, data} -> to_sn(d, reg, {:snmtm_resp, tadr, sdn, data})
      {:timeout, reg} -> to_sn(d, reg, :snmtm_timeout)
      :reset_guard -> each_sn(d, &SN.deliver(&1, :reset_guard_clbk))
    end)
  end

  defp deliver_ssdoc(d, effects) do
    Enum.each(effects, fn {:resp, reg, len, abort, data} ->
      to_sn(d, reg, {:ssdoc_resp, len, abort, data})
    end)
  end

  defp to_sn(d, reg, ev) when is_integer(reg) and reg < tuple_size(d.sns),
    do: SN.deliver(elem(d.sns, reg), ev)

  defp to_sn(_d, _reg, _ev), do: :ok

  defp each_sn(d, fun), do: d.sns |> Tuple.to_list() |> Enum.each(fun)

  defp stop_sns(d) do
    each_sn(d, &:gen_statem.stop/1)
    %{d | sns: {}, sadrs: {}, idx: 0}
  end

  ## ScmInitFsm, SnSodEntryInit, SCM_BuildLocalSadrList

  defp init_fsm(d) do
    with {:ok, guard} <- sod_get(d, 0x100C, 1),
         {:ok, mode} <- sod_get(d, 0x101B, 1),
         {:ok, add_sadrs} <- local_sadr_list(d),
         {:ok, cfgs} <- sn_entries(d, 0, []) do
      if cfgs == [] do
        error(d, :sod_read_err, 0)
        {false, d}
      else
        start_sns(d, Enum.reverse(cfgs), guard, mode, add_sadrs)
      end
    else
      _ -> {false, d}
    end
  end

  defp start_sns(d, cfgs, guard, mode, add_sadrs) do
    pids =
      cfgs
      |> Enum.with_index()
      |> Enum.map(fn {cfg, i} ->
        cfg =
          Map.merge(cfg, %{
            sn: i,
            scm: self(),
            owner: d.owner,
            sod: d.sod,
            snmtm: d.snmtm,
            ssdoc: d.ssdoc,
            guard_time: guard,
            config_mode: mode,
            add_sadrs: add_sadrs,
            revision_ok: d.revision_ok
          })

        {:ok, pid} = SN.start_link(cfg)
        pid
      end)

    peers = List.to_tuple(pids)
    Enum.each(pids, &SN.set_peers(&1, peers))
    sadrs = cfgs |> Enum.map(& &1.sadr) |> List.to_tuple()
    {true, %{d | sns: peers, sadrs: sadrs, idx: 0}}
  end

  # SnSodEntryInit for n = 0, 1, ... until 0xC400+n/1 is missing. Entries
  # with an out-of-range SADR are skipped.
  defp sn_entries(d, n, acc) when n >= d.max, do: {:ok, acc}

  defp sn_entries(d, n, acc) do
    idx = 0xC400 + n

    case query_read(d, idx, 1) do
      :missing ->
        {:ok, acc}

      {:ok, sadr} when sadr < 1 or sadr > @max_sadr ->
        sn_entries(d, n + 1, acc)

      {:ok, sadr} ->
        with {:ok, payld} <- sod_get(d, idx, 8),
             {:ok, poll} <- sod_get(d, idx, 9),
             :ok <- ptr_acs(d, 0xCC00 + sadr, 1),
             :ok <- ptr_acs(d, idx, 15),
             {:ok, crc_max} <- act_len(d, {idx, 15}) do
          cfg = %{
            sadr: sadr,
            payld: payld,
            poll: poll,
            udid: {0xCC00 + sadr, 1},
            rem_crc_max: crc_max
          }

          sn_entries(d, n + 1, [cfg | acc])
        end

      :error ->
        :error
    end
  end

  # SCM_BuildLocalSadrList: aw_MainSadr[i], the main SADR of additional
  # SADR i+1 (0 if none).
  defp local_sadr_list(d) do
    Enum.reduce_while(0..(@max_sadr - 1), {:ok, []}, fn i, {:ok, acc} ->
      case query_read(d, 0xC801 + i, 1) do
        {:ok, main} when main != i + 1 -> {:cont, {:ok, [main | acc]}}
        {:ok, _} -> {:cont, {:ok, [0 | acc]}}
        :missing -> {:cont, {:ok, [0 | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, list} -> {:ok, list |> Enum.reverse() |> List.to_tuple()}
      :error -> :error
    end
  end

  ## SOD access (SCMbase.c)

  # SCM_SodPtrAcs: objects the SCM reads in place must not have callbacks.
  defp ptr_acs(d, idx, sub) do
    case SOD.attr_get(d.sod, idx, sub) do
      {:ok, _h, attr} ->
        if Enum.any?([:bef_rd, :bef_wr, :aft_wr], &(&1 in attr.attr)),
          do: error(d, :obj_clbk_err, idx) && :error,
          else: :ok

      {:error, code, abort} ->
        error(d, code, abort) && :error
    end
  end

  # SCM_SodQueryRead: SOD_AttrGet first; a missing object is not an error.
  defp query_read(d, idx, sub) do
    case SOD.attr_get(d.sod, idx, sub) do
      {:ok, _h, _attr} -> sod_get(d, idx, sub)
      {:error, _, abort} when abort in [:obj_does_not_exist, :sub_idx_does_not_exist] -> :missing
      {:error, code, abort} -> error(d, code, abort) && :error
    end
  end

  defp act_len(d, h) do
    case SOD.act_len_get(d.sod, h) do
      {:ok, n} -> {:ok, n}
      {:error, code, abort} -> error(d, code, abort) && :error
    end
  end

  defp sod_get(d, i, s) do
    case SOD.get(d.sod, i, s) do
      {:ok, v} -> {:ok, v}
      {:error, code, abort} -> error(d, code, abort) && :error
    end
  end

  defp error(d, code, info) do
    send(d.owner, {:opensafety_scm, self(), {:error, code, info}})
    d
  end
end
