defmodule OpenSafety.SNMTM do
  @moduledoc """
  SNMT master (`SNMTMmain.c`, `SNMTMfsm.c`, `SNMTMrequest.c`): the SCM's
  pool of SNMT request slots.

  Each slot is the C `t_FSM`, a two-state machine: waiting for a request
  (`o_wfRequest`), or waiting for the response to the request it sent,
  with a response timeout and a repetition counter. Slot `n` is free when
  it waits for a request; `available?/1` is `SNMTM_CheckFsmAvailable`.

  ## Requests

  Every request is addressed from the SCM SADR (0x1200/2) to the SN's
  SADR, with the SCM's SDN (0x1200/1), CT and TR zero. `reg` is the
  caller's registration number (the SCM's SN index), handed back with the
  response or timeout. Each returns `{:ok, frame}` or `:error`.

    * `req_udid/4` - 0x28, no data
    * `req_assgn_sadr/5` - 0x2A, the SN's UDID
    * `req_assgn_scm_udid/5` - 0x2C cmd 14 + SCM UDID
    * `req_assgn_add_sadr/6` - 0x2C cmd 10 + SADR + Tx SPDO number
    * `req_guarding/4` - 0x2C cmd 8
    * `req_sn_trans/6` - 0x2C cmd 2 + parameter timestamp (pre-op to op)
      or cmd 0 (op to pre-op)
    * `sn_error_ack/4` - 0x2C cmd 12 + error group + code; sent without a
      slot, no response expected

  Response timeout and repetitions come from 0x1202/1 and /2 on every
  (re)transmission.

  ## Results instead of callbacks

  The C calls `SCM_SNMTM_RespClbk` and `SCM_SNMTM_ResetGuardClbk` from
  inside response and timeout processing. Here those calls are returned
  as effects for the caller (the SCM) to deliver:

    * `{:resp, reg, tadr, sdn, data}` - response assigned to slot `reg`
    * `{:timeout, reg}` - repetitions used up
    * `:reset_guard` - an SN sent "reset guarding SCM" (0x2F)

  `process_response/3` returns `{ok, effects}`; `build_request/3`
  (`SNMTM_BuildRequest`) returns `{free, frames, effects}`.

  Errors go to the owner as `{:opensafety_snmtm, pid, {:error, code, info}}`.

  ## Options

    * `:sod` - `OpenSafety.SOD.Server` (required)
    * `:owner` - default: caller
    * `:slots` - `SNMTM_cfg_MAX_NUM_FSM` (default 101,
      `SCM_cfg_MAX_NUM_OF_NODES`)
    * `:serr` - `OpenSafety.SERR` for the `:snmt_retry` / `:snmt_tout`
      counters (per slot)
  """

  use GenServer

  import Bitwise

  alias OpenSafety.{Frame, SERR}
  alias OpenSafety.SOD.Server
  alias OpenSafety.SPDO.Time

  @frm_type 0x28
  @udid_req 0x00
  @ass_sadr 0x02
  @ext_ser_req 0x04
  @rst_guard 0x07

  @sn_set_to_preop 0
  @sn_set_to_op 2
  @scm_guard_sn 8
  @assgn_add_sadr 10
  @sn_ack 12
  @assgn_udid_scm 14

  @max_resp_ext_cmd 0x0F

  # ao_ReqRespTable[req >> 1][resp >> 1]
  @req_resp {
    {true, false, false, false, false, false, false, false},
    {false, true, false, true, true, false, false, false},
    {false, false, false, false, false, false, false, false},
    {false, false, false, false, false, false, false, false},
    {true, true, false, false, false, false, false, false},
    {false, false, true, false, false, false, false, false},
    {false, false, false, false, false, false, false, false},
    {false, false, false, false, false, false, false, true}
  }

  ## API

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "SNMTM_CheckFsmAvailable"
  def available?(s), do: GenServer.call(s, :available?)

  def req_udid(s, ct, reg, sadr), do: GenServer.call(s, {:req, ct, reg, sadr, :udid})

  def req_assgn_sadr(s, ct, reg, sadr, <<_::binary-size(6)>> = udid),
    do: GenServer.call(s, {:req, ct, reg, sadr, {:assgn_sadr, udid}})

  def req_assgn_scm_udid(s, ct, reg, sadr, <<_::binary-size(6)>> = udid),
    do: GenServer.call(s, {:req, ct, reg, sadr, {:assgn_scm_udid, udid}})

  def req_assgn_add_sadr(s, ct, reg, sadr, add_sadr, spdo_num),
    do: GenServer.call(s, {:req, ct, reg, sadr, {:assgn_add_sadr, add_sadr, spdo_num}})

  def req_guarding(s, ct, reg, sadr), do: GenServer.call(s, {:req, ct, reg, sadr, :guarding})

  @doc "`trans` is `:preop_to_op` or `:op_to_preop`."
  def req_sn_trans(s, ct, reg, sadr, trans, timestamp \\ 0),
    do: GenServer.call(s, {:req, ct, reg, sadr, {:sn_trans, trans, timestamp}})

  def sn_error_ack(s, sadr, group, code), do: GenServer.call(s, {:error_ack, sadr, group, code})

  @doc "SNMTM_ProcessResponse: `{ok, effects}`."
  def process_response(s, ct, %Frame{} = f), do: GenServer.call(s, {:response, ct, f})

  @doc "SNMTM_BuildRequest: `{free, frames, effects}`."
  def build_request(s, ct, free), do: GenServer.call(s, {:build, ct, free})

  ## GenServer

  @impl true
  def init(opts) do
    n = Keyword.get(opts, :slots, 101)

    {:ok,
     %{
       sod: Keyword.fetch!(opts, :sod),
       owner: Keyword.fetch!(opts, :owner),
       serr: Keyword.get(opts, :serr),
       slots: :erlang.make_tuple(n, free_slot())
     }}
  end

  @impl true
  def handle_call(:available?, _from, s), do: {:reply, get_free(s) != nil, s}

  def handle_call({:req, ct, reg, sadr, kind}, _from, s) do
    {reply, s} = request(s, ct, reg, sadr, kind)
    {:reply, reply, s}
  end

  def handle_call({:error_ack, sadr, group, code}, _from, s) do
    reply =
      case header(s, sadr) do
        {:ok, f} -> {:ok, %{f | data: <<@sn_ack, group, code>>}}
        :error -> :error
      end

    {:reply, reply, s}
  end

  def handle_call({:response, ct, f}, _from, s) do
    {ok, s, effects} = process_response_(s, ct, f)
    {:reply, {ok, effects}, s}
  end

  def handle_call({:build, ct, free}, _from, s) do
    {free, s, frames, effects} = build(s, ct, free, 0, [], [])
    {:reply, {free, frames, effects}, s}
  end

  ## Requests (SNMTMrequest.c)

  defp request(s, ct, reg, sadr, kind) do
    with {:ok, data} <- req_data(s, kind),
         n when n != nil <- free_or_error(s, kind),
         {:ok, f} <- header(s, sadr) do
      f = %{f | id: req_id(kind), data: data}
      send_request(s, ct, n, reg, f)
    else
      _ -> {:error, s}
    end
  end

  defp req_id(:udid), do: @udid_req ||| @frm_type
  defp req_id({:assgn_sadr, _}), do: @ass_sadr ||| @frm_type
  defp req_id(_), do: @ext_ser_req ||| @frm_type

  defp req_data(_s, :udid), do: {:ok, <<>>}
  defp req_data(_s, {:assgn_sadr, udid}), do: {:ok, udid}
  defp req_data(_s, {:assgn_scm_udid, udid}), do: {:ok, <<@assgn_udid_scm, udid::binary>>}
  defp req_data(_s, :guarding), do: {:ok, <<@scm_guard_sn>>}

  defp req_data(s, {:assgn_add_sadr, add, spdo}) do
    cond do
      add < 1 or add > 0x3FF -> {:error, error(s, :add_sadr_inv, add)}
      spdo < 2 or spdo > 0x3FF -> {:error, error(s, :spdo_num_inv, spdo)}
      true -> {:ok, <<@assgn_add_sadr, add::little-16, spdo::little-16>>}
    end
  end

  defp req_data(_s, {:sn_trans, :preop_to_op, ts}), do: {:ok, <<@sn_set_to_op, ts::little-32>>}
  defp req_data(_s, {:sn_trans, :op_to_preop, _}), do: {:ok, <<@sn_set_to_preop>>}
  defp req_data(s, {:sn_trans, other, _}), do: {:error, error(s, :sn_trans_inv, other)}

  defp free_or_error(s, kind) do
    case get_free(s) do
      nil -> error(s, no_fsm_code(kind), 0) && nil
      n -> n
    end
  end

  defp no_fsm_code(:udid), do: :no_fsm_avail_req_udid
  defp no_fsm_code({:assgn_sadr, _}), do: :no_fsm_avail_ass_sadr
  defp no_fsm_code({:assgn_scm_udid, _}), do: :no_fsm_avail_req_scm_udid
  defp no_fsm_code({:assgn_add_sadr, _, _}), do: :no_fsm_avail_ass_add_sadr
  defp no_fsm_code(:guarding), do: :no_fsm_avail_req_guard
  defp no_fsm_code({:sn_trans, _, _}), do: :no_fsm_avail_sn_trans

  # Header common to all requests: TADR is the SCM SADR (ScmSadrGet).
  defp header(s, sadr) do
    with {:ok, scm} <- sod_get(s, 0x1200, 2),
         {:ok, sdn} <- sod_get(s, 0x1200, 1) do
      {:ok, %Frame{id: 0, adr: sadr, tadr: scm, sdn: sdn, ct: 0, tr: 0, data: <<>>}}
    end
  end

  ## Slot FSM (SNMTMfsm.c)

  # sendRequest
  defp send_request(s, ct, n, reg, f) do
    slot = %{elem(s.slots, n) | req: f, reg: reg}

    case transmit(s, ct, slot) do
      {:ok, slot, frame} -> {{:ok, frame}, put_slot(s, n, %{slot | wf_request: false})}
      :error -> {:error, s}
    end
  end

  # transmitRequest: (re)arm the timeout and repetitions from the SOD.
  defp transmit(s, ct, slot) do
    with {:ok, timeout} <- sod_get(s, 0x1202, 1),
         {:ok, retries} <- sod_get(s, 0x1202, 2) do
      slot = %{slot | resp_timeout: Time.u32(ct + timeout), nom_rep: retries}
      {:ok, slot, slot.req}
    end
  end

  defp process_response_(s, _ct, f) do
    cond do
      f.tr != 0 ->
        {true, error(s, :resp_tr_field_not_unused, f.tr), []}

      f.ct != 0 ->
        {true, error(s, :resp_ct_field_not_unused, f.ct), []}

      (f.id &&& 0x07) == @rst_guard ->
        {true, s, [:reset_guard]}

      not dsadr_scm_sadr?(s, f.adr) ->
        {false, s, []}

      true ->
        case assign(s, f, 0) do
          nil ->
            {false, error(s, :resp_not_assigned, f.id), []}

          n ->
            slot = elem(s.slots, n)
            {true, put_slot(s, n, free_slot()), [{:resp, slot.reg, f.tadr, f.sdn, f.data}]}
        end
    end
  end

  # IsDsadrScmSadr
  defp dsadr_scm_sadr?(s, adr) do
    case sod_get(s, 0x1200, 2) do
      {:ok, ^adr} ->
        true

      {:ok, _} ->
        error(s, :resp_rej_wrong_dsadr, adr)
        false

      :error ->
        false
    end
  end

  # SNMTM_AssignResponse
  defp assign(s, _f, n) when n >= tuple_size(s.slots), do: nil

  defp assign(s, f, n) do
    slot = elem(s.slots, n)
    id = f.id &&& bnot(1) &&& 0xFF

    if not slot.wf_request and slot.req.id == id and matches?(slot.req, f),
      do: n,
      else: assign(s, f, n + 1)
  end

  defp matches?(req, f) do
    case req.id &&& 0x07 do
      @ext_ser_req ->
        <<req_cmd, _::binary>> = req.data
        resp_cmd = first_byte(f.data)
        cmd_ok?(req_cmd, resp_cmd) and req.adr == f.tadr and req.sdn == f.sdn

      @udid_req ->
        req.adr == f.tadr

      @ass_sadr ->
        byte_size(f.data) >= 6 and binary_part(f.data, 0, 6) == req.data
    end
  end

  defp first_byte(<<b, _::binary>>), do: b
  defp first_byte(<<>>), do: 0

  # checkCmdByte
  defp cmd_ok?(req, resp) when resp <= @max_resp_ext_cmd,
    do: @req_resp |> elem(req >>> 1) |> elem(resp >>> 1)

  defp cmd_ok?(_req, _resp), do: false

  # SNMTM_BuildRequest -> SNMTM_ProcessFsm(k_EVT_CHK_TIMEOUT) per slot.
  defp build(s, _ct, free, n, frames, effects) when n >= tuple_size(s.slots),
    do: {free, s, Enum.reverse(frames), Enum.reverse(effects)}

  defp build(s, ct, free, n, frames, effects) do
    slot = elem(s.slots, n)

    cond do
      slot.wf_request or free == 0 ->
        build(s, ct, free, n + 1, frames, effects)

      not Time.timeout?(ct, slot.resp_timeout) ->
        build(s, ct, free, n + 1, frames, effects)

      slot.act_rep >= slot.nom_rep ->
        :ok = SERR.count_acyc(s.serr, n, :snmt_tout)
        s = error(s, :no_resp_received, slot.reg)
        s = put_slot(s, n, free_slot())
        build(s, ct, free, n + 1, frames, [{:timeout, slot.reg} | effects])

      true ->
        case transmit(s, ct, slot) do
          {:ok, slot, frame} ->
            :ok = SERR.count_acyc(s.serr, n, :snmt_retry)
            s = put_slot(s, n, %{slot | act_rep: slot.act_rep + 1})
            build(s, ct, free - 1, n + 1, [frame | frames], effects)

          :error ->
            {free, s, Enum.reverse(frames), Enum.reverse(effects)}
        end
    end
  end

  ## Helpers

  # SNMTM_GetFsmFree
  defp get_free(s), do: get_free(s.slots, 0)
  defp get_free(slots, n) when n >= tuple_size(slots), do: nil
  defp get_free(slots, n), do: if(elem(slots, n).wf_request, do: n, else: get_free(slots, n + 1))

  # resetFsm
  defp free_slot,
    do: %{wf_request: true, resp_timeout: 0, act_rep: 0, nom_rep: 0, reg: nil, req: nil}

  defp put_slot(s, n, slot), do: %{s | slots: put_elem(s.slots, n, slot)}

  defp sod_get(s, i, sub) do
    case Server.get(s.sod, i, sub) do
      {:ok, v} ->
        {:ok, v}

      {:error, code, abort} ->
        error(s, code, abort)
        :error
    end
  end

  defp error(s, code, info) do
    send(s.owner, {:opensafety_snmtm, self(), {:error, code, info}})
    s
  end
end
