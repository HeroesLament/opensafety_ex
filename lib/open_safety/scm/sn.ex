defmodule OpenSafety.SCM.SN do
  @moduledoc """
  The SCM's configuration state machine for one safety node
  (`SCMoper.c`, `SCMverDvi.c`, `SCMverParam.c`, `SCMdldParam.c`,
  `SCMdldAddParam.c`, `SCMactSn.c`, `SCMguarding.c`, `SCMudidMism.c`), as a
  `gen_statem` whose 26 states are the C stack's `SCM_t_FSM_STATE`.

  One process per configured SN, started and driven by `OpenSafety.SCM`.

  ## States

  Address and identity:

    * `:send_assign_sadr_req` - assign the SADR to the expected UDID
    * `:wf_assign_sadr_resp` - on timeout ask the SN for its UDID instead
    * `:wf_assign_scm_udid_resp` - the SCM's UDID was sent
    * `:wf_udid_resp` - compare the UDID the SN reported
    * `:wf_operator_ack` - UDID mismatch, waiting for the operator (ACM)
    * `:verify_uniq_udid`, `:wf_assign_sadr_resp2` - accept the new UDID
    * `:idle2` - wait one guard time, then start over

  Device and parameter verification (SSDO reads of 0x1018):

    * `:wf_vendor_id_resp`, `:wf_product_code_resp`,
      `:wf_revision_number_resp`, `:wf_timestamp`

  Parameter download:

    * `:wf_pre_op_resp`, `:wf_param_dl_resp`, `:assign_add_sadr`,
      `:wf_add_sadr_resp`

  Activation and guarding:

    * `:send_put_to_op`, `:wf_op_resp`, `:wf_poll_timeout`
    * `:wf_sapl_ack`, `:send_read_timestamp` - SN FAIL, the application
      acknowledges
    * `:send_sapl_ack`, `:send_add_par`, `:wf_add_par_dl_resp` - SN FAIL of
      the "additional parameters" group: acknowledge, download that set
    * `:wf_guard_timer`, `:wf_guard_resp` - operational, guarded

  ## Events

  The C keeps an event bit field per SN (`w_event`) that callbacks set and
  the state functions consume when `SCM_Trigger` visits the SN. That
  model is kept: SNMTM/SSDOC results arrive through `deliver/2` and only
  set bits; `trigger/3` runs the current state if its precondition (a free
  SNMTM or SSDOC slot and a free frame) holds. Bits a state leaves
  unconsumed are reported as `:unvalid_event_err`, as in `ScmFsmProcess`.

  ## Ported as is

  `SCM_WfAssignScmUdidResp` (on success) and `SCM_WfUdidResp` (UDID
  equal) return FALSE although they made progress, which ends the current
  `SCM_Trigger` round early. With one SN processed per call (the stack's
  default) this has no effect.

  `SCM_UniqueUdid` reads the other SNs' control blocks. Here the SN asks
  its peers (`udid_info`) directly; the coordinator is blocked in this
  SN's trigger call and every peer is idle, so there is no call cycle.
  """

  @behaviour :gen_statem

  import Bitwise

  alias OpenSafety.{SNMTM, SSDOC}
  alias OpenSafety.SOD.Server, as: SOD
  alias OpenSafety.SPDO.Time

  # SCM_k_EVT_*
  @generic 1
  @ssdoc_resp 2
  @snmtm_resp 4
  @ack 8
  @snmtm_timeout 16
  @ssdoc_timeout 32
  @resp_error 64
  @timeout 128
  @reset_grd 256

  # SCM_k_NS_*
  @status %{
    missing: 0,
    invalid: 1,
    wrong_sadr: 2,
    udid_mismatch: 3,
    wrong_param: 4,
    wrong_add_param: 5,
    valid: 128,
    ok: 129
  }

  # SNMTS_k_SN_*
  @sts_preop 1
  @sts_op 3
  @sn_fail 7
  @sts_busy 9
  @fail_grp_add 5

  @acm 0
  @udid_len 6
  @resp_buff 7
  @add_par_hdr 16
  @add_param_version 1

  # as_FsmStateFunctions[].b_preCon
  @precon %{
    send_assign_sadr_req: :snmtm,
    wf_assign_sadr_resp: :snmtm,
    wf_assign_scm_udid_resp: :ssdoc,
    wf_udid_resp: :none,
    wf_operator_ack: :none,
    idle2: :none,
    wf_vendor_id_resp: :ssdoc,
    wf_product_code_resp: :ssdoc,
    wf_revision_number_resp: :ssdoc,
    wf_timestamp: :snmtm,
    wf_pre_op_resp: :ssdoc,
    wf_param_dl_resp: :none,
    assign_add_sadr: :snmtm,
    wf_add_sadr_resp: :none,
    wf_assign_sadr_resp2: :snmtm,
    verify_uniq_udid: :snmtm,
    send_put_to_op: :snmtm,
    send_read_timestamp: :ssdoc,
    wf_op_resp: :none,
    wf_poll_timeout: :none,
    wf_sapl_ack: :snmtm,
    wf_guard_timer: :snmtm,
    wf_guard_resp: :none,
    send_sapl_ack: :snmtm,
    send_add_par: :ssdoc,
    wf_add_par_dl_resp: :none
  }

  @states Map.keys(@precon)

  ## API

  def start_link(cfg), do: :gen_statem.start_link(__MODULE__, cfg, [])

  @doc "One `SCM_Trigger` visit: `{ok, free, frames}`."
  def trigger(pid, ct, free), do: :gen_statem.call(pid, {:trigger, ct, free})

  @doc """
  Deliver a result: `{:snmtm_resp, tadr, sdn, data}`, `:snmtm_timeout`,
  `{:ssdoc_resp, len, abort, data}`, `:reset_guarding`
  (`SCM_ResetNodeGuarding`) or `:reset_guard_clbk`
  (`SCM_SNMTM_ResetGuardClbk`).
  """
  def deliver(pid, event), do: :gen_statem.call(pid, {:deliver, event})

  @doc "SCM_OperatorAck"
  def operator_ack(pid), do: :gen_statem.call(pid, :operator_ack)

  @doc "SCM_SnFailAck"
  def sn_fail_ack(pid, group, code), do: :gen_statem.call(pid, {:sn_fail_ack, group, code})

  def state(pid), do: :gen_statem.call(pid, :state)
  def status(pid), do: :gen_statem.call(pid, :status)

  @doc false
  def udid_info(pid), do: :gen_statem.call(pid, :udid_info)

  @doc false
  def set_peers(pid, peers), do: :gen_statem.call(pid, {:peers, peers})

  @doc "SCM_k_NS_* value of a status atom."
  def status_code(s), do: Map.fetch!(@status, s)

  ## gen_statem

  @impl true
  def callback_mode, do: :state_functions

  @impl true
  def init(cfg) do
    d =
      Map.merge(cfg, %{
        udid_used: false,
        event: @generic,
        status: :missing,
        report: true,
        timer: 0,
        add_sadr: 0,
        err_group: 0,
        err_code: 0,
        ssdoc_abort: 0,
        upload_len: 0,
        tadr: 0,
        rx_sdn: 0,
        resp: <<0::56>>,
        new_udid: <<0::48>>,
        rem_crc: <<>>,
        target: :resp,
        peers: {},
        free: 0,
        frames: []
      })

    {:ok, :send_assign_sadr_req, d}
  end

  for state <- @states do
    def unquote(state)({:call, from}, msg, d), do: handle(unquote(state), from, msg, d)
  end

  defp handle(state, from, {:trigger, ct, free}, d) do
    d = check_timeout(state, ct, d)

    if precon?(state, free, d) do
      {ok, state, d} = process(state, ct, %{d | free: free, frames: []})
      reply(state, %{d | frames: []}, from, {ok, d.free, Enum.reverse(d.frames)})
    else
      reply(state, d, from, {true, free, []})
    end
  end

  defp handle(state, from, {:deliver, ev}, d), do: reply(state, deliver_(state, ev, d), from, :ok)

  defp handle(:wf_operator_ack, from, :operator_ack, d),
    do: reply(:wf_operator_ack, set(d, @ack), from, true)

  defp handle(state, from, :operator_ack, d),
    do: reply(state, error(d, :param2_err, d.sn), from, false)

  defp handle(:wf_sapl_ack, from, {:sn_fail_ack, group, code}, d) do
    <<_, _, rest::binary>> = d.resp
    d = %{d | resp: <<group, code, rest::binary>>}
    reply(:wf_sapl_ack, set(d, @ack), from, true)
  end

  defp handle(state, from, {:sn_fail_ack, _, _}, d),
    do: reply(state, error(d, :param4_err, d.sn), from, false)

  defp handle(state, from, :state, d), do: reply(state, d, from, state)
  defp handle(state, from, :status, d), do: reply(state, d, from, d.status)
  defp handle(state, from, :udid_info, d), do: reply(state, d, from, {d.udid, d.udid_used})
  defp handle(state, from, {:peers, p}, d), do: reply(state, %{d | peers: p}, from, :ok)

  defp reply(state, d, from, r), do: {:next_state, state, d, [{:reply, from, r}]}

  ## Results (SCM_SNMTM_RespClbk, SCM_SsdocClbk, reset guarding)

  defp deliver_(_state, {:snmtm_resp, tadr, sdn, data}, d) do
    resp = binary_part(data <> <<0::56>>, 0, @resp_buff)
    set(%{d | tadr: tadr, rx_sdn: sdn, resp: resp}, @snmtm_resp)
  end

  defp deliver_(_state, :snmtm_timeout, d), do: set(d, @snmtm_timeout)

  defp deliver_(state, {:ssdoc_resp, len, abort, data}, d) do
    cond do
      abort == 0 ->
        set(store_upload(%{d | upload_len: len}, data), @ssdoc_resp)

      abort == OpenSafety.SOD.abort_code(:ssdo_time_out) ->
        set(%{d | upload_len: 0}, @ssdoc_timeout)

      true ->
        d = %{d | upload_len: 0, ssdoc_abort: abort}
        d = error(d, :err_sdo_abort_node, {d.sadr, state})
        d = error(d, :err_sdo_abort, abort)
        set(d, @resp_error)
    end
  end

  defp deliver_(state, :reset_guarding, d) do
    d = %{d | report: true}

    cond do
      state in [:wf_guard_timer, :idle2] -> set(d, @timeout)
      state == :wf_operator_ack -> set(d, @reset_grd)
      true -> d
    end
  end

  defp deliver_(state, :reset_guard_clbk, d) do
    if state in [:wf_guard_timer, :idle2], do: set(d, @timeout), else: d
  end

  # The C uploads into the request's buffer: the response buffer, or the
  # remote parameter checksum object (0xC400+sn/15).
  defp store_upload(d, nil), do: d

  defp store_upload(%{target: :rem_crc} = d, data) do
    _ = SOD.write(d.sod, {0xC400 + d.sn, 15}, data, true, 0, byte_size(data))
    %{d | rem_crc: data}
  end

  defp store_upload(d, data) do
    n = min(byte_size(data), @resp_buff)
    <<_::binary-size(n), rest::binary>> = d.resp
    %{d | resp: binary_part(data, 0, n) <> rest}
  end

  ## SCM_Trigger for this SN (CheckTimeout, ScmFsmPreCon, ScmFsmProcess)

  defp check_timeout(state, ct, d)
       when state in [:wf_guard_timer, :wf_poll_timeout, :idle2, :wf_sapl_ack] do
    if Time.timeout?(ct, d.timer), do: set(d, @timeout), else: d
  end

  defp check_timeout(_state, _ct, d), do: d

  defp precon?(state, free, d) do
    case Map.fetch!(@precon, state) do
      :snmtm -> SNMTM.available?(d.snmtm) and free > 0
      :ssdoc -> SSDOC.available?(d.ssdoc) and free > 0
      :none -> true
    end
  end

  defp process(state, _ct, %{event: 0} = d), do: {true, state, d}

  defp process(state, ct, d) do
    {ok, state, d} = run(state, ct, d)

    if ok and d.event not in [0, @generic, @ack],
      do: {false, state, error(d, :unvalid_event_err, d.event)},
      else: {ok, state, d}
  end

  ## SCMoper.c

  defp run(:send_assign_sadr_req, ct, %{event: @generic} = d) do
    d = clear(d)

    case read_udid(d, d.udid) do
      {:ok, udid} ->
        snmtm(d, :send_assign_sadr_req, :wf_assign_sadr_resp, fn m ->
          SNMTM.req_assgn_sadr(m, ct, d.sn, d.sadr, udid)
        end)

      :error ->
        {false, :send_assign_sadr_req, d}
    end
  end

  defp run(:wf_assign_sadr_resp, ct, %{event: @snmtm_resp} = d),
    do: assign_sadr_resp(:wf_assign_sadr_resp, ct, clear(d), true)

  defp run(:wf_assign_sadr_resp, ct, %{event: @snmtm_timeout} = d),
    do:
      snmtm(clear(d), :wf_assign_sadr_resp, :wf_udid_resp, &SNMTM.req_udid(&1, ct, d.sn, d.sadr))

  defp run(:wf_assign_scm_udid_resp, ct, %{event: @snmtm_resp} = d) do
    d = clear(d)
    state = :wf_assign_scm_udid_resp

    case sod_get(d, 0x1200, 4) do
      {:ok, scm_udid} ->
        <<_, resp_udid::binary-size(6), _::binary>> = d.resp

        cond do
          scm_udid != resp_udid ->
            to_idle2(d, state, :missing, d.report, ct)

          d.rx_sdn == own_sdn(d) and d.tadr == d.sadr ->
            # FALSE even on success (see moduledoc).
            {_ok, state, d} =
              ssdoc_read(d, ct, state, :wf_vendor_id_resp, 0x1018, 1, :uint32, @resp_buff, :resp)

            {false, state, d}

          true ->
            to_idle2(d, state, :missing, d.report, ct)
        end

      :error ->
        {false, state, d}
    end
  end

  defp run(:wf_assign_scm_udid_resp, ct, %{event: @snmtm_timeout} = d),
    do: to_idle2(clear(d), :wf_assign_scm_udid_resp, :missing, d.report, ct)

  defp run(:wf_udid_resp, ct, %{event: @snmtm_resp} = d) do
    d = clear(d)

    case check_sn_udid(d) do
      {:ok, true, d} ->
        # FALSE although it made progress (see moduledoc).
        {false, :send_assign_sadr_req, %{d | event: @generic}}

      {:ok, false, d} ->
        d = %{d | new_udid: binary_part(d.resp, 0, @udid_len)}

        case set_status(d, :udid_mismatch, d.report) do
          {true, d} ->
            {state, d} =
              if d.config_mode == @acm,
                do: {:wf_operator_ack, d},
                else: {:idle2, %{d | timer: Time.u32(ct + d.guard_time)}}

            {true, state, sapl(d, {:udid_mismatch, d.sadr, d.new_udid, d.sn})}

          {false, d} ->
            {false, :wf_udid_resp, d}
        end

      {:error, d} ->
        {false, :wf_udid_resp, d}
    end
  end

  defp run(:wf_udid_resp, ct, %{event: @snmtm_timeout} = d),
    do: to_idle2(clear(d), :wf_udid_resp, :missing, d.report, ct)

  defp run(:wf_operator_ack, _ct, %{event: e} = d) when e in [@ack, @ack ||| @reset_grd],
    do: {true, :verify_uniq_udid, %{d | event: @generic}}

  defp run(:wf_operator_ack, _ct, %{event: @reset_grd} = d) do
    {ok, d} = set_status(%{d | event: @generic}, :missing, false)
    {ok, :send_assign_sadr_req, d}
  end

  defp run(:idle2, _ct, %{event: @timeout} = d),
    do: {true, :send_assign_sadr_req, %{d | event: @generic}}

  ## SCMverDvi.c

  defp run(:wf_vendor_id_resp, ct, %{event: @ssdoc_resp} = d),
    do: verify_dvi(clear(d), ct, :wf_vendor_id_resp, 2, :wf_product_code_resp, 2)

  defp run(:wf_product_code_resp, ct, %{event: @ssdoc_resp} = d),
    do: verify_dvi(clear(d), ct, :wf_product_code_resp, 3, :wf_revision_number_resp, 3)

  defp run(:wf_revision_number_resp, ct, %{event: @ssdoc_resp} = d) do
    d = clear(d)
    state = :wf_revision_number_resp

    case sod_get(d, 0xC400 + d.sn, 4) do
      {:ok, expected} ->
        <<received::little-32, _::binary>> = d.resp

        if d.revision_ok.(d.sadr, expected, received),
          do:
            ssdoc_read(d, ct, state, :wf_timestamp, 0x1018, 6, :domain, d.rem_crc_max, :rem_crc),
          else: to_idle2(d, state, :invalid, d.report, ct)

      :error ->
        {false, state, d}
    end
  end

  defp run(state, ct, %{event: e} = d)
       when state in [:wf_vendor_id_resp, :wf_product_code_resp, :wf_revision_number_resp] and
              e in [@ssdoc_timeout, @resp_error],
       do: ssdoc_failed(state, ct, d)

  ## SCMverParam.c

  defp run(:wf_timestamp, ct, %{event: @ssdoc_resp} = d) do
    d = clear(d)
    sn = 0xC400 + d.sn

    with {:ok, crc} <- sod_get(d, sn, 14),
         {:ok, len} <- act_len(d, {sn, 14}) do
      same =
        len != 0 and len == d.upload_len and byte_size(d.rem_crc) >= len and
          binary_part(crc, 0, len) == binary_part(d.rem_crc, 0, len)

      if same do
        {true, :send_put_to_op, %{d | event: @generic}}
      else
        snmtm(d, :wf_timestamp, :wf_pre_op_resp, fn m ->
          SNMTM.req_sn_trans(m, ct, d.sn, d.sadr, :op_to_preop)
        end)
      end
    else
      _ -> {false, :wf_timestamp, d}
    end
  end

  defp run(:wf_timestamp, ct, %{event: e} = d) when e in [@ssdoc_timeout, @resp_error],
    do: ssdoc_failed(:wf_timestamp, ct, d)

  ## SCMdldParam.c

  defp run(:wf_pre_op_resp, ct, %{event: @snmtm_resp} = d) do
    d = clear(d)
    sn = 0xC400 + d.sn

    case query_read(d, sn, 10) do
      {:ok, len} ->
        case SOD.read(d.sod, {sn, 11}) do
          {:ok, set} ->
            req = %{
              idx: 0x101A,
              sub: 0,
              type: :domain,
              payload_len: (d.payld - 1) * 2,
              data_len: len,
              data: set
            }

            ssdoc(d, :wf_pre_op_resp, :wf_param_dl_resp, :resp, fn c ->
              SSDOC.send_write_req(c, d.sadr, d.sn, ct, req, true)
            end)

          {:error, code, abort} ->
            {false, :wf_pre_op_resp, error(d, code, abort)}
        end

      :missing ->
        to_idle2(d, :wf_pre_op_resp, :wrong_param, d.report, ct)

      {:error, d} ->
        {false, :wf_pre_op_resp, d}
    end
  end

  defp run(:wf_pre_op_resp, _ct, %{event: @snmtm_timeout} = d),
    do: missing_restart(:wf_pre_op_resp, clear(d))

  defp run(:wf_param_dl_resp, _ct, %{event: @ssdoc_resp} = d),
    do: {true, :assign_add_sadr, %{d | event: @generic, add_sadr: 0}}

  defp run(:wf_param_dl_resp, _ct, %{event: @ssdoc_timeout} = d),
    do: missing_restart(:wf_param_dl_resp, clear(d))

  defp run(:wf_param_dl_resp, ct, %{event: @resp_error} = d),
    do: to_idle2(clear(d), :wf_param_dl_resp, :wrong_param, d.report, ct)

  defp run(:assign_add_sadr, ct, %{event: @generic} = d) do
    d = clear(d)
    d = %{d | add_sadr: next_add_sadr(d.add_sadrs, d.sadr, d.add_sadr)}

    cond do
      d.add_sadr == 0 ->
        {true, :send_put_to_op, %{d | event: @generic}}

      true ->
        case sod_get(d, 0xC800 + d.add_sadr, 2) do
          {:ok, spdo} ->
            snmtm(d, :assign_add_sadr, :wf_add_sadr_resp, fn m ->
              SNMTM.req_assgn_add_sadr(m, ct, d.sn, d.sadr, d.add_sadr, spdo)
            end)

          :error ->
            {false, :assign_add_sadr, d}
        end
    end
  end

  defp run(:wf_add_sadr_resp, ct, %{event: @snmtm_resp} = d) do
    d = clear(d)
    <<_, sadr::little-16, _::binary>> = d.resp

    if sadr == d.add_sadr,
      do: {true, :assign_add_sadr, %{d | event: @generic}},
      else: to_idle2(d, :wf_add_sadr_resp, :wrong_param, d.report, ct)
  end

  defp run(:wf_add_sadr_resp, _ct, %{event: @snmtm_timeout} = d),
    do: missing_restart(:wf_add_sadr_resp, clear(d))

  ## SCMudidMism.c

  defp run(:wf_assign_sadr_resp2, ct, %{event: @snmtm_resp} = d),
    do: assign_sadr_resp(:wf_assign_sadr_resp2, ct, clear(d), false)

  defp run(:wf_assign_sadr_resp2, _ct, %{event: @snmtm_timeout} = d),
    do: missing_restart(:wf_assign_sadr_resp2, clear(d))

  defp run(:verify_uniq_udid, ct, %{event: @generic} = d) do
    d = clear(d)

    if unique_udid?(d, d.new_udid) do
      _ = write_udid(d, d.udid, d.new_udid)

      result =
        snmtm(d, :verify_uniq_udid, :wf_assign_sadr_resp2, fn m ->
          SNMTM.req_assgn_sadr(m, ct, d.sn, d.sadr, d.new_udid)
        end)

      case result do
        {true, state, d} -> {true, state, %{d | udid_used: true}}
        other -> other
      end
    else
      to_idle2(d, :verify_uniq_udid, :invalid, d.report, ct)
    end
  end

  ## SCMactSn.c

  defp run(:send_put_to_op, ct, %{event: @generic} = d) do
    d = clear(d)

    case sod_get(d, 0xC400 + d.sn, 7) do
      {:ok, ts} ->
        snmtm(d, :send_put_to_op, :wf_op_resp, fn m ->
          SNMTM.req_sn_trans(m, ct, d.sn, d.sadr, :preop_to_op, ts)
        end)

      :error ->
        {false, :send_put_to_op, d}
    end
  end

  defp run(:send_read_timestamp, ct, %{event: @generic} = d) do
    d = clear(d)
    ssdoc_read(d, ct, :send_read_timestamp, :wf_timestamp, 0x1018, 7, :uint32, @resp_buff, :resp)
  end

  defp run(:wf_op_resp, ct, %{event: @snmtm_resp} = d) do
    d = clear(d)
    <<sts, group, code, _::binary>> = d.resp

    case sts do
      @sts_op ->
        guard_ok(d, :wf_op_resp, ct)

      @sn_fail when group == @fail_grp_add ->
        {true, :send_sapl_ack, %{d | err_group: group, err_code: code, event: @generic}}

      @sn_fail ->
        d = sapl(d, {:node_status, d.sadr, d.status, d.status})
        d = sapl(d, {:sn_fail, d.sadr, group, code, d.sn})
        {true, :wf_sapl_ack, %{d | timer: Time.u32(ct + d.poll)}}

      @sts_busy ->
        {true, :wf_poll_timeout, %{d | timer: Time.u32(ct + d.poll)}}

      _ ->
        {false, :wf_op_resp, error(d, :invalid_snmt_state, sts)}
    end
  end

  defp run(:wf_op_resp, _ct, %{event: @snmtm_timeout} = d),
    do: missing_restart(:wf_op_resp, clear(d))

  defp run(:wf_poll_timeout, _ct, %{event: @timeout} = d),
    do: {true, :send_put_to_op, %{d | event: @generic}}

  defp run(:wf_sapl_ack, ct, d) do
    cond do
      (d.event &&& bnot(@ack ||| @timeout)) != 0 ->
        {true, :wf_sapl_ack, d}

      (d.event &&& @ack) != 0 ->
        d = clear(d)
        <<group, code, _::binary>> = d.resp

        case SNMTM.sn_error_ack(d.snmtm, d.sadr, group, code) do
          {:ok, frame} -> {true, :send_read_timestamp, sent(%{d | event: @generic}, frame)}
          :error -> {false, :wf_sapl_ack, d}
        end

      true ->
        d =
          if d.report do
            <<_, group, code, _::binary>> = d.resp
            d = sapl(d, {:node_status, d.sadr, d.status, d.status})
            %{sapl(d, {:sn_fail, d.sadr, group, code, d.sn}) | report: false}
          else
            d
          end

        {true, :wf_sapl_ack, clear(%{d | timer: Time.u32(ct + d.poll)})}
    end
  end

  ## SCMguarding.c

  defp run(:wf_guard_timer, ct, %{event: @timeout} = d),
    do:
      snmtm(clear(d), :wf_guard_timer, :wf_guard_resp, &SNMTM.req_guarding(&1, ct, d.sn, d.sadr))

  defp run(:wf_guard_resp, ct, %{event: @snmtm_resp} = d) do
    d = clear(d)
    <<sts, _::binary>> = d.resp

    case sts do
      @sts_op -> guard_ok(d, :wf_guard_resp, ct)
      @sts_preop -> missing_restart(:wf_guard_resp, d)
      _ -> {false, :wf_guard_resp, error(d, :invalid_snmt_state1, sts)}
    end
  end

  defp run(:wf_guard_resp, _ct, %{event: @snmtm_timeout} = d),
    do: missing_restart(:wf_guard_resp, clear(d))

  ## SCMdldAddParam.c

  defp run(:send_sapl_ack, _ct, d) do
    if (d.event &&& bnot(@generic)) != 0 do
      {true, :send_sapl_ack, d}
    else
      d = clear(d)

      case SNMTM.sn_error_ack(d.snmtm, d.sadr, d.err_group, d.err_code) do
        {:ok, frame} -> {true, :send_add_par, sent(%{d | event: @generic}, frame)}
        :error -> {false, :send_sapl_ack, d}
      end
    end
  end

  defp run(:send_add_par, ct, d) do
    if (d.event &&& bnot(@generic)) != 0,
      do: {true, :send_add_par, d},
      else: send_add_par(clear(d), ct)
  end

  defp run(:wf_add_par_dl_resp, _ct, %{event: @ssdoc_resp} = d),
    do: {true, :send_put_to_op, %{d | event: @generic}}

  defp run(:wf_add_par_dl_resp, _ct, %{event: @ssdoc_timeout} = d),
    do: missing_restart(:wf_add_par_dl_resp, clear(d))

  defp run(:wf_add_par_dl_resp, ct, %{event: @resp_error} = d),
    do: to_idle2(clear(d), :wf_add_par_dl_resp, :wrong_param, d.report, ct)

  # Any other event: the state ignores it (the `else o_res = TRUE` branch).
  defp run(state, _ct, d), do: {true, state, d}

  ## State helpers

  # SCM_WfAssignSadrResp / SCM_WfAssignSadrResp2 on a response.
  defp assign_sadr_resp(state, ct, d, mark_used) do
    if d.rx_sdn == own_sdn(d) and d.tadr == d.sadr do
      case set_status(d, :valid, false) do
        {true, d} ->
          case sod_get(d, 0x1200, 4) do
            {:ok, scm_udid} ->
              result =
                snmtm(d, state, :wf_assign_scm_udid_resp, fn m ->
                  SNMTM.req_assgn_scm_udid(m, ct, d.sn, d.sadr, scm_udid)
                end)

              case result do
                {true, next, d} ->
                  {true, next, if(mark_used, do: %{d | udid_used: true}, else: d)}

                other ->
                  other
              end

            :error ->
              {false, state, d}
          end

        {false, d} ->
          {false, state, d}
      end
    else
      to_idle2(d, state, :wrong_sadr, d.report, ct)
    end
  end

  # SCM_WfVendorIdResp / SCM_WfProductCodeResp: compare with
  # 0xC400+sn/sub, then read 0x1018/next_sub.
  defp verify_dvi(d, ct, state, sub, next, next_sub) do
    case sod_get(d, 0xC400 + d.sn, sub) do
      {:ok, expected} ->
        <<received::little-32, _::binary>> = d.resp

        if received == expected,
          do: ssdoc_read(d, ct, state, next, 0x1018, next_sub, :uint32, @resp_buff, :resp),
          else: to_idle2(d, state, :invalid, d.report, ct)

      :error ->
        {false, state, d}
    end
  end

  # SSDO timeout: node missing, start over; SSDO abort: node invalid.
  defp ssdoc_failed(state, _ct, %{event: @ssdoc_timeout} = d),
    do: missing_restart(state, clear(d))

  defp ssdoc_failed(state, ct, d), do: to_idle2(clear(d), state, :invalid, d.report, ct)

  defp missing_restart(state, d) do
    case set_status(d, :missing, false) do
      {true, d} -> {true, :send_assign_sadr_req, %{d | event: @generic}}
      {false, d} -> {false, state, d}
    end
  end

  defp to_idle2(d, state, status, report, ct) do
    case set_status(d, status, report) do
      {true, d} -> {true, :idle2, %{d | timer: Time.u32(ct + d.guard_time)}}
      {false, d} -> {false, state, d}
    end
  end

  defp guard_ok(d, state, ct) do
    case set_status(d, :ok, d.report) do
      {true, d} -> {true, :wf_guard_timer, %{d | timer: Time.u32(ct + d.guard_time)}}
      {false, d} -> {false, state, d}
    end
  end

  # SCM_SendAddParam: the additional parameter set 0xE400+sn/(code&0x0F)+1
  # starts with a 16-byte header (id, version, SADR, size, CRC, timestamp);
  # error codes with the high nibble 0xF want the whole set, others the
  # header only.
  defp send_add_par(d, ct) do
    sub = (d.err_code &&& 0x0F) + 1
    idx = 0xE400 + d.sn
    info = idx ||| sub <<< 16

    checked =
      with {:ok, raw} <- SOD.read(d.sod, {idx, sub}),
           {:ok, len} <- SOD.act_len_get(d.sod, {idx, sub}) do
        case binary_part(raw, 0, len) do
          <<_id, version, sadr::little-16, _::binary>> = set when len >= @add_par_hdr ->
            cond do
              version != @add_param_version -> {:error, :add_param1_err}
              sadr != d.sadr -> {:error, :add_param2_err}
              true -> {:ok, set, len}
            end

          _ ->
            {:error, :add_param3_err}
        end
      else
        _ -> {:error, :add_param4_err}
      end

    case checked do
      {:ok, set, len} ->
        data_len = if (d.err_code &&& 0xF0) == 0xF0, do: len, else: @add_par_hdr

        req = %{
          idx: 0x101A,
          sub: 0,
          type: :domain,
          payload_len: (d.payld - 1) * 2,
          data_len: data_len,
          data: set
        }

        ssdoc(d, :send_add_par, :wf_add_par_dl_resp, :resp, fn c ->
          SSDOC.send_write_req(c, d.sadr, d.sn, ct, req, true)
        end)

      {:error, code} ->
        d = error(d, code, info)
        to_idle2(d, :send_add_par, :wrong_add_param, d.report, ct)
    end
  end

  # CheckSnUdid: ACM compares with the configured UDID; MCM searches the
  # UDID list of the SADR (0xCC00+sadr/1..n) and takes the match.
  defp check_sn_udid(d) do
    resp_udid = binary_part(d.resp, 0, @udid_len)

    if d.config_mode == @acm do
      case read_udid(d, d.udid) do
        {:ok, u} -> {:ok, u == resp_udid, d}
        :error -> {:error, d}
      end
    else
      case sod_get(d, 0xCC00 + d.sadr, 0) do
        {:ok, n} -> search_udid(d, resp_udid, 1, n)
        :error -> {:error, d}
      end
    end
  end

  defp search_udid(d, _udid, i, n) when i > n, do: {:ok, false, d}

  defp search_udid(d, udid, i, n) do
    handle = {0xCC00 + d.sadr, i}

    case read_udid(d, handle) do
      {:ok, ^udid} -> {:ok, true, %{d | udid: handle}}
      {:ok, _} -> search_udid(d, udid, i + 1, n)
      :error -> {:error, d}
    end
  end

  # SCM_UniqueUdid: no SN may already use the new UDID; unused copies are
  # cleared.
  defp unique_udid?(d, new) do
    d.peers
    |> Tuple.to_list()
    |> Enum.reduce_while(true, fn pid, true ->
      {handle, used} = if pid == self(), do: {d.udid, d.udid_used}, else: udid_info(pid)

      case read_udid(d, handle) do
        {:ok, ^new} when used ->
          {:halt, false}

        {:ok, ^new} ->
          _ = write_udid(d, handle, <<0::48>>)
          {:cont, true}

        _ ->
          {:cont, true}
      end
    end)
  end

  # SCM_GetNextAddSadr over aw_MainSadr (index i is additional SADR i+1).
  defp next_add_sadr(list, main, add) when add < tuple_size(list) do
    if elem(list, add) == main, do: add + 1, else: next_add_sadr(list, main, add + 1)
  end

  defp next_add_sadr(_list, _main, _add), do: 0

  ## Requests: on success the state advances and a frame is used
  ## (SCM_NumFreeFrmsDec); on failure the state stays and the round ends.

  defp snmtm(d, state, next, fun) do
    case fun.(d.snmtm) do
      {:ok, frame} -> {true, next, sent(d, frame)}
      :error -> {false, state, d}
    end
  end

  defp ssdoc(d, state, next, target, fun) do
    case fun.(d.ssdoc) do
      {:ok, frame} -> {true, next, sent(%{d | target: target}, frame)}
      :error -> {false, state, d}
    end
  end

  defp ssdoc_read(d, ct, state, next, idx, sub, type, len, target) do
    req = %{idx: idx, sub: sub, type: type, payload_len: d.payld, data_len: len}
    ssdoc(d, state, next, target, &SSDOC.send_read_req(&1, d.sadr, d.sn, ct, req))
  end

  defp sent(d, frame), do: %{d | frames: [frame | d.frames], free: d.free - 1}

  ## SCMbase.c

  # SCM_SetNodeStatus
  defp set_status(d, status, report) do
    case SOD.put(d.sod, 0xC400 + d.sn, 5, Map.fetch!(@status, status), true) do
      :ok ->
        d =
          cond do
            report -> %{sapl(d, {:node_status, d.sadr, d.status, status}) | report: false}
            status != d.status -> sapl(d, {:node_status, d.sadr, d.status, status})
            true -> d
          end

        d = if status == :missing, do: %{d | udid_used: false}, else: d
        {true, %{d | status: status}}

      _ ->
        {false, error(d, :sod_write_err, 0)}
    end
  end

  # SCM_SodQueryRead: SOD_AttrGet first; a missing object is not an error.
  defp query_read(d, idx, sub) do
    case SOD.attr_get(d.sod, idx, sub) do
      {:ok, _h, _attr} ->
        case sod_get(d, idx, sub) do
          {:ok, v} -> {:ok, v}
          :error -> {:error, d}
        end

      {:error, _, abort} when abort in [:obj_does_not_exist, :sub_idx_does_not_exist] ->
        :missing

      {:error, code, abort} ->
        {:error, error(d, code, abort)}
    end
  end

  defp read_udid(d, handle) do
    case SOD.read(d.sod, handle) do
      {:ok, u} when byte_size(u) >= @udid_len ->
        {:ok, binary_part(u, 0, @udid_len)}

      {:ok, _} ->
        :error

      {:error, code, abort} ->
        error(d, code, abort)
        :error
    end
  end

  defp write_udid(d, handle, udid), do: SOD.write(d.sod, handle, udid, true, 0, @udid_len)

  defp act_len(d, handle) do
    case SOD.act_len_get(d.sod, handle) do
      {:ok, n} ->
        {:ok, n}

      {:error, code, abort} ->
        error(d, code, abort)
        :error
    end
  end

  defp own_sdn(d) do
    case SOD.get(d.sod, 0x1200, 1) do
      {:ok, v} -> v
      _ -> 0
    end
  end

  defp sod_get(d, i, s) do
    case SOD.get(d.sod, i, s) do
      {:ok, v} ->
        {:ok, v}

      {:error, code, abort} ->
        error(d, code, abort)
        :error
    end
  end

  defp set(d, bit), do: %{d | event: d.event ||| bit}
  defp clear(d), do: %{d | event: 0}

  defp sapl(d, msg) do
    send(d.owner, {:opensafety_scm, d.scm, msg})
    d
  end

  defp error(d, code, info), do: sapl(d, {:error, code, info})
end
