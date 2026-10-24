defmodule OpenSafety.SNMTS do
  @moduledoc """
  Safety Network Management, slave side (`SNMTS*.c`): the safety node's
  state machine, as a `gen_statem` whose twelve states are the C stack's
  `t_FSM_STATE`.

  ## States

  Pre-operational, waiting for the SCM:

    * `:initialization` - until the application calls `perform_trans_pre_op/2`
    * `:wf_sadr_ass_step1`, `:wf_sadr_ass_step2` - SADR, then SDN, assignment
    * `:wf_udid_scm_ass` - the SCM's UDID
    * `:wf_set_to_op1_step1`, `:wf_set_to_op1_step2` - first SET TO OP;
      SPDO mapping activation
    * `:wf_api_chksum` - the application computes the parameter checksum
    * `:wf_set_to_op2` - second SET TO OP; checksum/timestamp compared
    * `:wf_api_conf` - the application confirms entering Operational
    * `:wf_set_to_op3` - third SET TO OP; Operational

  Operational:

    * `:operational_step1`, `:operational_step2` - guarding, life time;
      step 2 is a SADR re-assignment in progress

  `sn_state/1` reports the three main states of `SNMTS_GetSnState`.

  ## Driving it (C equivalents)

    * `process_request/3` - one received SNMT request (`SNMTS_ProcessRequest`,
      looped while busy as the SSC does). Returns `{:reply, frame}` or
      `:noreply`.
    * `timer_check/3` - `SNMTS_TimerCheck`: refresh time in pre-operational
      (sends the reset-guarding frame), life time in operational.
    * `perform_trans_pre_op/2`, `pass_param_chksum_valid/2`,
      `enter_op_state/4` - the application API.

  The application callbacks (`SAPL_SNMTS_*Clbk`) are messages to the owner,
  `{:opensafety_snmts, pid, msg}`:

    * `:calc_param_checksum` - answer with `pass_param_chksum_valid/2`
    * `:switch_to_op_request` - answer with `enter_op_state/4`
    * `{:error_ack, group, code}`
    * `{:error, code, info}` - `SERR_SetError`, `code` after `SNMTS_k_ERR_*`

  `SAPL_SNMTS_ParameterSetProcessed` is synchronous in C, so it is the
  `:param_set_processed` option (a zero-arity function, default true).

  ## Objects used (all through `OpenSafety.SOD.Server`)

  0x1019/0 UDID; 0x1C00/1 main SADR; 0x1200/1 SDN; 0x1200/4 UDID of the SCM;
  0x1018/7 parameter timestamp; 0x100C/1 guard time, /2 life time factor;
  0x100D/0 refresh time; 0x100E/0 pre-operational retries.

  ## Options

    * `:sod` - the node's `OpenSafety.SOD.Server` (required)
    * `:spdo` - the node's `OpenSafety.SPDO`, switched with the state
    * `:owner` - pid for callbacks and errors (default: caller)
    * `:param_set_processed` - see above
    * `:max_tx_spdo` - `SPDO_cfg_MAX_NO_TX_SPDO`; 1 means no additional SADRs
    * `:scm` - the node's `OpenSafety.SCM`, if it runs one
      (`EPLS_cfg_SCM`): then SCM SET TO STOP / SET TO OP (commands 4 and 6)
      deactivate / activate it, without a response
  """

  @behaviour :gen_statem

  import Bitwise

  alias OpenSafety.{Frame, SPDO}
  alias OpenSafety.SOD.Server, as: SOD
  alias OpenSafety.SPDO.Time

  # SNMT response frame IDs (SNMT_k_FRM_TYPE 0x28 | minor)
  @resp_udid 0x29
  @sadr_assigned 0x2B
  @resp_ext 0x2D
  @rst_guard_scm 0x2F

  # Minor request IDs
  @udid_req 0
  @ass_sadr 2
  @ext_req 4

  # SNMT_t_EXT_SERV_REQ
  @sn_set_to_preop 0
  @sn_set_to_op 2
  @scm_guard_sn 8
  @assgn_add_sadr 10
  @sn_ack 12
  @assgn_udid_scm 14
  @scm_set_to_stop 4
  @scm_set_to_op 6

  # t_SNMTS_EXT_SERV_RESP
  @sts_preop 1
  @sts_op 3
  @add_sadr_assgn 5
  @sn_fail 7
  @sts_busy 9
  @udid_scm_assgn 15

  # SNMTS_k_FAIL_*
  @grp_stk 4
  @err_crc_chksum 1
  @err_map_failed_rx 2
  @err_map_failed_tx 3

  @udid_len 6
  @continuous_retries 0xFF

  ## API

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    :gen_statem.start_link(__MODULE__, opts, [])
  end

  @doc "SNMTS_PerformTransPreOp: leave Initialization, or drop to pre-operational."
  def perform_trans_pre_op(pid, ct), do: event(pid, :api_set_to_preop, ct)

  @doc "SNMTS_PassParamChkSumValid."
  def pass_param_chksum_valid(pid, valid?),
    do: :gen_statem.call(pid, {:chksum_avail, valid?})

  @doc "SNMTS_EnterOpState. Error group 4 (stack) is reserved."
  def enter_op_state(pid, enter?, group \\ 0, code \\ 0),
    do: :gen_statem.call(pid, {:conf_avail, enter?, group, code})

  @doc """
  SNMTS_ProcessRequest on a decoded SNMT request, repeated while the state
  machine reports busy. Returns `{:reply, frame}`, `:noreply` (processed,
  nothing to answer) or `:rejected` (the C returns FALSE; the SSC counts
  it as `SERR_k_ACYC_REJECT`).
  """
  def process_request(pid, ct, %Frame{} = f), do: request(pid, ct, f, false)

  defp request(pid, ct, f, busy) do
    case :gen_statem.call(pid, {:request, ct, f, busy}) do
      {_ok, _tx, true, f2} -> request(pid, ct, f2, true)
      {true, tx, false, _f} when tx != nil -> {:reply, tx}
      {true, _tx, false, _f} -> :noreply
      _ -> :rejected
    end
  end

  @doc "SNMTS_TimerCheck. Returns the frames to send (at most `free`)."
  def timer_check(pid, ct, free), do: :gen_statem.call(pid, {:chk_timer, ct, free})

  @doc "SNMTS_GetSnState: :initialization | :pre_operational | :operational."
  def sn_state(pid), do: :gen_statem.call(pid, :sn_state)

  @doc "The internal t_FSM_STATE."
  def fsm_state(pid), do: :gen_statem.call(pid, :fsm_state)

  defp event(pid, ev, ct), do: :gen_statem.call(pid, {:event, ev, ct})

  ## gen_statem

  @impl true
  def callback_mode, do: :state_functions

  @impl true
  def init(opts) do
    d = %{
      sod: Keyword.fetch!(opts, :sod),
      spdo: Keyword.get(opts, :spdo),
      scm: Keyword.get(opts, :scm),
      owner: Keyword.fetch!(opts, :owner),
      param_set_processed: Keyword.get(opts, :param_set_processed, fn -> true end),
      max_tx_spdo: Keyword.get(opts, :max_tx_spdo, 1),
      # SNMTSresponse.c
      sn_fail_sent: false,
      last_fail: {0, 0},
      # SNMTSappInfo.c
      calc_chksum: false,
      api_conf: false,
      int_err: {0, 0},
      # SNMTSlifetime.c
      guard_running: false,
      guard_to: 0,
      life_cnt: 0,
      # SNMTSrefresh.c
      refresh_to: 0,
      retries: 0
    }

    {:ok, :initialization, d}
  end

  # Every state function takes one normalized event and returns
  # {result, next_state, data, tx_frame | nil, busy, rx_frame}.
  @states ~w(initialization wf_sadr_ass_step1 wf_sadr_ass_step2 wf_udid_scm_ass
             wf_set_to_op1_step1 wf_set_to_op1_step2 wf_api_chksum wf_set_to_op2
             wf_api_conf wf_set_to_op3 operational_step1 operational_step2)a

  for state <- @states do
    def unquote(state)({:call, from}, msg, d), do: handle(unquote(state), from, msg, d)
  end

  defp handle(state, from, :sn_state, d), do: reply(state, d, from, main_state(state))
  defp handle(state, from, :fsm_state, d), do: reply(state, d, from, state)

  defp handle(state, from, {:event, ev, ct}, d) do
    {ok, state, d, _tx, _busy, _rx} = fsm(state, ev, ct, nil, d)
    reply(state, d, from, ok)
  end

  # SNMTS_PassParamChkSumValid: the event first, the result stored only if
  # the state machine accepted it.
  defp handle(state, from, {:chksum_avail, valid?}, d) do
    {ok, state, d, _, _, _} = fsm(state, :chksum_avail, 0, nil, d)
    d = if ok, do: %{d | calc_chksum: valid?}, else: d
    reply(state, d, from, ok)
  end

  defp handle(state, from, {:conf_avail, enter?, group, code}, d) do
    if not enter? and group == @grp_stk do
      reply(state, error(d, :err_grp_inv, 0), from, false)
    else
      {ok, state, d, _, _, _} = fsm(state, :conf_avail, 0, nil, d)

      d =
        cond do
          not ok -> d
          enter? -> %{d | api_conf: true}
          true -> %{d | api_conf: false, int_err: {group, code}}
        end

      reply(state, d, from, ok)
    end
  end

  defp handle(state, from, {:chk_timer, ct, free}, d) do
    if free == 0 do
      reply(state, error(d, :no_mngt_frms_avail, 0), from, [])
    else
      {_ok, state, d, tx, _busy, _rx} = fsm(state, :chk_timer, ct, nil, d)
      reply(state, d, from, if(tx, do: [tx], else: []))
    end
  end

  defp handle(state, from, {:request, ct, f, busy}, d) do
    {ok, state, d, tx, busy, rx} =
      if busy do
        process_request_frame(state, ct, f, d)
      else
        case check_request(f, d) do
          {:ok, d} -> process_request_frame(state, ct, f, d)
          {:error, d} -> {false, state, d, nil, false, f}
        end
      end

    busy = ok and busy
    reply(state, d, from, {ok, tx, busy, rx})
  end

  defp reply(state, d, from, r), do: {:next_state, state, d, [{:reply, from, r}]}

  defp main_state(:initialization), do: :initialization
  defp main_state(s) when s in [:operational_step1, :operational_step2], do: :operational
  defp main_state(_), do: :pre_operational

  ## Request decoding (SNMTSprocess.c)

  # checkRequest: CT and TR unused; filterServReq.
  defp check_request(f, d) do
    cond do
      f.ct != 0 -> {:error, error(d, :ct_field_not_unused, f.ct)}
      f.tr != 0 -> {:error, error(d, :tr_field_not_unused, f.tr)}
      true -> filter_serv_req(f, d)
    end
  end

  # Only UDID request and SADR assignment may reach a node that is not
  # (yet) addressed by this SADR/SDN.
  defp filter_serv_req(f, d) do
    own_sadr = sod_get(d, 0x1C00, 1)
    own_sdn = sod_get(d, 0x1200, 1)
    minor = f.id &&& 0x07

    if own_sadr == 0 or own_sadr != f.adr or own_sdn == 0 or own_sdn != f.sdn do
      if minor in [@udid_req, @ass_sadr],
        do: {:ok, d},
        else: {:error, error(d, :req_rej_inv_dsadr, f.adr <<< 16 ||| f.sdn)}
    else
      {:ok, d}
    end
  end

  # processRequest
  defp process_request_frame(state, ct, f, d) do
    le = byte_size(f.data)

    case f.id &&& 0x07 do
      @udid_req when le != 0 ->
        {false, state, error(d, :le_udid_req_inv, le), nil, false, f}

      @udid_req ->
        {d, tx} = tx_resp_udid(f, d)
        {true, state, d, tx, false, f}

      @ass_sadr ->
        case check_rx_udid(f, d) do
          {:ok, d} -> fsm(state, :rx_sadr, 0, f, d)
          {:error, d} -> {false, state, d, nil, false, f}
        end

      @ext_req when le < 1 ->
        {false, state, error(d, :ext_req_len, 0), nil, false, f}

      @ext_req ->
        process_request_ext(state, ct, f, d)

      _ ->
        {false, state, error(d, :rx_frmid_req_proc_inv, f.id), nil, false, f}
    end
  end

  # processRequestExt
  defp process_request_ext(state, ct, f, d) do
    <<cmd, _::binary>> = f.data
    le = byte_size(f.data)

    case cmd do
      @sn_set_to_preop -> ext(state, le == 1, :le_set_to_preop_inv, :rx_set_to_preop, 0, f, d)
      @sn_set_to_op -> ext(state, le == 5, :le_set_to_op_inv, :rx_set_to_op, ct, f, d)
      @scm_guard_sn -> ext(state, le == 1, :le_guard_inv, :rx_guarding, ct, f, d)
      @assgn_add_sadr -> add_sadr(state, le, f, d)
      @sn_ack -> ext(state, le == 3, :le_err_ack_inv, :sn_ack, 0, f, d)
      @assgn_udid_scm -> ext(state, le == 7, :le_udid_scm, :rx_udid_scm, 0, f, d)
      # SCM_SET_TO_STOP / SCM_SET_TO_OP: only on an SCM node (EPLS_cfg_SCM).
      @scm_set_to_stop when d.scm != nil -> scm_set(state, :stop, le, f, d)
      @scm_set_to_op when d.scm != nil -> scm_set(state, :op, le, f, d)
      _ -> {false, state, error(d, :req_ext_frmtyp_inv1, cmd), nil, false, f}
    end
  end

  defp ext(state, true, _err, ev, ct, f, d), do: fsm(state, ev, ct, f, d)

  defp ext(state, false, err, _ev, _ct, f, d),
    do: {false, state, error(d, err, byte_size(f.data)), nil, false, f}

  # SCM_Deactivate / SCM_Activate; neither is answered.
  defp scm_set(state, :stop, le, f, d) when le != 1,
    do: {false, state, error(d, :le_scm_set_to_stop_inv, le), nil, false, f}

  defp scm_set(state, :op, le, f, d) when le != 1,
    do: {false, state, error(d, :le_scm_set_to_op_inv, le), nil, false, f}

  defp scm_set(state, :stop, _le, f, d) do
    :ok = OpenSafety.SCM.deactivate(d.scm)
    {true, state, d, nil, false, f}
  end

  defp scm_set(state, :op, _le, f, d),
    do: {OpenSafety.SCM.activate(d.scm), state, d, nil, false, f}

  defp add_sadr(state, le, f, d) when le != 5,
    do: {false, state, error(d, :le_add_sadr_ass_inv, le), nil, false, f}

  defp add_sadr(state, _le, f, %{max_tx_spdo: 1} = d) do
    d = error(d, :add_sadr_not_suppo, 0)
    <<cmd, _sadr::binary-size(2), rest::binary>> = f.data
    f = %{f | data: <<cmd, 0::little-16, rest::binary>>}
    {true, state, d, tx_resp_ext(f, @add_sadr_assgn, d), false, f}
  end

  defp add_sadr(state, _le, f, d), do: fsm(state, :rx_sadr_add, 0, f, d)

  # checkRxUdid: the request must carry this node's UDID.
  defp check_rx_udid(f, d) do
    case SOD.read(d.sod, {0x1019, 0}) do
      {:error, code, abort} ->
        {:error, error(d, code, abort)}

      {:ok, udid} ->
        cond do
          byte_size(f.data) != @udid_len ->
            {:error, error(d, :le_sadr_ass_inv, byte_size(f.data))}

          f.data != binary_part(udid, 0, @udid_len) ->
            {:error, error(d, :rx_udid_uneven, 0)}

          true ->
            {:ok, d}
        end
    end
  end

  ## The state machine (SNMTSsnstate.c)

  defp fsm(:initialization, :api_set_to_preop, ct, f, d) do
    case refresh_start(d, ct) do
      {:ok, d} -> {true, :wf_sadr_ass_step1, d, nil, false, f}
      {:error, d} -> {false, :initialization, d, nil, false, f}
    end
  end

  defp fsm(:initialization, ev, _ct, f, d),
    do: {false, :initialization, error(d, :event_undef1, ev), nil, false, f}

  defp fsm(:wf_sadr_ass_step1 = s, ev, ct, f, d) do
    case ev do
      :rx_sadr ->
        main_sadr_assign(f, d)

      :chk_timer ->
        case refresh_check(d, ct) do
          {:ok, true, d} -> {true, s, d, rst_guard_scm(), false, f}
          {:ok, false, d} -> {true, s, d, nil, false, f}
          {:error, d} -> {false, s, d, nil, false, f}
        end

      :rx_guarding ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :api_set_to_preop ->
        {true, s, d, nil, false, f}

      :rx_set_to_preop ->
        {false, s, error(d, :event14, 0), nil, false, f}

      :sn_ack ->
        {false, s, error(d, :event13, 0), nil, false, f}

      :rx_set_to_op ->
        {false, s, error(d, :event1, 0), nil, false, f}

      :rx_udid_scm ->
        {true, s, error(d, :event15, 0), tx_resp_ext(f, @udid_scm_assgn, d), false, f}

      :rx_sadr_add ->
        {false, s, error(d, :event2, 0), nil, false, f}

      _ ->
        {false, s, error(d, :event_undef2, ev), nil, false, f}
    end
  end

  defp fsm(:wf_sadr_ass_step2 = s, ev, _ct, f, d) do
    case ev do
      :rx_sadr ->
        # SDN_SetSdn writes with overwrite; a failure is reported but the
        # assignment still answers, as in C.
        d = sod_put(d, 0x1200, 1, f.sdn, true)
        {true, :wf_udid_scm_ass, d, tx_resp_sadr_assigned(f, d), false, f}

      ev when ev in [:chk_timer, :api_set_to_preop] ->
        {true, s, d, nil, false, f}

      _ ->
        {false, s, error(d, :event_undef3, ev), nil, false, f}
    end
  end

  defp fsm(:wf_udid_scm_ass = s, ev, _ct, f, d) do
    case ev do
      :rx_udid_scm ->
        udid = binary_part(f.data, 1, @udid_len)

        case SOD.write(d.sod, {0x1200, 4}, udid) do
          :ok ->
            {true, :wf_set_to_op1_step1, d, tx_resp_ext(f, @udid_scm_assgn, d, udid), false, f}

          {:error, code, abort} ->
            {true, s, error(d, code, abort), tx_resp_ext(f, @udid_scm_assgn, d), false, f}
        end

      :rx_sadr ->
        main_sadr_assign(f, d)

      :chk_timer ->
        {true, s, d, nil, false, f}

      :rx_guarding ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :api_set_to_preop ->
        {true, s, d, nil, false, f}

      :rx_set_to_preop ->
        {false, s, error(d, :event16, 0), nil, false, f}

      :sn_ack ->
        {false, s, error(d, :event17, 0), nil, false, f}

      :rx_set_to_op ->
        {false, s, error(d, :event18, 0), nil, false, f}

      :rx_sadr_add ->
        {false, s, error(d, :event19, 0), nil, false, f}

      _ ->
        {false, s, error(d, :event_undef12, ev), nil, false, f}
    end
  end

  defp fsm(:wf_set_to_op1_step1 = s, ev, _ct, f, d) do
    case ev do
      :rx_set_to_op ->
        # With Tx SPDOs configured (SPDO_cfg_MAX_NO_TX_SPDO != 0) the mapping
        # is activated next, in step 2.
        if d.param_set_processed.() do
          {true, :wf_set_to_op1_step2, d, tx_resp_ext(f, @sts_busy, d), false, f}
        else
          {true, s, d, tx_resp_ext(f, @sts_busy, d), false, f}
        end

      :rx_guarding ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :rx_set_to_preop ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :rx_sadr_add ->
        {d, f} = enter_add_sadr(f, d)
        {true, s, d, tx_resp_ext(f, @add_sadr_assgn, d), false, f}

      :sn_ack ->
        {false, s, sn_ack_resp_check(f, d), nil, false, f}

      :rx_sadr ->
        main_sadr_assign(f, d)

      ev when ev in [:chk_timer, :api_set_to_preop] ->
        {true, s, d, nil, false, f}

      :rx_udid_scm ->
        {true, s, error(d, :event20, 0), tx_resp_ext(f, @udid_scm_assgn, d), false, f}

      _ ->
        {false, s, error(d, :event_undef4, ev), nil, false, f}
    end
  end

  defp fsm(:wf_set_to_op1_step2 = s, ev, _ct, f, d) do
    case ev do
      :rx_set_to_op ->
        # SPDO_ActivateTxSpdoMapping / SPDO_ActivateRxSpdoMapping. The SPDO
        # layer is configured from options, so activation is never busy.
        case activate_mapping(d) do
          :ok ->
            send(d.owner, {:opensafety_snmts, self(), :calc_param_checksum})
            {true, :wf_api_chksum, d, tx_resp_ext(f, @sts_busy, d), false, f}

          {:error, :tx} ->
            d = fail(d, @grp_stk, @err_map_failed_tx)
            {true, :wf_set_to_op1_step1, d, tx_fail(f, @grp_stk, @err_map_failed_tx, d), false, f}

          {:error, :rx} ->
            d = fail(d, @grp_stk, @err_map_failed_rx)
            {true, :wf_set_to_op1_step1, d, tx_fail(f, @grp_stk, @err_map_failed_rx, d), false, f}
        end

      :rx_guarding ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :rx_set_to_preop ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :rx_sadr_add ->
        {false, s, error(d, :event27, 0), nil, false, f}

      :sn_ack ->
        {false, s, sn_ack_resp_check(f, d), nil, false, f}

      :rx_sadr ->
        main_sadr_assign(f, d)

      ev when ev in [:chk_timer, :api_set_to_preop] ->
        {true, s, d, nil, false, f}

      :rx_udid_scm ->
        {true, s, error(d, :event21, 0), tx_resp_ext(f, @udid_scm_assgn, d), false, f}

      _ ->
        {false, s, error(d, :event_undef5, ev), nil, false, f}
    end
  end

  defp fsm(:wf_api_chksum = s, ev, _ct, f, d) do
    case ev do
      :rx_set_to_op ->
        {true, s, d, tx_resp_ext(f, @sts_busy, d), false, f}

      :chksum_avail ->
        {true, :wf_set_to_op2, d, nil, false, f}

      :rx_sadr ->
        main_sadr_assign(f, d)

      :rx_set_to_preop ->
        {false, s, error(d, :event9, 0), nil, false, f}

      :rx_guarding ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :sn_ack ->
        {false, s, sn_ack_resp_check(f, d), nil, false, f}

      :chk_timer ->
        {true, s, d, nil, false, f}

      :rx_sadr_add ->
        {false, s, error(d, :event3, 0), nil, false, f}

      :rx_udid_scm ->
        {true, s, error(d, :event22, 0), tx_resp_ext(f, @udid_scm_assgn, d), false, f}

      :api_set_to_preop ->
        {true, s, d, nil, false, f}

      _ ->
        {false, s, error(d, :event_undef6, ev), nil, false, f}
    end
  end

  defp fsm(:wf_set_to_op2 = s, ev, _ct, f, d) do
    case ev do
      :rx_set_to_op ->
        case app_chksum_comp(f, d) do
          {:ok, d} ->
            send(d.owner, {:opensafety_snmts, self(), :switch_to_op_request})
            {true, :wf_api_conf, d, tx_resp_ext(f, @sts_busy, d), false, f}

          {:error, d} ->
            d = fail(d, @grp_stk, @err_crc_chksum)
            {true, :wf_set_to_op1_step1, d, tx_fail(f, @grp_stk, @err_crc_chksum, d), false, f}
        end

      :rx_sadr ->
        main_sadr_assign(f, d)

      :rx_guarding ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :rx_set_to_preop ->
        {false, s, error(d, :event10, 0), nil, false, f}

      :sn_ack ->
        {false, s, sn_ack_resp_check(f, d), nil, false, f}

      :chk_timer ->
        {true, s, d, nil, false, f}

      :rx_sadr_add ->
        {false, s, error(d, :event4, 0), nil, false, f}

      :rx_udid_scm ->
        {true, s, error(d, :event23, 0), tx_resp_ext(f, @udid_scm_assgn, d), false, f}

      :api_set_to_preop ->
        {true, s, d, nil, false, f}

      _ ->
        {false, s, error(d, :event_undef7, ev), nil, false, f}
    end
  end

  defp fsm(:wf_api_conf = s, ev, _ct, f, d) do
    case ev do
      :rx_set_to_op ->
        {true, s, d, tx_resp_ext(f, @sts_busy, d), false, f}

      :conf_avail ->
        {true, :wf_set_to_op3, d, nil, false, f}

      :rx_sadr ->
        main_sadr_assign(f, d)

      :rx_guarding ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :rx_set_to_preop ->
        {false, s, error(d, :event11, 0), nil, false, f}

      :sn_ack ->
        {false, s, sn_ack_resp_check(f, d), nil, false, f}

      :chk_timer ->
        {true, s, d, nil, false, f}

      :api_set_to_preop ->
        {true, s, d, nil, false, f}

      :rx_sadr_add ->
        {false, s, error(d, :event5, 0), nil, false, f}

      :rx_udid_scm ->
        {true, s, error(d, :event24, 0), tx_resp_ext(f, @udid_scm_assgn, d), false, f}

      _ ->
        {false, s, error(d, :event_undef8, ev), nil, false, f}
    end
  end

  defp fsm(:wf_set_to_op3 = s, ev, ct, f, d) do
    case ev do
      :rx_set_to_op ->
        if d.api_conf do
          case life_time_start(d, ct) do
            {:ok, d} ->
              tx = tx_resp_ext(f, @sts_op, d)
              if d.spdo, do: :ok = SPDO.set_to_op(d.spdo, ct)
              {true, :operational_step1, d, tx, false, f}

            {:error, d} ->
              {false, s, d, nil, false, f}
          end
        else
          {g, c} = d.int_err
          d = fail(d, g, c)
          {true, :wf_set_to_op1_step1, d, tx_fail(f, g, c, d), false, f}
        end

      :rx_sadr ->
        main_sadr_assign(f, d)

      :rx_guarding ->
        {true, s, d, tx_resp_ext(f, @sts_preop, d), false, f}

      :rx_set_to_preop ->
        {false, s, error(d, :event12, 0), nil, false, f}

      :sn_ack ->
        {false, s, sn_ack_resp_check(f, d), nil, false, f}

      :chk_timer ->
        {true, s, d, nil, false, f}

      :api_set_to_preop ->
        {true, s, d, nil, false, f}

      :rx_sadr_add ->
        {false, s, error(d, :event6, 0), nil, false, f}

      :rx_udid_scm ->
        {true, s, error(d, :event25, 0), tx_resp_ext(f, @udid_scm_assgn, d), false, f}

      _ ->
        {false, s, error(d, :event_undef9, ev), nil, false, f}
    end
  end

  defp fsm(:operational_step1 = s, ev, ct, f, d) do
    case ev do
      :rx_guarding ->
        case life_time_start(d, ct) do
          {:ok, d} -> {true, s, d, tx_resp_ext(f, @sts_op, d), false, f}
          {:error, d} -> {false, s, d, nil, false, f}
        end

      :rx_set_to_preop ->
        tx = tx_resp_ext(f, @sts_preop, d)
        spdo_pre_op(d)
        {true, :wf_set_to_op1_step1, d, tx, false, f}

      :chk_timer ->
        life_time_expiry(s, :wf_set_to_op1_step1, ct, f, d)

      :rx_sadr ->
        {true, :operational_step2, d, nil, true, f}

      :rx_udid_scm ->
        udid = binary_part(f.data, 1, @udid_len)

        case SOD.write(d.sod, {0x1200, 4}, udid) do
          :ok ->
            {true, s, d, tx_resp_ext(f, @udid_scm_assgn, d, udid), false, f}

          {:error, code, abort} ->
            d = error(d, code, abort)
            {true, :wf_sadr_ass_step1, d, tx_resp_ext(f, @udid_scm_assgn, d), false, f}
        end

      :api_set_to_preop ->
        spdo_pre_op(d)
        {true, :wf_set_to_op1_step1, d, nil, false, f}

      :rx_set_to_op ->
        {true, s, d, tx_resp_ext(f, @sts_op, d), false, f}

      :rx_sadr_add ->
        {false, s, error(d, :event7, 0), nil, false, f}

      :sn_ack ->
        {false, s, error(d, :event8, 0), nil, false, f}

      _ ->
        {false, s, error(d, :event_undef10, ev), nil, false, f}
    end
  end

  defp fsm(:operational_step2 = s, ev, ct, f, d) do
    case ev do
      :rx_sadr ->
        {true, :operational_step1, d, tx_resp_sadr_assigned(f, d), false, f}

      :chk_timer ->
        life_time_expiry(s, :wf_sadr_ass_step2, ct, f, d)

      :api_set_to_preop ->
        spdo_pre_op(d)
        {true, :wf_sadr_ass_step2, d, nil, false, f}

      _ ->
        {false, s, error(d, :event_undef11, ev), nil, false, f}
    end
  end

  # SADR assignment from any pre-operational state: write it (a failure is
  # reported, the assignment continues), then step 2 on the same frame.
  defp main_sadr_assign(f, d) do
    d = sod_put(d, 0x1C00, 1, f.adr, false)
    {true, :wf_sadr_ass_step2, d, nil, true, f}
  end

  defp life_time_expiry(s, to_state, ct, f, d) do
    case life_time_check(d, ct) do
      {:ok, true, d} ->
        case refresh_start(d, ct) do
          {:ok, d} ->
            spdo_pre_op(d)
            {true, to_state, %{d | guard_running: false}, nil, false, f}

          {:error, d} ->
            {false, s, d, nil, false, f}
        end

      {:ok, false, d} ->
        {true, s, d, nil, false, f}

      {:error, d} ->
        {false, s, d, nil, false, f}
    end
  end

  defp spdo_pre_op(%{spdo: nil}), do: :ok
  defp spdo_pre_op(%{spdo: spdo}), do: :ok = SPDO.set_to_pre_op(spdo)

  defp activate_mapping(%{spdo: nil}), do: :ok
  defp activate_mapping(%{spdo: spdo}), do: SPDO.activate_mapping(spdo)

  # enterAddSadr: write the additional SADR into the Tx SPDO's comm.
  # parameter; the response echoes what was stored (0 on failure).
  defp enter_add_sadr(f, d) do
    <<cmd, add_sadr::little-16, tx_no::little-16>> = f.data

    {d, stored} =
      cond do
        tx_no < 2 or tx_no > d.max_tx_spdo ->
          {error(d, :txspdo_num_inv, tx_no), 0}

        true ->
          case SOD.attr_get(d.sod, 0x1C00 + tx_no - 1, 1) do
            {:error, :attr_get, abort}
            when abort in [:obj_does_not_exist, :sub_idx_does_not_exist] ->
              {error(d, :spdo_num, tx_no), 0}

            {:error, code, abort} ->
              {error(d, code, abort), 0}

            {:ok, h, _} ->
              case SOD.write(d.sod, h, <<add_sadr::little-16>>) do
                :ok -> {d, add_sadr}
                {:error, code, abort} -> {error(d, code, abort), 0}
              end
          end
      end

    {d, %{f | data: <<cmd, stored::little-16, tx_no::little-16>>}}
  end

  ## Responses (SNMTSresponse.c)

  defp tx_resp_udid(f, d) do
    {d, udid} =
      case SOD.read(d.sod, {0x1019, 0}) do
        {:ok, u} -> {d, binary_part(u, 0, @udid_len)}
        {:error, code, abort} -> {error(d, code, abort), <<0::48>>}
      end

    {d, resp(f, @resp_udid, f.sdn, f.adr, udid)}
  end

  defp tx_resp_sadr_assigned(f, d) do
    resp(
      f,
      @sadr_assigned,
      sod_get(d, 0x1200, 1),
      sod_get(d, 0x1C00, 1),
      binary_part(f.data, 0, @udid_len)
    )
  end

  defp tx_resp_ext(f, type, _d, udid_scm \\ nil) do
    data =
      case type do
        @add_sadr_assgn -> <<type, binary_part(f.data, 1, 4)::binary>>
        @udid_scm_assgn -> <<type, udid_scm || <<0::48>>::binary>>
        _ -> <<type>>
      end

    resp(f, @resp_ext, f.sdn, f.adr, data)
  end

  defp tx_fail(f, group, code, _d),
    do: resp(f, @resp_ext, f.sdn, f.adr, <<@sn_fail, group, code>>)

  # Remember the last SN FAIL so the SCM's acknowledgement can be matched.
  defp fail(d, group, code), do: %{d | sn_fail_sent: true, last_fail: {group, code}}

  defp resp(f, id, sdn, tadr, data),
    do: %Frame{id: id, adr: f.tadr, sdn: sdn, ct: 0, tr: 0, tadr: tadr, data: data}

  # SNMTS_TxRespRstGuardScm: fixed SADR, SDN and TADR of 1.
  defp rst_guard_scm,
    do: %Frame{id: @rst_guard_scm, adr: 1, sdn: 1, ct: 0, tr: 0, tadr: 1, data: <<>>}

  # SNMTS_SnAckRespCheck
  defp sn_ack_resp_check(f, d) do
    <<_cmd, group, code>> = f.data

    cond do
      not d.sn_fail_sent ->
        error(d, :sn_ack2, 0)

      d.last_fail == {group, code} ->
        send(d.owner, {:opensafety_snmts, self(), {:error_ack, group, code}})
        %{d | sn_fail_sent: false}

      true ->
        {lg, lc} = d.last_fail
        error(d, :sn_ack1, lg <<< 24 ||| lc <<< 16 ||| group <<< 8 ||| code)
    end
  end

  ## Application info (SNMTSappInfo.c)

  defp app_chksum_comp(f, d) do
    <<_cmd, rx_ts::little-32>> = f.data

    cond do
      not d.calc_chksum ->
        {:error, error(d, :param_chksum_inv, 0)}

      true ->
        case SOD.get(d.sod, 0x1018, 7) do
          {:ok, ^rx_ts} -> {:ok, d}
          {:ok, ts} -> {:error, error(d, :param_timestamp_inv, ts)}
          {:error, code, abort} -> {:error, error(d, code, abort)}
        end
    end
  end

  ## Life guarding (SNMTSlifetime.c)

  defp life_time_start(d, ct) do
    with {:ok, d} <- guard_time_start(d, ct),
         {:ok, factor} <- sod_fetch(d, 0x100C, 2) do
      {:ok, %{d | life_cnt: band(factor - 1, 0xFF), guard_running: true}}
    end
  end

  defp life_time_check(%{guard_running: false} = d, _ct), do: {:error, error(d, :timer, 0)}

  defp life_time_check(d, ct) do
    cond do
      not Time.timeout?(ct, d.guard_to) ->
        {:ok, false, d}

      d.life_cnt == 0 ->
        {:ok, true, error(d, :life_time_elapsed, 0)}

      true ->
        case guard_time_start(d, ct) do
          {:ok, d} -> {:ok, false, %{d | life_cnt: d.life_cnt - 1}}
          {:error, d} -> {:error, %{d | guard_running: false}}
        end
    end
  end

  defp guard_time_start(d, ct) do
    with {:ok, t} <- sod_fetch(d, 0x100C, 1), do: {:ok, %{d | guard_to: Time.u32(ct + t)}}
  end

  ## Pre-operational refresh (SNMTSrefresh.c)

  defp refresh_start(d, ct), do: refresh_update(%{d | retries: 0}, ct)

  defp refresh_update(d, ct) do
    with {:ok, t} <- sod_fetch(d, 0x100D, 0), do: {:ok, %{d | refresh_to: Time.u32(ct + t)}}
  end

  defp refresh_check(d, ct) do
    case sod_fetch(d, 0x100E, 0) do
      {:error, d} ->
        {:error, d}

      {:ok, max} when max != @continuous_retries and d.retries >= max ->
        {:ok, false, d}

      {:ok, _max} ->
        if Time.timeout?(ct, d.refresh_to) do
          d = error(%{d | retries: d.retries + 1}, :refr_time_elapsed, 0)

          case refresh_update(d, ct) do
            {:ok, d} -> {:ok, true, d}
            {:error, d} -> {:error, d}
          end
        else
          {:ok, false, d}
        end
    end
  end

  ## SOD access

  defp sod_fetch(d, i, s) do
    case SOD.get(d.sod, i, s) do
      {:ok, v} -> {:ok, v}
      {:error, code, abort} -> {:error, error(d, code, abort)}
    end
  end

  defp sod_get(d, i, s) do
    case SOD.get(d.sod, i, s) do
      {:ok, v} -> v
      _ -> 0
    end
  end

  defp sod_put(d, i, s, v, overwrite) do
    case SOD.put(d.sod, i, s, v, overwrite) do
      :ok -> d
      {:error, code, abort} -> error(d, code, abort)
    end
  end

  defp error(d, code, info) do
    send(d.owner, {:opensafety_snmts, self(), {:error, code, info}})
    d
  end
end
