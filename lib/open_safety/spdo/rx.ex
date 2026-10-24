defmodule OpenSafety.SPDO.Rx do
  @moduledoc """
  One Rx SPDO: the Time Synchronization Consumer state machine
  (`SPDOrxSyncConsSm.c`) as a `gen_statem`, with the SPDO Consumer state
  machine (`SPDOrxConsSm.c`) in its data.

  ## States (time synchronization)

    * `:send_treq` - send the first TReq of a block.
    * `:wf_tres` - send the rest of the block (`no_consecutive_treq`), and
      wait for a TRes whose TR falls inside the block and whose round trip
      is within `min/max_tsync_prop_delay`.
    * `:wf_next_treq_block` - no answer within `max_tsync_prop_delay`;
      wait `time_delay_treq` and send another block.
    * `:wf_next_time_sync` - synchronized; resynchronize after
      `time_delay_sync`.

  The time request cycle (`time_request_cycle`) bounds the whole attempt;
  expiry, too many unanswered TReqs, or a round trip that is too short is a
  time synchronization failure, which drops the consumer to its safe state.

  ## Consumer (data)

  `safe` is the consumer's state: true until a data frame passes the
  propagation-delay window *after* a frame has already seeded the CT check
  (the first good frame after synchronization is never taken over). The
  SCT watchdog is a deadline in CT: no valid data before it means safe
  state and `:sct_timer`.

  ## Configuration (`0x1400..0x17FE`)

  `:sadr` (1, 0 disables), `:sct` (2), `:no_consecutive_treq` (3),
  `:time_delay_treq` (4), `:time_delay_sync` (5), `:min_tsync_prop_delay`
  (6), `:max_tsync_prop_delay` (7), `:min_spdo_prop_delay` (8),
  `:max_spdo_prop_delay` (9), `:best_case_tres_delay` (10),
  `:time_request_cycle` (11), `:tx_spdo_no` (12), plus `:len` (mapped
  payload bytes) and `:max_not_answered_tr` (`SPDO_cfg_NO_NOT_ANSWERED_TR`,
  default 100).

  ## Replies

  Every call returns `{events, info, time_sync_ok}`; the coordinator keeps
  the last `time_sync_ok` per Rx SPDO to set the connection-valid bit of
  the Tx SPDO it synchronizes over (`GetConnectionValid`). Events, oldest
  first:

    * `{:data, payload}` - valid process data taken over
    * `:safe_state` - consumer went from valid to safe
    * `{:error, code, info}` - the C stack's `SERR_SetError` for this SPDO,
      `code` named after `SPDO_k_ERR_*`

  ## Mapping

  With `:sod` and `:mapping` (from `OpenSafety.SPDO.Config`), valid data
  is also written into the mapped objects (`SPDO_RxMappingProcess`; dummy
  entries are skipped), and every pass through the safe state writes the
  mapped objects' defaults (`SPDO_RxSpdoToSafeState`).

  ## Connection valid

  The connection-valid bit field (`SHNF_aaulConnValidBit`) and its
  statistic (`SHNF_aaulConnValidStatistic`): set while the consumer is
  valid and the producer's frames carry the connection-valid ID bit,
  cleared otherwise, counting valid-to-invalid edges. `conn_valid/1`
  returns `{valid, edges}`; `reset/1` clears the bit, not the count.

  ## Statistics

  With `:serr` and `:idx` in the configuration (the coordinator sets
  both), every error above is also counted as the C counts it
  (`SERR_CountSpdoEvt`), and so is a frame dropped for an invalid CT
  (`:inv_ct`), which raises no error.
  """

  @behaviour :gen_statem

  alias OpenSafety.SERR
  alias OpenSafety.SOD.Server, as: SOD
  alias OpenSafety.SPDO.Tx
  import OpenSafety.SPDO.Time

  # EPLS_k_MAX_TR + 1
  @tr_mod 64

  # SERR_CountSpdoEvt next to each SERR_SetError of the consumers.
  @counted %{
    rx_len: :payload,
    sct_timer: :sct_tout,
    delay_short: :prop_short,
    delay_long: :prop_long,
    tres_treq: :tr_late,
    late_tres: :tr_late,
    tr_expired: :tr_exp,
    treq_time_1: :tr_time1,
    treq_time_2: :tr_time2,
    short_tsync: :tr_prop_short,
    long_tsync: :tr_prop_long,
    tr_invalid: :tr_inv
  }

  def start_link(cfg), do: :gen_statem.start_link(__MODULE__, cfg, [])

  @doc "SPDO_ResetRxSm for this SPDO."
  def reset(pid), do: :gen_statem.call(pid, :reset)

  @doc """
  Build pass 2 (SPDO_TimeSyncConsSm with no frame): maybe send a TReq
  through `tx`. Info is `{frames, budget}`. Only called for an active SPDO
  (SADR != 0); the coordinator skips inactive ones, as the C does.
  """
  def build(pid, ct, tx, conn_valid, budget),
    do: :gen_statem.call(pid, {:build, ct, tx, conn_valid, budget})

  @doc "Data-only or TReq frame from this SPDO's producer."
  def data(pid, ct, frame), do: :gen_statem.call(pid, {:data, ct, frame})

  @doc """
  TRes from this SPDO's producer. `for_us` is whether its TADR is one of
  this node's Tx SPDO addresses (only then does it feed synchronization).
  """
  def tres(pid, ct, frame, for_us), do: :gen_statem.call(pid, {:tres, ct, frame, for_us})

  @doc "SPDO_CheckRxTimeout for this SPDO."
  def check_timeout(pid, ct), do: :gen_statem.call(pid, {:check, ct})

  @doc "SPDO_GetRxSpdoStatus."
  def status(pid, ct), do: :gen_statem.call(pid, {:status, ct})

  @doc "Connection-valid bit and its valid-to-invalid count: `{valid, edges}`."
  def conn_valid(pid), do: :gen_statem.call(pid, :conn_valid)

  ## gen_statem

  @impl true
  def callback_mode, do: :state_functions

  @impl true
  def init(cfg) do
    cfg =
      cfg
      |> Map.put_new(:len, 0)
      |> Map.put_new(:max_not_answered_tr, 100)

    {:ok, :send_treq, reset_data(%{cfg: cfg, cv: false, cv_edges: 0})}
  end

  ## Time synchronization states

  def send_treq({:call, from}, {:build, ct, tx, cv, budget}, d) do
    {frames, budget, d} = send_treq_frame(d, ct, tx, cv, budget)

    if frames == [] do
      reply(:send_treq, d, from, frames, budget)
    else
      d = %{d | t_cycle: u32(ct + d.cfg.time_request_cycle), first_tr: d.cnt_tr}
      reply(:wf_tres, inc_treq(d, ct), from, frames, budget)
    end
  end

  def send_treq(type, msg, d), do: common(:send_treq, type, msg, d)

  def wf_tres({:call, from}, {:build, ct, tx, cv, budget}, d) do
    case wf_tres_check(d, ct) do
      {:failed, d} ->
        reply(:send_treq, d, from, [], budget)

      {:block_done, d} ->
        reply(:wf_next_treq_block, d, from, [], budget)

      :wait ->
        if d.n_consec < d.cfg.no_consecutive_treq do
          {frames, budget, d} = send_treq_frame(d, ct, tx, cv, budget)
          d = if frames == [], do: d, else: inc_treq(d, ct)
          reply(:wf_tres, d, from, frames, budget)
        else
          reply(:wf_tres, d, from, [], budget)
        end
    end
  end

  def wf_tres(type, msg, d), do: common(:wf_tres, type, msg, d)

  def wf_next_treq_block({:call, from}, {:build, ct, tx, cv, budget}, d) do
    cond do
      timeout?(ct, d.t_cycle) ->
        d = d |> error(:treq_time_2, 0) |> sync_failure()
        reply(:send_treq, d, from, [], budget)

      timeout?(ct, d.t_td) ->
        {frames, budget, d} = send_treq_frame(d, ct, tx, cv, budget)

        if frames == [] do
          reply(:wf_next_treq_block, d, from, frames, budget)
        else
          reply(:wf_tres, inc_treq(%{d | first_tr: d.cnt_tr}, ct), from, frames, budget)
        end

      true ->
        reply(:wf_next_treq_block, d, from, [], budget)
    end
  end

  def wf_next_treq_block(type, msg, d), do: common(:wf_next_treq_block, type, msg, d)

  def wf_next_time_sync({:call, from}, {:build, ct, tx, cv, budget}, d) do
    if timeout?(ct, d.t_ts) do
      {frames, budget, d} = send_treq_frame(d, ct, tx, cv, budget)

      if frames == [] do
        reply(:send_treq, d, from, frames, budget)
      else
        d = %{d | t_cycle: u32(ct + d.cfg.time_request_cycle), first_tr: d.cnt_tr}
        reply(:wf_tres, inc_treq(d, ct), from, frames, budget)
      end
    else
      reply(:wf_next_time_sync, d, from, [], budget)
    end
  end

  def wf_next_time_sync(type, msg, d), do: common(:wf_next_time_sync, type, msg, d)

  ## Calls valid in every state

  # ProcessTRes: CT check first; then, if the TRes answers one of our Tx
  # SPDOs, the synchronization step for the current state; then the
  # consumer, since a TRes also carries process data.
  defp common(state, {:call, from}, {:tres, ct, f, for_us}, d) do
    if ct_valid?(d, f.ct) do
      {state, d} = if for_us, do: sync_tres(state, d, ct, f), else: {state, d}
      events(state, cons_sm(d, ct, f, false), from, :ok)
    else
      events(state, count(d, :inv_ct), from, :ok)
    end
  end

  defp common(state, {:call, from}, {:data, ct, f}, d) do
    d = if ct_valid?(d, f.ct), do: cons_sm(d, ct, f, false), else: count(d, :inv_ct)
    events(state, d, from, :ok)
  end

  defp common(state, {:call, from}, {:check, ct}, d),
    do: events(state, cons_sm(d, ct, nil, false), from, :ok)

  # SPDO_ResetRxSm (TimeSyncConsSmInit, SPDO_RxSpdoToSafeState,
  # SPDO_ConsSmResetRx) and SPDO_ResetConnectionValidBitField.
  defp common(_state, {:call, from}, :reset, d) do
    d = reset_data(%{cfg: d.cfg, cv: false, cv_edges: d.cv_edges})
    map_defaults(d)
    {:next_state, :send_treq, d, [{:reply, from, {[], :ok, false}}]}
  end

  defp common(state, {:call, from}, :conn_valid, d),
    do: {:next_state, state, d, [{:reply, from, {d.cv, d.cv_edges}}]}

  defp common(state, {:call, from}, {:status, ct}, d) do
    status =
      if d.sync_ok and not d.safe do
        {:ok,
         %{
           data: d.payload,
           d_ct: d.d_ct_prod,
           age: u32(ct - (d.sct_deadline - d.cfg.sct)),
           prop_delay: d.t_prop_del
         }}
      else
        :invalid
      end

    {:next_state, state, d, [{:reply, from, {[], status, d.sync_ok}}]}
  end

  ## Time synchronization helpers

  # SPDO_TimeSyncConsSm with a TRes, per state.
  defp sync_tres(:send_treq, d, _ct, _f), do: {:send_treq, error(d, :tres_treq, 0)}

  defp sync_tres(:wf_tres, d, ct, f) do
    case wf_tres_check(d, ct) do
      {:failed, d} -> {:send_treq, d}
      {:block_done, d} -> {:wf_next_treq_block, d}
      :wait -> accept_tres(d, ct, f)
    end
  end

  defp sync_tres(:wf_next_treq_block, d, _ct, _f),
    do: {:wf_next_treq_block, error(d, :late_tres, 0)}

  defp sync_tres(:wf_next_time_sync, d, _ct, _f), do: {:wf_next_time_sync, d}

  # The checks at the top of k_STATE_WF_TRES, run on every call in that
  # state: cycle timer or unanswered-TReq limit means failure; the last
  # TReq of the block outliving max_tsync_prop_delay means wait for the
  # next block.
  defp wf_tres_check(d, ct) do
    limit = d.cfg.max_not_answered_tr

    cond do
      d.not_answered == limit ->
        {:failed, %{d | not_answered: 0} |> error(:tr_expired, 0) |> sync_failure()}

      timeout?(ct, d.t_cycle) ->
        {:failed, d |> error(:treq_time_1, 0) |> sync_failure()}

      timeout?(ct, d.t_max_prop) and d.n_consec >= d.cfg.no_consecutive_treq ->
        {:block_done, %{d | n_consec: 0, t_td: u32(ct + d.cfg.time_delay_treq)}}

      true ->
        :wait
    end
  end

  # StateWaitForTres with a TRes.
  defp accept_tres(d, ct, f) do
    if tr_valid?(f.tr, d.first_tr, d.cnt_tr) do
      sent_ct = Map.get(d.sent, f.tr, 0)
      prop = u32(ct - sent_ct)
      c = d.cfg

      cond do
        prop >= c.min_tsync_prop_delay and prop <= c.max_tsync_prop_delay ->
          d = %{
            d
            | t_ref_cons: u16(u16(sent_ct) + c.best_case_tres_delay),
              t_ref_prod: f.ct,
              t_prop_del: u16(prop),
              sync_ok: true,
              n_consec: 0,
              not_answered: 0,
              t_ts: u32(ct + c.time_delay_sync)
          }

          {:wf_next_time_sync, d}

        prop < c.min_tsync_prop_delay ->
          d = %{d | n_consec: 0} |> error(:short_tsync, prop) |> sync_failure()
          {:send_treq, d}

        true ->
          {:wf_tres, error(d, :long_tsync, prop)}
      end
    else
      {:wf_tres, error(d, :tr_invalid, f.tr)}
    end
  end

  # IsTrValid: TR inside [first, last) of the block, modulo the TR wrap.
  defp tr_valid?(tr, first, last) do
    cond do
      last > first -> first <= tr and tr < last
      last < first -> first <= tr or tr < last
      true -> false
    end
  end

  # IncTReqCounters
  defp inc_treq(d, ct) do
    n = d.n_consec + 1

    d = %{
      d
      | sent: Map.put(d.sent, d.cnt_tr, ct),
        cnt_tr: rem(d.cnt_tr + 1, @tr_mod),
        n_consec: n,
        not_answered: d.not_answered + 1
    }

    if n == d.cfg.no_consecutive_treq,
      do: %{d | t_max_prop: u32(ct + d.cfg.max_tsync_prop_delay)},
      else: d
  end

  defp send_treq_frame(d, ct, tx, cv, budget) do
    {frames, budget} = Tx.send_treq(tx, ct, d.cnt_tr, d.cfg.sadr, cv, budget)
    {frames, budget, d}
  end

  ## Consumer (SPDOrxConsSm.c)

  # SPDO_CtValid
  defp ct_valid?(d, frame_ct),
    do: not d.ct_chk or (frame_ct != d.last_ct and ct_ahead?(frame_ct, d.last_ct))

  defp sync_failure(d), do: cons_sm(d, nil, nil, true)

  # SPDO_ConsSm. `f` nil is the timeout check; `failure` is a time
  # synchronization failure.
  defp cons_sm(d, ct, f, failure) do
    d = conn_valid_bit(d, f, failure)

    cond do
      d.safe ->
        d = to_safe(d)
        if f, do: process_data(d, ct, f), else: d

      failure ->
        %{to_safe(d) | ct_chk: false, sync_ok: false, safe: true}

      f != nil ->
        process_data(d, ct, f)

      timeout?(ct, d.sct_deadline) ->
        d = error(d, :sct_timer, 0)
        %{to_safe(d) | ct_chk: false, sync_ok: false, safe: true}

      true ->
        d
    end
  end

  # ProcessData
  defp process_data(d, ct, f) do
    if d.sync_ok do
      c = d.cfg
      d_cons = u16(u16(ct) - d.t_ref_cons)
      d_prod = u16(f.ct - d.t_ref_prod)
      prop = u16(d_cons - d_prod)

      cond do
        prop < c.min_spdo_prop_delay or d_prod > d_cons ->
          d = error(d, :delay_short, prop)
          %{to_safe(d) | ct_chk: false, sync_ok: false, safe: true}

        prop <= c.max_spdo_prop_delay ->
          cond do
            # The first frame after synchronization only seeds the CT check.
            not d.ct_chk ->
              %{to_safe(d) | ct_chk: true, last_ct: f.ct, safe: true}

            byte_size(f.data) == c.len ->
              map_data(d, f.data)

              %{
                d
                | ct_chk: true,
                  d_ct_prod: u16(f.ct - d.last_ct),
                  last_ct: f.ct,
                  sct_deadline: u32(ct + c.sct),
                  safe: false,
                  payload: f.data
              }
              |> event({:data, f.data})

            true ->
              error(d, :rx_len, byte_size(f.data))
          end

        true ->
          error(d, :delay_long, prop)
      end
    else
      d
    end
  end

  # SPDO_RxSpdoToSafeState: payload back to default. The event fires on
  # the valid-to-safe edge only, not on every call the C makes in safe state.
  defp to_safe(d) do
    map_defaults(d)
    if d.safe, do: %{d | payload: nil}, else: event(%{d | payload: nil}, :safe_state)
  end

  # The connection-valid bit, at the top of SPDO_ConsSm.
  defp conn_valid_bit(d, f, failure) do
    cond do
      failure or d.safe -> cv_drop(d)
      f == nil -> d
      Bitwise.band(f.id, 1) == 0 -> cv_drop(d)
      true -> %{d | cv: true}
    end
  end

  defp cv_drop(%{cv: true} = d), do: %{d | cv: false, cv_edges: d.cv_edges + 1}
  defp cv_drop(d), do: d

  ## Mapping (SPDOrxmapp.c)

  defp map_data(%{cfg: %{sod: sod, mapping: m}}, data) when is_list(m) and sod != nil do
    Enum.reduce(m, data, fn e, data ->
      <<part::binary-size(e.len), rest::binary>> = data
      if Map.has_key?(e, :index), do: :ok = SOD.poke(sod, {e.index, e.sub}, part)
      rest
    end)

    :ok
  end

  defp map_data(_d, _data), do: :ok

  defp map_defaults(%{cfg: %{sod: sod, mapping: m}}) when is_list(m) and sod != nil do
    for %{index: i, sub: s, len: n} <- m, do: :ok = SOD.poke_default(sod, {i, s}, n)
    :ok
  end

  defp map_defaults(_d), do: :ok

  ## Data

  defp reset_data(%{cfg: cfg} = keep) do
    %{
      cfg: cfg,
      cv: Map.get(keep, :cv, false),
      cv_edges: Map.get(keep, :cv_edges, 0),
      ev: [],
      # t_RX_CONS_SM
      safe: true,
      ct_chk: false,
      last_ct: 0,
      sync_ok: false,
      t_ref_cons: 0,
      t_ref_prod: 0,
      d_ct_prod: 0,
      t_prop_del: 0,
      sct_deadline: 0,
      payload: nil,
      # t_RX_SYNC_CONS_SPDO
      sent: %{},
      first_tr: 0,
      n_consec: 0,
      cnt_tr: 0,
      not_answered: 0,
      t_cycle: 0,
      t_td: 0,
      t_ts: 0,
      t_max_prop: 0
    }
  end

  defp event(d, e), do: %{d | ev: [e | d.ev]}

  defp error(d, code, info) do
    d = if evt = @counted[code], do: count(d, evt), else: d
    event(d, {:error, code, info})
  end

  defp count(d, evt) do
    :ok = SERR.count_spdo(Map.get(d.cfg, :serr), Map.get(d.cfg, :idx, 0), evt)
    d
  end

  defp reply(state, d, from, frames, budget), do: events(state, d, from, {frames, budget})

  defp events(state, d, from, info) do
    {:next_state, state, %{d | ev: []}, [{:reply, from, {:lists.reverse(d.ev), info, d.sync_ok}}]}
  end
end
