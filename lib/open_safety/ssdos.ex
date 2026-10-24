defmodule OpenSafety.SSDOS do
  @moduledoc """
  Safety Service Data Object server (`SSDOSmain.c`, `SSDOSsodAcs.c`,
  `SSDOSupDnwLd.c`): SOD read and write access for the SCM, as a
  `gen_statem` whose states are the C stack's `t_SSDOS_FSM_STATES`.

  ## States

    * `:wf_req_init` - wait for an initiate request (download or upload,
      expedited or segmented) or an abort
    * `:dwnld_resp_init`, `:upld_resp_init` - answer the initiate request
      (reached as "busy" on the same frame)
    * `:dwnld_wf_req_seg`, `:upld_wf_req_seg` - segmented transfer
    * `:resp_abort` - answer with an abort (busy, same frame)

  ## Frame payload (SSDOint.h)

      SACMD | INDEX (u16 LE) | SUB | data...          initiate / abort
      SACMD | data...                                 segment

  SACMD: 0x21 download expedited, 0x29 download segmented, 0x09/0x49
  middle/end download segment, 0x20 upload, 0x28 upload segmented,
  0x08/0x48 middle/end upload segment, 0x04 abort; 0x10 is the toggle bit
  on segments.

  Writes are only accepted in pre-operational (`SodAcsWriteAllowed`), and a
  segmented transfer holds the SOD lock until it ends or aborts.

  ## Driving it

  `process_request/2` takes one decoded SSDO request and returns
  `{:reply, frame}`, `:noreply`, or `:rejected` when the C returns FALSE
  (counted by the SSC as `SERR_k_ACYC_REJECT`), repeating while busy
  exactly as the SSC loop does. Fast (slim) requests, ID 0x3A, may carry up to
  `max_pyld_fast` bytes and are answered with ID 0x3B (the SSC's slim bit).

  Errors go to the owner as `{:opensafety_ssdos, pid, {:error, code, info}}`.

  ## Options

    * `:sod` - `OpenSafety.SOD.Server` (required)
    * `:snmts` - `OpenSafety.SNMTS`, for the pre-operational write check
      (required)
    * `:owner` - pid for errors (default: caller)
    * `:max_pyld` - `EPLS_cfg_MAX_PYLD_LEN` (default 12)
    * `:max_pyld_fast` - `EPLS_cfg_MAX_PYLD_LEN_FAST_SSDO` (default 22)
  """

  @behaviour :gen_statem

  import Bitwise

  alias OpenSafety.{Frame, SNMTS, SOD}
  alias OpenSafety.SOD.Server

  @dwnld_init_exp 0x21
  @dwnld_init_seg 0x29
  @dwnld_seg_mid 0x09
  @dwnld_seg_end 0x49
  @upld_init_exp 0x20
  @upld_init_seg 0x28
  @upld_seg_mid 0x08
  @abort 0x04

  @toggle 0x10
  @seg_bit 0x08
  @endseg_bit 0x40

  @req_fast 0x3A
  @resp 0x39
  @resp_fast 0x3B

  @hdr 4
  @hdr_seg 1
  @obj_len 4

  @strings [:visible_string, :octet_string, :domain]

  ## API

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    :gen_statem.start_link(__MODULE__, opts, [])
  end

  @doc "SSDOS_ProcessRequest, repeated while busy: `{:reply, frame}`, `:noreply` or `:rejected`."
  def process_request(pid, %Frame{} = f), do: request(pid, f, false)

  defp request(pid, f, busy) do
    case :gen_statem.call(pid, {:request, f, busy}) do
      {true, _tx, true} -> request(pid, f, true)
      {true, tx, false} when tx != nil -> {:reply, tx}
      {true, _tx, false} -> :noreply
      _ -> :rejected
    end
  end

  def state(pid), do: :gen_statem.call(pid, :state)

  ## gen_statem

  @impl true
  def callback_mode, do: :state_functions

  @impl true
  def init(opts) do
    d = %{
      sod: Keyword.fetch!(opts, :sod),
      snmts: Keyword.fetch!(opts, :snmts),
      owner: Keyword.fetch!(opts, :owner),
      max: Keyword.get(opts, :max_pyld, 12),
      max_fast: Keyword.get(opts, :max_pyld_fast, 22)
    }

    {:ok, :wf_req_init, fsm_init(d)}
  end

  @states ~w(wf_req_init dwnld_resp_init dwnld_wf_req_seg upld_resp_init
             upld_wf_req_seg resp_abort)a

  for state <- @states do
    def unquote(state)({:call, from}, msg, d), do: handle(unquote(state), from, msg, d)
  end

  defp handle(state, from, :state, d), do: {:next_state, state, d, [{:reply, from, state}]}

  # SSDOS_ProcessRequest: TR unused, and addressed to this node.
  defp handle(state, from, {:request, f, _busy}, d) do
    d = %{d | state: state}

    {ok, state, d, tx, busy} =
      cond do
        f.tr != 0 ->
          {false, state, error(d, :tr, f.tr), nil, false}

        f.sdn != sod_get(d, 0x1200, 1) or f.adr != sod_get(d, 0x1C00, 1) ->
          {false, state, error(d, :req_dsadr, f.adr <<< 16 ||| f.sdn), nil, false}

        true ->
          fsm(state, f, d)
      end

    busy = ok and busy
    {:next_state, state, d, [{:reply, from, {ok, tx, busy}}]}
  end

  ## States

  defp fsm(:wf_req_init, f, d), do: wf_req_init(f, d)

  defp fsm(:dwnld_resp_init, f, d) do
    case d.sa_cmd do
      @dwnld_init_seg ->
        case dwnld_init_seg_resp(f, d) do
          {:ok, d, tx} -> {true, :dwnld_wf_req_seg, d, tx, false}
          {:abort, d, abort} -> reset_abort_send(f, d, abort)
        end

      @dwnld_init_exp ->
        case dwnld_init_exp_resp(f, d) do
          {:ok, d, tx} ->
            {ok, d} = fsm_reset(d, false)
            {ok, :wf_req_init, d, tx, false}

          {:abort, d, abort} ->
            reset_abort_send(f, d, abort)
        end
    end
  end

  defp fsm(:dwnld_wf_req_seg, f, d) do
    le = byte_size(f.data)

    if len_ok?(f, d) and le > @hdr_seg do
      <<sa, _::binary>> = f.data
      d = %{d | sa_cmd: sa}

      case sa &&& bnot(@toggle) &&& 0xFF do
        @dwnld_seg_mid ->
          with_req_valid(f, d, false, fn d ->
            case dwnld_mid_seg(f, d, sa) do
              {:ok, d, tx} -> {true, :dwnld_wf_req_seg, d, tx, false}
              {:abort, d, abort} -> reset_abort_send(f, d, abort)
            end
          end)

        @dwnld_seg_end ->
          with_req_valid(f, d, false, fn d ->
            case dwnld_end_seg(f, d, sa) do
              {:ok, d, tx} ->
                {ok, d} = fsm_reset(d, false)
                {ok, :wf_req_init, d, tx, false}

              {:abort, d, abort} ->
                reset_abort_send(f, d, abort)
            end
          end)

        _ ->
          restart(f, d, sa)
      end
    else
      d = error(d, :pyld_len1, le)
      reset_abort_send(f, d, :len_does_not_match)
    end
  end

  defp fsm(:upld_resp_init, f, d) do
    case d.sa_cmd do
      @upld_init_seg ->
        s = d.seg
        data = <<s.entry::little-32, s.raw::binary>>
        {d, tx} = resp(f, d, @upld_init_seg, true, data)
        {true, :upld_wf_req_seg, %{d | seg: %{s | tranf: byte_size(s.raw)}}, tx, false}

      @upld_init_exp ->
        {d, tx} = resp(f, d, @upld_init_exp, true, d.seg.raw)
        {ok, d} = fsm_reset(d, false)
        {ok, :wf_req_init, d, tx, false}
    end
  end

  defp fsm(:upld_wf_req_seg, f, d) do
    le = byte_size(f.data)

    if len_ok?(f, d) and le >= @hdr do
      <<sa, _::binary>> = f.data
      d = %{d | sa_cmd: sa}

      if (sa &&& bnot(@toggle) &&& 0xFF) == @upld_seg_mid do
        if le == @hdr do
          with_req_valid(f, d, true, fn d ->
            case upld_seg(f, d, sa) do
              {:ok, d, tx, true} ->
                {ok, d} = fsm_reset(d, false)
                {ok, :wf_req_init, d, tx, false}

              {:ok, d, tx, false} ->
                {true, :upld_wf_req_seg, d, tx, false}

              {:abort, d, abort} ->
                reset_abort_send(f, d, abort)
            end
          end)
        else
          d = error(d, :pyld_len3, le)
          reset_abort_send(f, d, :len_does_not_match)
        end
      else
        restart(f, d, sa)
      end
    else
      d = error(d, :pyld_len2, le)
      reset_abort_send(f, d, :len_does_not_match)
    end
  end

  defp fsm(:resp_abort, f, d), do: reset_abort_send(f, d, d.abort)

  # An abort for the running transfer, or any other request, ends the
  # transfer and is treated as a new initiate request.
  defp restart(f, d, sa) do
    go = fn d ->
      case fsm_reset(d, true) do
        {true, d} -> wf_req_init(f, d)
        {false, d} -> {false, :wf_req_init, d, nil, false}
      end
    end

    if sa == @abort, do: with_req_valid(f, d, true, go), else: go.(d)
  end

  ## WfReqInitState

  defp wf_req_init(f, d) do
    le = byte_size(f.data)

    if le >= @hdr and len_ok?(f, d) do
      <<sa, _::binary>> = f.data
      d = %{d | sa_cmd: sa}

      case sa do
        @dwnld_init_exp ->
          {abort, d} = dwnld_init_exp_req(f, d)
          init_result(d, abort, :dwnld_resp_init)

        @dwnld_init_seg ->
          {abort, d} = dwnld_init_seg_req(f, d)
          init_result(d, abort, :dwnld_resp_init)

        @upld_init_exp when le == @hdr ->
          case upld_init_req(f, d) do
            {:no_error, d, seg?} ->
              d = if seg?, do: %{d | sa_cmd: sa ||| @seg_bit}, else: d
              {true, :upld_resp_init, d, nil, true}

            {abort, d, _} ->
              {true, :resp_abort, %{d | abort: abort}, nil, true}
          end

        @upld_init_exp ->
          {false, :wf_req_init, error(d, :upld_init_len, le), nil, true}

        @abort when le == @hdr + 4 ->
          <<_::binary-size(4), code::little-32>> = f.data
          d = error(d, :abort_rx, code)
          {_ok, d} = fsm_reset(d, true)
          {false, :wf_req_init, d, nil, true}

        @abort ->
          {false, :wf_req_init, error(d, :abort_len, le), nil, true}

        _ ->
          d = d |> error(:sacmd, sa) |> idx_copy(f)
          {true, :resp_abort, %{d | abort: :cmd_id_invalid}, nil, true}
      end
    else
      d = error(d, :pyld_len, le)
      {_ok, d} = fsm_reset(d, false)
      {false, :wf_req_init, d, nil, false}
    end
  end

  defp init_result(d, :no_error, next), do: {true, next, d, nil, true}
  defp init_result(d, abort, _next), do: {true, :resp_abort, %{d | abort: abort}, nil, true}

  ## Download (SSDOSupDnwLd.c)

  defp dwnld_init_exp_req(f, d) do
    case attr_get(f, d, false) do
      {:no_error, d, size} ->
        d = put_in(d.seg.entry, size)

        case write_allowed(d, false) do
          {:ok, d} -> {:no_error, d}
          {:error, d, abort} -> {abort, d}
        end

      {abort, d, _} ->
        {abort, d}
    end
  end

  defp dwnld_init_seg_req(f, d) do
    with {:no_error, d, size} <- attr_get(f, d, false),
         d = put_in(d.seg.entry, size),
         {:ok, d} <- write_allowed(d, true) do
      le = byte_size(f.data)

      if le >= @hdr + @obj_len do
        <<_::binary-size(4), rx_size::little-32, raw::binary>> = f.data

        if rx_size <= d.seg.entry do
          seg =
            if rx_size == 0,
              do: %{d.seg | size_unknown: true},
              else: %{d.seg | size_unknown: false, entry: rx_size}

          {:no_error, %{d | seg: %{seg | raw: raw}}}
        else
          {:block_size_invalid, error(d, :dwnld_seg_len, 0)}
        end
      else
        {:len_does_not_match, error(d, :req_pyld_len, 0)}
      end
    else
      {:error, d, abort} -> {abort, d}
      {abort, d, _} -> {abort, d}
    end
  end

  defp dwnld_init_seg_resp(f, d) do
    with {:ok, d} <- lock(d),
         {:ok, d} <- write_first_segment(d) do
      {d, tx} = resp(f, d, @dwnld_init_seg, true, <<>>)
      {:ok, put_in(d.seg.tranf, byte_size(d.seg.raw)), tx}
    end
  end

  defp write_first_segment(%{seg: %{raw: <<>>}} = d), do: {:ok, d}
  defp write_first_segment(d), do: acs_write(d, d.seg.raw, 0, byte_size(d.seg.raw), false)

  defp dwnld_init_exp_resp(f, d) do
    <<_::binary-size(4), raw::binary>> = f.data
    n = byte_size(raw)

    result =
      if d.attr.type in @strings do
        if n <= d.seg.entry,
          do: acs_write(d, raw, 0, n, true),
          else: {:abort, error(d, :dwnld_exp_len1, 0), :len_does_not_match}
      else
        if n != d.seg.entry,
          do: {:abort, error(d, :dwnld_exp_len, 0), :len_does_not_match},
          else: acs_write(d, raw, 0, 0, false)
      end

    with {:ok, d} <- result do
      {d, tx} = resp(f, d, @dwnld_init_exp, true, <<>>)
      {:ok, d, tx}
    end
  end

  defp dwnld_mid_seg(f, d, sa) do
    <<_, raw::binary>> = f.data
    calc = d.seg.tranf + byte_size(raw)

    if calc < d.seg.entry do
      with {:ok, d} <- acs_write(d, raw, d.seg.tranf, byte_size(raw), false) do
        d = put_in(d.seg.tranf, calc)
        {d, tx} = resp(f, d, sa, false, <<>>)
        {:ok, d, tx}
      end
    else
      {:abort, error(d, :dwnld_seg_len2, 0), :block_size_invalid}
    end
  end

  defp dwnld_end_seg(f, d, sa) do
    <<_, raw::binary>> = f.data
    calc = d.seg.tranf + byte_size(raw)

    fits =
      (d.seg.size_unknown and calc <= d.seg.entry) or
        (not d.seg.size_unknown and calc == d.seg.entry)

    if fits do
      with {:ok, d} <- acs_write(d, raw, d.seg.tranf, byte_size(raw), true) do
        {d, tx} = resp(f, d, sa, false, <<>>)
        {:ok, d, tx}
      end
    else
      {:abort, error(d, :dwnld_seg_len1, 0), :block_size_invalid}
    end
  end

  ## Upload

  defp upld_init_req(f, d) do
    case attr_get(f, d, true) do
      {:no_error, d, size} ->
        d = put_in(d.seg.entry, size)

        if size > d.max - @hdr do
          raw_len = d.max - (@hdr + @obj_len)

          with {:ok, d} <- lock_upload(d),
               {:ok, raw, d} <- acs_read(d, 0, raw_len) do
            {:no_error, put_in(d.seg.raw, raw), true}
          else
            {:abort, d, abort} -> {abort, d, true}
          end
        else
          case acs_read(d, 0, 0) do
            {:ok, raw, d} -> {:no_error, put_in(d.seg.raw, binary_part(raw, 0, size)), false}
            {:abort, d, abort} -> {abort, d, false}
          end
        end

      {abort, d, _} ->
        {abort, d, false}
    end
  end

  defp lock_upload(d) do
    case lock(d) do
      {:ok, d} -> {:ok, d}
      {:abort, d, abort} -> {:abort, d, abort}
    end
  end

  defp upld_seg(f, d, sa) do
    rest = d.seg.entry - d.seg.tranf

    {raw_len, last, sa} =
      if rest > d.max - @hdr_seg,
        do: {d.max - @hdr_seg, false, sa},
        else: {rest, true, sa ||| @endseg_bit}

    case acs_read(d, d.seg.tranf, raw_len) do
      {:ok, raw, d} ->
        {d, tx} = resp(f, d, sa, false, raw)
        {:ok, put_in(d.seg.tranf, d.seg.tranf + raw_len), tx, last}

      {:abort, d, abort} ->
        {:abort, d, abort}
    end
  end

  ## SOD access (SSDOSsodAcs.c)

  # SSDOS_SodAcsReqValid: toggle bit (unless abort); with check_obj, the
  # index and sub-index of the running transfer.
  defp with_req_valid(f, d, check_obj, fun) do
    <<sa, rest::binary>> = f.data
    {idx, sub} = idx_of(rest)

    cond do
      (sa &&& @toggle) != 0 != d.toggle and sa != @abort ->
        {false, current(d), error(d, :toggle_bit, 0), nil, false}

      check_obj and {idx, sub} != {d.idx, d.sub} ->
        {false, current(d), error(d, :idx_sidx, 0), nil, false}

      true ->
        fun.(d)
    end
  end

  # The state the call arrived in, for rejections that leave it unchanged.
  defp current(d), do: d.state

  defp idx_of(<<idx::little-16, sub, _::binary>>), do: {idx, sub}
  defp idx_of(_), do: {0, 0}

  defp idx_copy(d, f) do
    <<_, rest::binary>> = f.data
    {idx, sub} = idx_of(rest)
    %{d | idx: idx, sub: sub}
  end

  # SSDOS_SodAcsAttrGet: object size is the actual length for reads, the
  # maximum length for writes.
  defp attr_get(f, d, read?) do
    d = idx_copy(d, f)

    case Server.attr_get(d.sod, d.idx, d.sub) do
      {:error, _code, abort} when abort in [:obj_does_not_exist, :sub_idx_does_not_exist] ->
        {abort, d, 0}

      {:error, code, abort} ->
        {abort, error(d, code, abort), 0}

      {:ok, h, attr} ->
        d = %{d | handle: h, attr: attr}

        if read? do
          case Server.act_len_get(d.sod, h) do
            {:ok, n} -> {:no_error, d, n}
            {:error, code, abort} -> {abort, error(d, code, abort), 0}
          end
        else
          {:no_error, d, attr.len}
        end
    end
  end

  # SSDOS_SodAcsWriteAllowed: write enabled, not locked (for segmented),
  # node pre-operational; strings and domains start empty.
  defp write_allowed(d, seg?) do
    cond do
      not Server.write_access?(d.sod) ->
        {:error, error(d, :wr_acs1, :present_device_state), :present_device_state}

      seg? and Server.locked?(d.sod) ->
        {:error, error(d, :wr_acs2, :present_device_state), :present_device_state}

      SNMTS.sn_state(d.snmts) != :pre_operational ->
        {:error, error(d, :wr_acs3, :present_device_state), :present_device_state}

      d.attr.type in @strings ->
        case Server.act_len_set(d.sod, d.handle, 0) do
          :ok -> {:ok, d}
          {:error, code, abort} -> {:error, error(d, code, abort), abort}
        end

      true ->
        {:ok, d}
    end
  end

  # SSDOS_SodAcsWrite
  defp acs_write(d, data, offset, size, act_len_set?) do
    set =
      if act_len_set?,
        do: Server.act_len_set(d.sod, d.handle, offset + size),
        else: :ok

    with :ok <- set do
      cond do
        offset == 0 and size == 0 and act_len_set? ->
          {:ok, d}

        offset == 0 and size == 0 ->
          sod_write(d, data, 0, 0, false)

        true ->
          sod_write(d, data, offset, size, not act_len_set?)
      end
    else
      {:error, code, abort} -> {:abort, error(d, code, abort), abort}
    end
  end

  defp sod_write(d, data, offset, size, seg_write?) do
    case Server.write(d.sod, d.handle, data, false, offset, size) do
      :ok -> {:ok, if(seg_write?, do: %{d | seg_write_called: true}, else: d)}
      {:error, code, abort} -> {:abort, error(d, code, abort), abort}
    end
  end

  # SSDOS_SodAcsRead: only readable objects; a before-read callback abort
  # is passed to the client without a stack error.
  defp acs_read(d, offset, size) do
    if :ro in d.attr.attr or :ro_const in d.attr.attr do
      case Server.read(d.sod, d.handle, offset, size) do
        {:ok, raw} -> {:ok, raw, d}
        {:error, :clbk_abort_br, abort} -> {:abort, d, abort}
        {:error, code, abort} -> {:abort, error(d, code, abort), :general_error}
      end
    else
      {:abort, d, :obj_not_readable}
    end
  end

  # SSDOS_SodAcsLock
  defp lock(d) do
    case Server.lock(d.sod) do
      :ok -> {:ok, %{d | lock_called: true}}
      {:error, code, abort} -> {:abort, error(d, code, abort), abort}
    end
  end

  # SSDOS_SodAcsResp: the response mirrors the request's addressing and
  # CT; every response flips the toggle bit.
  defp resp(f, d, sa, obj_info?, payload) do
    head = if obj_info?, do: <<sa, d.idx::little-16, d.sub>>, else: <<sa>>
    id = if f.id == @req_fast, do: @resp_fast, else: @resp

    tx = %Frame{
      id: id,
      adr: f.tadr,
      tadr: f.adr,
      sdn: f.sdn,
      ct: f.ct,
      tr: 0,
      data: head <> payload
    }

    {%{d | toggle: not d.toggle}, tx}
  end

  ## Reset (FsmInit, FsmReset, FsmResetAbortSend, SSDOS_SodAcsReset)

  defp reset_abort_send(f, d, abort) do
    {d, tx} = resp(f, d, @abort, true, <<SOD.abort_code(abort)::little-32>>)
    {ok, d} = fsm_reset(d, true)
    {ok, :wf_req_init, d, tx, false}
  end

  defp fsm_reset(d, abort?) do
    {ok, d} = acs_reset(d, abort?)
    {ok, fsm_init(d)}
  end

  defp acs_reset(d, abort?) do
    cond do
      d.lock_called and d.seg_write_called and abort? ->
        case Server.act_len_set(d.sod, d.handle, 0) do
          :ok -> unlock(d)
          {:error, code, abort} -> {false, error(d, code, abort)}
        end

      d.lock_called ->
        unlock(d)

      d.seg_write_called ->
        {false, error(d, :lock_wr_seg, 0)}

      true ->
        {true, d}
    end
  end

  defp unlock(d) do
    case Server.unlock(d.sod) do
      :ok -> {true, d}
      {:error, code, abort} -> {false, error(d, code, abort)}
    end
  end

  defp fsm_init(d) do
    Map.merge(d, %{
      state: :wf_req_init,
      sa_cmd: 0,
      abort: :no_error,
      seg: %{size_unknown: false, raw: <<>>, tranf: 0, entry: 0},
      toggle: false,
      lock_called: false,
      seg_write_called: false,
      idx: 0,
      sub: 0,
      handle: nil,
      attr: nil
    })
  end

  ## Helpers

  defp len_ok?(f, d) do
    le = byte_size(f.data)
    le <= d.max or (f.id == @req_fast and le <= d.max_fast)
  end

  defp sod_get(d, i, s) do
    case Server.get(d.sod, i, s) do
      {:ok, v} -> v
      _ -> 0
    end
  end

  defp error(d, code, info) do
    send(d.owner, {:opensafety_ssdos, self(), {:error, code, info}})
    d
  end
end
