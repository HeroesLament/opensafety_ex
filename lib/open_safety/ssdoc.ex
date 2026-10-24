defmodule OpenSafety.SSDOC do
  @moduledoc """
  SSDO client (`SSDOCaccess.c`, `SSDOCprotocol.c`, `SSDOCservice.c`,
  `SSDOCservreq.c`, `SSDOCservTimer.c`): the SCM's pool of SSDO transfer
  slots, reading and writing the SOD of remote safety nodes.

  Each slot carries the C stack's three layers for one transfer:

    * protocol FSM (`t_PROT_FSM`): which response is expected next -
      `:wf_req_trans` (slot free), `:wf_upld_init_resp`,
      `:wf_dwnld_resp_exp`, `:wf_dwnld_resp_init_seg`,
      `:wf_dwnld_resp_mid_seg`, `:wf_upld_resp_mid_seg`,
      `:wf_dwnld_resp_end_seg`, `:wf_upld_resp_end_seg`
    * service FSM (`t_SERV_FSM`): waiting for a request, or waiting for
      the response to the request in the slot's request buffer
    * response timer: timeout and retries from 0x1201/1 and /2

  ## Requests

  `req` is the C `SSDOC_t_REQ` as a map:

      %{idx: 0x1018, sub: 1, type: :uint32,  # SOD data type atom
        payload_len: 12,                     # max SSDO payload (8..254)
        data_len: 7,                         # write: length of :data;
                                             # read: receive buffer size
        data: <<...>>}                       # write only

  `send_write_req/6` downloads (expedited if it fits, else segmented;
  `fast` uses the slim SSDO frame 0x3A for strings and domains),
  `send_read_req/5` uploads. Both return `{:ok, frame}` or `:error`, and
  refuse a second transfer to the same SADR (`SSDOC_TransferRunning`).

  ## Results instead of callbacks

  Every `SSDOC_t_RESP_CLBK` call becomes an effect for the caller:

      {:resp, reg, len, abort_code, data}

  with `abort_code` the integer `SOD_ABT_*` (0 on success) and `data` the
  uploaded bytes (`nil` for downloads and errors). The C copies uploads
  into the caller's buffer; here the caller gets the bytes.

  `process_response/3` returns `{ok, frames, effects}`: a response can
  trigger the next segment request (or an abort). `build_request/3`
  (`SSDOC_BuildRequest`) retransmits on timeout and aborts once retries
  are used up, returning `{free, frames, effects}`.

  Errors go to the owner as `{:opensafety_ssdoc, pid, {:error, code, info}}`.

  ## Ported as is

  When `checkResponse` rejects a response (wrong toggle bit, index or
  length), the C reports the abort to the caller but leaves the protocol
  FSM in its state while the service FSM goes back to waiting for a
  request: no timeout can fire and the slot is never free again. This
  port does the same.

  ## Options

    * `:sod` - `OpenSafety.SOD.Server` (required)
    * `:owner` - default: caller
    * `:slots` - `SSDOC_cfg_MAX_NUM_FSM` (default 101)
    * `:max_pyld` - `EPLS_cfg_MAX_PYLD_LEN`, enables 64-bit types at >= 12
      (default 12)
    * `:serr` - `OpenSafety.SERR` for the `:ssdo_retry` / `:ssdo_tout`
      counters (per slot)
  """

  use GenServer

  import Bitwise

  alias OpenSafety.{Frame, SERR, SOD}
  alias OpenSafety.SOD.Server
  alias OpenSafety.SPDO.Time

  @dwnld_init_exp 0x21
  @dwnld_init_seg 0x29
  @dwnld_seg_mid 0x09
  @dwnld_seg_end 0x49
  @upld_init_exp 0x20
  @upld_init_seg 0x28
  @upld_seg_mid 0x08
  @upld_seg_end 0x48
  @abort 0x04
  @toggle 0x10

  @req 0x38
  @req_fast 0x3A

  @hdr 4
  @hdr_seg 1
  @obj_len 4
  @abort_len 4

  @max_serv 0xFE
  @min_serv 0x08
  @buf_len 0xFE

  @strings [:visible_string, :octet_string, :domain]

  ## API

  def start_link(opts) do
    opts = Keyword.put_new(opts, :owner, self())
    GenServer.start_link(__MODULE__, opts)
  end

  @doc "SSDOC_CheckFsmAvailable"
  def available?(s), do: GenServer.call(s, :available?)

  @doc "SSDOC_SendWriteReq: `{:ok, frame}` or `:error`."
  def send_write_req(s, sadr, reg, ct, req, fast \\ false),
    do: GenServer.call(s, {:write, sadr, reg, ct, req, fast})

  @doc "SSDOC_SendReadReq: `{:ok, frame}` or `:error`."
  def send_read_req(s, sadr, reg, ct, req), do: GenServer.call(s, {:read, sadr, reg, ct, req})

  @doc "SSDOC_ProcessResponse: `{ok, frames, effects}`."
  def process_response(s, ct, %Frame{} = f), do: GenServer.call(s, {:response, ct, f})

  @doc "SSDOC_BuildRequest: `{free, frames, effects}`."
  def build_request(s, ct, free), do: GenServer.call(s, {:build, ct, free})

  ## GenServer

  @impl true
  def init(opts) do
    n = Keyword.get(opts, :slots, 101)
    slot = Map.merge(serv_slot(), prot_slot())

    {:ok,
     %{
       sod: Keyword.fetch!(opts, :sod),
       owner: Keyword.fetch!(opts, :owner),
       serr: Keyword.get(opts, :serr),
       max_pyld: Keyword.get(opts, :max_pyld, 12),
       slots: :erlang.make_tuple(n, slot)
     }}
  end

  @impl true
  def handle_call(:available?, _from, s), do: {:reply, prot_free(s) != nil, s}

  def handle_call({:write, sadr, reg, ct, req, fast}, _from, s) do
    {reply, s} = write_req(s, sadr, reg, ct, req, fast)
    {:reply, reply, s}
  end

  def handle_call({:read, sadr, reg, ct, req}, _from, s) do
    {reply, s} = read_req(s, sadr, reg, ct, req)
    {:reply, reply, s}
  end

  def handle_call({:response, ct, f}, _from, s) do
    {ok, s, acc} = process_response_(s, ct, f)
    {frames, effects} = split(acc)
    {:reply, {ok, frames, effects}, s}
  end

  def handle_call({:build, ct, free}, _from, s) do
    {free, s, acc} = build(s, ct, free, 0, [])
    {frames, effects} = split(acc)
    {:reply, {free, frames, effects}, s}
  end

  ## Access (SSDOCaccess.c)

  defp write_req(s, sadr, reg, ct, req, fast) do
    pl = req.payload_len

    cond do
      sadr < 1 or sadr > 0x3FF ->
        {:error, error(s, :wr_req_sadr, sadr)}

      Map.get(req, :data) == nil ->
        {:error, error(s, :wr_data_ptr, 0)}

      pl > @max_serv or pl < @min_serv ->
        {:error, error(s, :wr_req_pyldlen, pl)}

      true ->
        case type_len_valid(s, req.type, req.data_len, pl) do
          {:ok, len} ->
            req = %{req | data_len: len, data: pad(req.data, len)}

            if transfer_running?(s, sadr),
              do: {:error, s},
              else: send_req(s, sadr, reg, ct, req, true, fast)

          {:error, s} ->
            {:error, s}
        end
    end
  end

  defp read_req(s, sadr, reg, ct, req) do
    pl = req.payload_len

    cond do
      sadr < 1 or sadr > 0x3FF ->
        {:error, error(s, :rd_req_sadr, sadr)}

      pl > @max_serv or pl < @min_serv ->
        {:error, error(s, :rd_req_pyldlen, pl)}

      true ->
        case type_len_read_valid(s, req.type, req.data_len, pl) do
          :ok ->
            if transfer_running?(s, sadr),
              do: {:error, s},
              else: send_req(s, sadr, reg, ct, req, false, false)

          {:error, s} ->
            {:error, s}
        end
    end
  end

  # TypeLenReadValid: the receive buffer must hold the type, and not be 0.
  defp type_len_read_valid(s, type, len, pl) do
    case type_len_valid(s, type, len, pl) do
      {:ok, tmp} when tmp <= len and len > 0 -> :ok
      {:ok, _} -> {:error, error(s, :rd_data_len, len)}
      err -> err
    end
  end

  # TypeLenValid: fixed types define their length.
  defp type_len_valid(s, type, len, pl) do
    cond do
      type in [:boolean, :uint8, :int8] ->
        {:ok, 1}

      type in [:uint16, :int16] ->
        {:ok, 2}

      type in [:uint32, :int32, :real32] ->
        {:ok, 4}

      type in [:uint64, :int64, :real64] and s.max_pyld >= 12 ->
        if pl >= @hdr + 8, do: {:ok, 8}, else: {:error, error(s, :data_len, 0)}

      type in @strings ->
        {:ok, len}

      true ->
        {:error, error(s, :data_type, type)}
    end
  end

  ## Protocol layer (SSDOCprotocol.c)

  # SSDOC_SendReq
  defp send_req(s, sadr, reg, ct, req, download?, fast) do
    case prot_free(s) do
      nil ->
        {:error, error(s, :no_prot_fsm, 0)}

      n ->
        s = update(s, n, &%{&1 | reg: reg, toggle: false, req: req})

        {ok, s, acc} =
          cond do
            not download? ->
              then_prot(upld_init(s, n, ct, sadr, []), n, :wf_upld_init_resp)

            req.type in @strings and req.data_len > req.payload_len - @hdr ->
              s = update(s, n, &%{&1 | rest: req.data_len})
              then_prot(dwnld_init(s, n, ct, sadr, false, fast, []), n, :wf_dwnld_resp_init_seg)

            true ->
              req = %{req | payload_len: req.data_len + @hdr}
              fast = fast and req.type in @strings
              s = update(s, n, &%{&1 | req: req})
              then_prot(dwnld_init(s, n, ct, sadr, true, fast, []), n, :wf_dwnld_resp_exp)
          end

        case {ok, acc} do
          {true, [{:tx, frame}]} -> {{:ok, frame}, s}
          _ -> {:error, prot_init(s, n)}
        end
    end
  end

  defp then_prot({true, s, acc}, n, state), do: {true, update(s, n, &%{&1 | prot: state}), acc}
  defp then_prot(other, _n, _state), do: other

  # SSDOC_ProcessResponse
  defp process_response_(s, ct, f) do
    case assign(s, f) do
      nil ->
        {false, error(s, :resp_not_assigned, f.id), []}

      n ->
        slot = slot(s, n)

        cond do
          f.tr != 0 ->
            {false, error(s, :resp_tr_field_used, f.tr), []}

          f.ct != slot.hdr.ct ->
            {false, error(s, :resp_sano_diff, (f.ct <<< 16) + slot.hdr.ct), []}

          true ->
            s = put_slot(s, n, %{slot | wait_req: true})
            {ok, s, acc} = prot_process(s, n, ct, f.data, [])
            {ok, if(ok, do: s, else: prot_init(s, n)), acc}
        end
    end
  end

  # SSDOC_ProtocolFsmProcess
  defp prot_process(s, n, ct, data, acc) do
    le = byte_size(data)

    case check_response(s, n, data, le, acc) do
      {:ok, sa} ->
        sa = sa &&& bnot(@toggle) &&& 0xFF
        prot(slot(s, n).prot, s, n, ct, sa, data, le, acc)

      {:error, s, acc} ->
        {true, s, acc}
    end
  end

  defp prot(:wf_req_trans, s, _n, _ct, _sa, _data, _le, acc),
    do: {false, error(s, :prot_fsm_state, 0), acc}

  defp prot(:wf_upld_init_resp, s, n, ct, sa, data, le, acc) do
    slot = slot(s, n)

    cond do
      sa == @upld_init_exp ->
        if le >= @hdr and exp_upload_len_ok?(s, le, slot.req.type) do
          raw = binary_part(data, @hdr, le - @hdr)
          {true, prot_init(s, n), cb(acc, slot, le - @hdr, 0, raw)}
        else
          {false, error(s, :resp_data_len1, le), cb(acc, slot, 0, :len_does_not_match)}
        end

      sa == @upld_init_seg ->
        if le <= slot.req.payload_len and le >= @hdr + @obj_len do
          <<_::binary-size(4), rx::little-32, raw::binary>> = data

          if rx <= slot.req.data_len do
            slot =
              if rx == 0,
                do: %{slot | rest: slot.req.data_len, req: %{slot.req | data_len: 0}},
                else: %{slot | rest: rx}

            upld_resp_seg(put_slot(s, n, slot), n, ct, le, raw, acc)
          else
            {ok, s, acc} = serv_abort(s, n, :len_does_not_match, acc)

            if ok,
              do: {false, error(s, :rx_obj_size, rx), cb(acc, slot, 0, :len_does_not_match)},
              else: {false, s, acc}
          end
        else
          {false, error(s, :resp_data_len2, le), cb(acc, slot, 0, :len_does_not_match)}
        end

      true ->
        abort_resp(s, n, data, le, sa, acc)
    end
  end

  defp prot(:wf_upld_resp_mid_seg, s, n, ct, sa, data, le, acc) do
    slot = slot(s, n)

    cond do
      sa == @upld_seg_mid ->
        if le <= slot.req.payload_len and le > @hdr_seg do
          <<_, raw::binary>> = data
          upld_resp_seg(s, n, ct, le, raw, acc)
        else
          {false, error(s, :resp_data_len3, le), cb(acc, slot, 0, :len_does_not_match)}
        end

      sa == @upld_seg_end and slot.req.data_len == 0 ->
        if le <= slot.req.payload_len and le > @hdr_seg do
          unknown_size_end_seg(s, n, data, acc)
        else
          {false, error(s, :resp_data_len11, le), cb(acc, slot, 0, :len_does_not_match)}
        end

      sa == @upld_seg_end ->
        code = SOD.abort_code(:cmd_id_invalid)
        {false, error(s, :resp_sacmd_inv1, code), cb(acc, slot, 0, code)}

      true ->
        abort_resp(s, n, data, le, sa, acc)
    end
  end

  defp prot(:wf_upld_resp_end_seg, s, n, _ct, sa, data, le, acc) do
    slot = slot(s, n)

    cond do
      sa != @upld_seg_end ->
        abort_resp(s, n, data, le, sa, acc)

      not (le <= slot.req.payload_len and le > @hdr_seg) ->
        {false, error(s, :resp_data_len4, le), cb(acc, slot, 0, :len_does_not_match)}

      slot.req.data_len == 0 ->
        unknown_size_end_seg(s, n, data, acc)

      slot.rest == le - @hdr_seg ->
        <<_, raw::binary>> = data
        up = slot.uploaded + byte_size(raw)
        {true, prot_init(s, n), cb(acc, slot, up, 0, slot.up <> raw)}

      true ->
        {false, error(s, :rest_data_len2, le - @hdr_seg), cb(acc, slot, 0, :len_does_not_match)}
    end
  end

  defp prot(:wf_dwnld_resp_exp, s, n, _ct, sa, data, le, acc) do
    slot = slot(s, n)

    cond do
      sa != @dwnld_init_exp -> abort_resp(s, n, data, le, sa, acc)
      le == @hdr -> {true, prot_init(s, n), cb(acc, slot, slot.req.data_len, 0)}
      true -> {false, error(s, :resp_data_len5, le), cb(acc, slot, 0, :len_does_not_match)}
    end
  end

  defp prot(:wf_dwnld_resp_init_seg, s, n, ct, sa, data, le, acc) do
    slot = slot(s, n)

    cond do
      sa != @dwnld_init_seg -> abort_resp(s, n, data, le, sa, acc)
      le == @hdr -> dwnld_resp_seg(s, n, ct, slot.req.payload_len - (@hdr + @obj_len), acc)
      true -> {false, error(s, :resp_data_len6, le), cb(acc, slot, 0, :len_does_not_match)}
    end
  end

  defp prot(:wf_dwnld_resp_mid_seg, s, n, ct, sa, data, le, acc) do
    slot = slot(s, n)

    cond do
      sa != @dwnld_seg_mid -> abort_resp(s, n, data, le, sa, acc)
      le == @hdr_seg -> dwnld_resp_seg(s, n, ct, slot.req.payload_len - @hdr_seg, acc)
      true -> {false, error(s, :resp_data_len7, le), cb(acc, slot, 0, :len_does_not_match)}
    end
  end

  defp prot(:wf_dwnld_resp_end_seg, s, n, _ct, sa, data, le, acc) do
    slot = slot(s, n)

    cond do
      sa != @dwnld_seg_end -> abort_resp(s, n, data, le, sa, acc)
      le == @hdr_seg -> {true, prot_init(s, n), cb(acc, slot, slot.req.data_len, 0)}
      true -> {false, error(s, :resp_data_len8, le), cb(acc, slot, 0, :len_does_not_match)}
    end
  end

  # checkExpUploadRespLen
  defp exp_upload_len_ok?(s, le, type) do
    case le - @hdr do
      _ when type in @strings -> true
      1 -> type in [:int8, :uint8, :boolean]
      2 -> type in [:int16, :uint16]
      4 -> type in [:int32, :uint32, :real32]
      8 -> s.max_pyld >= 12 and type in [:int64, :uint64, :real64]
      _ -> false
    end
  end

  # checkResponse: toggle bit, and for non-segment responses index and
  # sub-index of the running transfer. Returns `{:ok, sacmd}` or
  # `{:error, s, acc}` after reporting the abort to the caller.
  defp check_response(s, n, data, le, acc) do
    slot = slot(s, n)
    sa = first_byte(data)
    plain = sa &&& bnot(@toggle) &&& 0xFF
    toggle_bad = (sa &&& @toggle) != 0 and not slot.toggle
    cmd_inv = SOD.abort_code(:cmd_id_invalid)

    cond do
      le == @hdr_seg or (le >= @hdr_seg and plain in [@upld_seg_mid, @upld_seg_end]) ->
        if toggle_bad,
          do: {:error, error(s, :resp_tb_wrong, cmd_inv), cb(acc, slot, 0, cmd_inv)},
          else: {:ok, sa}

      le >= @hdr ->
        <<_, idx::little-16, sub, _::binary>> = data
        incomp = SOD.abort_code(:gen_param_incomp)

        cond do
          toggle_bad ->
            {:error, error(s, :resp_tb_wrong, cmd_inv), cb(acc, slot, 0, cmd_inv)}

          idx != slot.req.idx ->
            {:error, error(s, :resp_idx_wrong, incomp), cb(acc, slot, 0, incomp)}

          sub != slot.req.sub ->
            {:error, error(s, :resp_subidx_wrong, incomp), cb(acc, slot, 0, incomp)}

          true ->
            {:ok, sa}
        end

      true ->
        {:error, error(s, :resp_data_len9, le), cb(acc, slot, 0, :len_does_not_match)}
    end
  end

  # processAbortResp: an abort ends the transfer; the slot is free again.
  defp abort_resp(s, n, data, le, sa, acc) do
    slot = slot(s, n)

    cond do
      sa == @abort and le == @hdr + @abort_len ->
        <<_::binary-size(4), code::little-32>> = data
        {true, put_slot(s, n, %{slot | prot: :wf_req_trans}), cb(acc, slot, 0, code)}

      sa == @abort ->
        {false, error(s, :resp_data_len10, le), cb(acc, slot, 0, :len_does_not_match)}

      true ->
        code = SOD.abort_code(:cmd_id_invalid)
        {false, error(s, :resp_sacmd_inv, code), cb(acc, slot, 0, code)}
    end
  end

  # processUpldRespSeg: store the segment, request the next one. The
  # end-segment threshold is the length of the response just received.
  defp upld_resp_seg(s, n, ct, resp_le, raw, acc) do
    slot = slot(s, n)
    len = byte_size(raw)
    toggle = not slot.toggle
    rest = Time.u32(slot.rest - len)

    slot = %{slot | toggle: toggle, up: slot.up <> raw, rest: rest, uploaded: slot.uploaded + len}

    next = if rest <= resp_le - @hdr_seg, do: :wf_upld_resp_end_seg, else: :wf_upld_resp_mid_seg
    sa = if toggle, do: @upld_seg_mid ||| @toggle, else: @upld_seg_mid

    then_prot(upld_seg(put_slot(s, n, slot), n, ct, sa, acc), n, next)
  end

  # processDwnldRespSeg: advance past the segment just acknowledged, send
  # the next (the last one sized to what is left).
  defp dwnld_resp_seg(s, n, ct, sent, acc) do
    slot = slot(s, n)
    toggle = not slot.toggle
    rest = Time.u32(slot.rest - sent)
    slot = %{slot | toggle: toggle, pos: slot.pos + sent, rest: rest}

    {slot, sa, next} =
      if rest <= slot.req.payload_len - @hdr_seg,
        do:
          {%{slot | req: %{slot.req | payload_len: rest + @hdr_seg}}, @dwnld_seg_end,
           :wf_dwnld_resp_end_seg},
        else: {slot, @dwnld_seg_mid, :wf_dwnld_resp_mid_seg}

    sa = if toggle, do: sa ||| @toggle, else: sa
    then_prot(dwnld_seg(put_slot(s, n, slot), n, ct, sa, acc), n, next)
  end

  # processUnknownSizeEndSeg
  defp unknown_size_end_seg(s, n, data, acc) do
    slot = slot(s, n)
    <<_, raw::binary>> = data
    len = byte_size(raw)

    if slot.rest >= len do
      up = slot.uploaded + len
      {true, prot_init(s, n), cb(acc, slot, up, 0, slot.up <> raw)}
    else
      {false, error(s, :rest_data_len, len), cb(acc, slot, 0, :len_does_not_match)}
    end
  end

  # SSDOC_BuildRequest: per busy slot, retransmit or abort on timeout.
  defp build(s, _ct, free, n, acc) when n >= tuple_size(s.slots), do: {free, s, acc}

  defp build(s, ct, free, n, acc) do
    slot = slot(s, n)

    cond do
      slot.wait_req or free == 0 or not Time.timeout?(ct, slot.resp_timeout) ->
        build(s, ct, free, n + 1, acc)

      slot.retries > 0 ->
        :ok = SERR.count_acyc(s.serr, n, :ssdo_retry)
        slot = %{slot | retries: slot.retries - 1, resp_timeout: Time.u32(ct + slot.sod_timeout)}
        build(put_slot(s, n, slot), ct, free - 1, n + 1, [{:tx, req_frame(slot)} | acc])

      true ->
        :ok = SERR.count_acyc(s.serr, n, :ssdo_tout)
        {ok, s, acc} = serv_abort(s, n, :ssdo_time_out, acc)
        free = if ok, do: free - 1, else: free
        acc = cb(acc, slot, @abort_len, :ssdo_time_out)
        s = prot_init(s, n)
        if ok, do: build(s, ct, free, n + 1, acc), else: {free, s, acc}
    end
  end

  ## Service layer (SSDOCservreq.c, SSDOCservice.c, SSDOCservTimer.c)

  # SSDOC_ServiceDwnldInit
  defp dwnld_init(s, n, ct, sadr, exp?, fast, acc) do
    case header(s, n, sadr, if(fast, do: @req_fast, else: @req)) do
      {:ok, slot} ->
        req = slot.req
        buf = put_buf(slot.buf, 1, <<req.idx::little-16, req.sub>>)

        buf =
          if exp? do
            buf
            |> put_buf(0, <<@dwnld_init_exp>>)
            |> put_buf(@hdr, binary_part(req.data, 0, req.payload_len - @hdr))
          else
            raw = req.payload_len - (@hdr + @obj_len)

            buf
            |> put_buf(0, <<@dwnld_init_seg>>)
            |> put_buf(@hdr, <<req.data_len::little-32>>)
            |> put_buf(@hdr + @obj_len, binary_part(req.data, 0, raw))
          end

        serv_req(put_slot(s, n, %{slot | le: req.payload_len, buf: buf}), n, ct, acc)

      :error ->
        {false, s, acc}
    end
  end

  # SSDOC_ServiceDwnldSeg
  defp dwnld_seg(s, n, ct, sa, acc) do
    slot = slot(s, n)
    req = slot.req
    raw = binary_part(req.data, slot.pos, req.payload_len - @hdr_seg)
    buf = slot.buf |> put_buf(0, <<sa>>) |> put_buf(@hdr_seg, raw)
    hdr = %{slot.hdr | ct: inc_ct(slot.hdr.ct)}
    serv_req(put_slot(s, n, %{slot | hdr: hdr, le: req.payload_len, buf: buf}), n, ct, acc)
  end

  # SSDOC_ServiceUpldInit
  defp upld_init(s, n, ct, sadr, acc) do
    case header(s, n, sadr, @req) do
      {:ok, slot} ->
        buf = put_buf(slot.buf, 0, <<@upld_init_exp, slot.req.idx::little-16, slot.req.sub>>)
        serv_req(put_slot(s, n, %{slot | le: @hdr, buf: buf}), n, ct, acc)

      :error ->
        {false, s, acc}
    end
  end

  # SSDOC_ServiceUpldSeg: the request keeps the init request's length.
  defp upld_seg(s, n, ct, sa, acc) do
    slot = slot(s, n)
    hdr = %{slot.hdr | ct: inc_ct(slot.hdr.ct)}
    serv_req(put_slot(s, n, %{slot | hdr: hdr, buf: put_buf(slot.buf, 0, <<sa>>)}), n, ct, acc)
  end

  # SSDOC_ServiceAbort: the last request's header with an abort payload.
  defp serv_abort(s, n, abort, acc) do
    slot = slot(s, n)

    buf =
      slot.buf |> put_buf(0, <<@abort>>) |> put_buf(@hdr, <<SOD.abort_code(abort)::little-32>>)

    slot = %{slot | le: @hdr + @abort_len, buf: buf}
    {true, put_slot(s, n, %{slot | wait_req: true}), [{:tx, req_frame(slot)} | acc]}
  end

  # Request header (SADR and SDN of the SCM, next SANo).
  defp header(s, n, sadr, id) do
    with {:ok, scm} <- sod_get(s, 0x1200, 2),
         {:ok, sdn} <- sod_get(s, 0x1200, 1) do
      slot = slot(s, n)
      hdr = %{slot.hdr | id: id, adr: sadr, sdn: sdn, ct: inc_ct(slot.hdr.ct), tadr: scm, tr: 0}
      {:ok, %{slot | hdr: hdr}}
    end
  end

  # SSDOC_ServiceFsmProcess(k_EVT_REQ): start the timer, send.
  defp serv_req(s, n, ct, acc) do
    slot = slot(s, n)

    if slot.wait_req do
      with {:ok, timeout} <- sod_get(s, 0x1201, 1),
           {:ok, retries} <- sod_get(s, 0x1201, 2) do
        slot = %{
          slot
          | resp_timeout: Time.u32(ct + timeout),
            sod_timeout: timeout,
            retries: retries
        }

        {true, put_slot(s, n, %{slot | wait_req: false}), [{:tx, req_frame(slot)} | acc]}
      else
        _ -> {false, serv_init(s, n), acc}
      end
    else
      {false, s |> serv_init(n) |> error(:serv_fsm_evt_inv2, :req), acc}
    end
  end

  defp req_frame(slot), do: %{slot.hdr | data: binary_part(slot.buf, 0, slot.le)}

  # SSDOC_ServiceResponseAssign
  defp assign(s, f) do
    id = f.id &&& bnot(1) &&& 0xFF

    case sod_get(s, 0x1200, 1) do
      {:ok, sdn} ->
        Enum.find(0..(tuple_size(s.slots) - 1), fn n ->
          slot = slot(s, n)

          not slot.wait_req and f.sdn == sdn and slot.hdr.id == id and slot.hdr.adr == f.tadr and
            slot.hdr.tadr == f.adr
        end)

      :error ->
        nil
    end
  end

  # SSDOC_TransferRunning
  defp transfer_running?(s, sadr) do
    running =
      Enum.any?(0..(tuple_size(s.slots) - 1), fn n ->
        slot = slot(s, n)
        not slot.wait_req and slot.hdr.adr == sadr
      end)

    if running, do: error(s, :transfer_running, sadr)
    running
  end

  ## Slots

  # getProtocolFsmFree
  defp prot_free(s) do
    Enum.find(0..(tuple_size(s.slots) - 1), fn n -> slot(s, n).prot == :wf_req_trans end)
  end

  # protocolFsmInit
  defp prot_init(s, n), do: update(s, n, &Map.merge(&1, prot_slot()))

  # serviceFsmInit
  defp serv_init(s, n), do: update(s, n, &Map.merge(&1, serv_slot()))

  defp prot_slot,
    do: %{
      prot: :wf_req_trans,
      reg: nil,
      req: nil,
      toggle: false,
      rest: 0,
      uploaded: 0,
      up: <<>>,
      pos: 0
    }

  defp serv_slot do
    %{
      wait_req: true,
      hdr: %Frame{id: 0, adr: 0, sdn: 0, ct: 0, tadr: 0, tr: 0},
      le: 0,
      buf: <<0::size(@buf_len)-unit(8)>>,
      resp_timeout: 0,
      sod_timeout: 0,
      retries: 0
    }
  end

  defp slot(s, n), do: elem(s.slots, n)
  defp put_slot(s, n, slot), do: %{s | slots: put_elem(s.slots, n, slot)}
  defp update(s, n, fun), do: put_slot(s, n, fun.(slot(s, n)))

  ## Helpers

  defp cb(acc, slot, len, abort, data \\ nil),
    do: [{:resp, slot.reg, len, SOD.abort_code(abort), data} | acc]

  defp split(acc) do
    acc = Enum.reverse(acc)
    {for({:tx, f} <- acc, do: f), for({:resp, _, _, _, _} = e <- acc, do: e)}
  end

  defp put_buf(buf, off, bin) do
    n = byte_size(bin)
    <<pre::binary-size(off), _::binary-size(n), post::binary>> = buf
    <<pre::binary, bin::binary, post::binary>>
  end

  defp pad(data, len) when byte_size(data) >= len, do: data
  defp pad(data, len), do: data <> :binary.copy(<<0>>, len - byte_size(data))

  defp inc_ct(0xFFFF), do: 1
  defp inc_ct(ct), do: ct + 1

  defp first_byte(<<b, _::binary>>), do: b
  defp first_byte(<<>>), do: 0

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
    send(s.owner, {:opensafety_ssdoc, self(), {:error, code, info}})
    s
  end
end
