defmodule OpenSafety.SPDO.Tx do
  @moduledoc """
  One Tx SPDO: the Time Synchronization Producer state machine
  (`SPDOtxSyncProdSm.c`) as a `gen_statem`, plus the send arbitration and
  frame building of `SPDOtxProdSm.c` in its data.

  ## States

    * `:wait_for_treq` - idle; a received TReq for this SPDO's address
      latches its TR and source address and moves to `:sending_tres`.
    * `:sending_tres` - answer with `no_tres` consecutive TRes, the first
      sent immediately (bypassing the refresh prescale), then back.

  Driven only by `OpenSafety.SPDO` (and by `OpenSafety.SPDO.Rx` for
  TReqs). Every call carries the consecutive time `ct`; nothing here reads
  a clock.

  ## Configuration (`0x1C00..0x1FFE`)

    * `:sadr` - sub 1, address this SPDO is sent from; 0 disables it.
    * `:refresh_prescale` - sub 2, maximum CT between data frames.
    * `:no_tres` - sub 3, TRes per TReq; 0 for a consumer-only device,
      whose Tx SPDO then only carries TReqs.
    * `:len` - mapped payload length in bytes.

  With `:sod` and `:mapping` (from `OpenSafety.SPDO.Config`) the payload
  is read from the mapped objects every time a frame is built
  (`SPDO_TxMappingProcess`), and `put_data/2` is refused.
  """

  @behaviour :gen_statem

  alias OpenSafety.Frame
  alias OpenSafety.SOD.Server, as: SOD
  import OpenSafety.SPDO.Time

  @id_data 0x30
  @id_treq 0x32
  @id_tres 0x34
  @conn_valid 0x01

  ## API (called by OpenSafety.SPDO and OpenSafety.SPDO.Rx)

  def start_link(cfg, sdn), do: :gen_statem.start_link(__MODULE__, {cfg, sdn}, [])

  @doc "SPDO_ResetTxSm for this SPDO (entering Operational)."
  def reset(pid, ct), do: :gen_statem.call(pid, {:reset, ct})

  @doc "Received TReq addressed to this SPDO (ProcessTReq). Returns events."
  def treq(pid, frame), do: :gen_statem.call(pid, {:treq, frame})

  @doc "Build pass 1: send a pending TRes. Returns `{frames, budget}`."
  def build_tres(pid, ct, conn_valid, budget),
    do: :gen_statem.call(pid, {:build_tres, ct, conn_valid, budget})

  @doc "Send a TReq on behalf of an Rx SPDO. Returns `{frames, budget}`."
  def send_treq(pid, ct, tr, tadr, conn_valid, budget),
    do: :gen_statem.call(pid, {:send, ct, :treq, tr, tadr, conn_valid, budget})

  @doc "Build pass 3: data-only SPDO (SPDO_ProdSm). Returns `{frames, budget}`."
  def build_data(pid, ct, conn_valid, budget),
    do: :gen_statem.call(pid, {:build_data, ct, conn_valid, budget})

  @doc "New process data; also forces the next send (SPDO_TxDataChanged)."
  def put_data(pid, bin), do: :gen_statem.call(pid, {:put_data, bin})

  @doc "SPDO_NewData: force the next send (the data is in the mapped objects)."
  def data_changed(pid), do: :gen_statem.call(pid, :data_changed)

  ## gen_statem

  @impl true
  def callback_mode, do: :state_functions

  @impl true
  def init({cfg, sdn}) do
    len = Map.get(cfg, :len, 0)
    no_tres = Map.get(cfg, :no_tres, 1)

    d = %{
      sdn: sdn,
      sadr: cfg.sadr,
      refresh_prescale: cfg.refresh_prescale,
      no_tres_cfg: no_tres,
      payload: :binary.copy(<<0>>, len),
      sod: Map.get(cfg, :sod),
      mapping: Map.get(cfg, :mapping),
      # SPDOtxProdSm t_VARIABLE_FOR_TX_SPDO
      sending: :free,
      timeout_dt: 0,
      new_data: true,
      last_ct_chk: false,
      last_ct: 0,
      # SPDOtxSyncProdSm t_TX_SYNC_PROD_SM
      echo_tr: 0,
      echo_tadr: 0,
      start_block: false,
      no_tres: no_tres
    }

    {:ok, :wait_for_treq, d}
  end

  ## States

  def wait_for_treq({:call, from}, {:treq, f}, d) do
    if d.no_tres == 0 do
      {:next_state, :wait_for_treq, d, [{:reply, from, [{:error, :treq_proc, 0}]}]}
    else
      d = %{d | echo_tr: f.tr, echo_tadr: f.adr, start_block: true}
      {:next_state, :sending_tres, d, [{:reply, from, []}]}
    end
  end

  def wait_for_treq({:call, from}, {:build_tres, _ct, _cv, budget}, d),
    do: {:next_state, :wait_for_treq, d, [{:reply, from, {[], budget}}]}

  def wait_for_treq(type, msg, d), do: common(:wait_for_treq, type, msg, d)

  # A further TReq while answering is ignored without an error.
  def sending_tres({:call, from}, {:treq, _f}, d),
    do: {:next_state, :sending_tres, d, [{:reply, from, []}]}

  def sending_tres({:call, from}, {:build_tres, ct, cv, budget}, d) do
    kind = if d.start_block, do: :tres_immediate, else: :tres
    {frames, budget, d} = send(d, ct, kind, d.echo_tr, d.echo_tadr, cv, budget)

    {state, d} =
      cond do
        frames == [] -> {:sending_tres, d}
        d.no_tres == 1 -> {:wait_for_treq, %{d | start_block: false, no_tres: d.no_tres_cfg}}
        true -> {:sending_tres, %{d | start_block: false, no_tres: d.no_tres - 1}}
      end

    {:next_state, state, d, [{:reply, from, {frames, budget}}]}
  end

  def sending_tres(type, msg, d), do: common(:sending_tres, type, msg, d)

  # Calls valid in every state.
  defp common(state, {:call, from}, {:send, ct, kind, tr, tadr, cv, budget}, d) do
    {frames, budget, d} = send(d, ct, kind, tr, tadr, cv, budget)
    {:next_state, state, d, [{:reply, from, {frames, budget}}]}
  end

  defp common(state, {:call, from}, {:build_data, ct, cv, budget}, d) do
    {frames, budget, d} =
      if d.sadr != 0, do: send(d, ct, :data_only, 0, 0, cv, budget), else: {[], budget, d}

    {:next_state, state, d, [{:reply, from, {frames, budget}}]}
  end

  defp common(_state, {:call, from}, {:reset, ct}, d) do
    d = %{
      d
      | sending: :free,
        timeout_dt: ct,
        new_data: true,
        last_ct_chk: false,
        last_ct: 0,
        echo_tr: 0,
        echo_tadr: 0,
        start_block: false,
        no_tres: d.no_tres_cfg
    }

    {:next_state, :wait_for_treq, d, [{:reply, from, :ok}]}
  end

  defp common(state, {:call, from}, :data_changed, d),
    do: {:next_state, state, %{d | new_data: true}, [{:reply, from, :ok}]}

  defp common(state, {:call, from}, {:put_data, _bin}, %{mapping: m} = d) when is_list(m),
    do: {:next_state, state, d, [{:reply, from, {:error, :sod_mapped}}]}

  defp common(state, {:call, from}, {:put_data, bin}, d) do
    if byte_size(bin) == byte_size(d.payload) do
      {:next_state, state, %{d | payload: bin, new_data: true}, [{:reply, from, :ok}]}
    else
      {:next_state, state, d, [{:reply, from, {:error, :length}}]}
    end
  end

  ## SPDO_SendTxSpdo

  # One frame per CT per SPDO, at most `budget` frames per build. TRes
  # immediate ignores the refresh prescale; everything else goes out only
  # when the prescale has elapsed or new data is pending. The request type
  # stays latched until the data-only call of the same build pass frees it.
  defp send(d, ct, kind, tr, tadr, cv, budget) do
    {frames, budget, d} =
      if d.sending == :free and budget > 0 and (not d.last_ct_chk or d.last_ct != ct) and
           (kind == :tres_immediate or timeout?(ct, d.timeout_dt) or d.new_data) do
        frame = %Frame{
          id: id(kind, cv),
          adr: d.sadr,
          sdn: d.sdn,
          ct: u16(ct),
          tr: tr,
          tadr: tadr,
          data: payload(d)
        }

        timeout_dt =
          if timeout?(ct, d.timeout_dt), do: u32(ct + d.refresh_prescale), else: d.timeout_dt

        d = %{
          d
          | sending: kind,
            last_ct: ct,
            new_data: false,
            last_ct_chk: true,
            timeout_dt: timeout_dt
        }

        {[frame], budget - 1, d}
      else
        {[], budget, d}
      end

    d = if kind == :data_only, do: %{d | sending: :free}, else: d
    {frames, budget, d}
  end

  # SPDO_TxMappingProcess: the mapped objects' current bytes, in order.
  defp payload(%{mapping: m, sod: sod}) when is_list(m) do
    for %{index: i, sub: s, len: n} <- m, into: <<>> do
      {:ok, b} = SOD.peek(sod, {i, s}, n)
      b
    end
  end

  defp payload(d), do: d.payload

  defp id(kind, cv) do
    base =
      case kind do
        :data_only -> @id_data
        :treq -> @id_treq
        _tres -> @id_tres
      end

    if cv, do: Bitwise.bor(base, @conn_valid), else: base
  end
end
