defmodule OpenSafety.SPDO.Config do
  @moduledoc """
  SPDO configuration from the object dictionary (`SPDOinit.c`, the
  comm-parameter setup of `SPDOtxProdSm.c` / `SPDOrxSyncConsSm.c`, and the
  mapping code shared by `SPDOtxmapp.c` / `SPDOrxmapp.c`,
  `SPDOmappcom.cin`).

  ## Objects

  Tx SPDO `n` (0-based): communication 0x1C00+n (/1 SADR u16, /2 refresh
  prescale u16, /3 number of TRes u8), mapping 0xC000+n. Rx SPDO `n`:
  communication 0x1400+n (/1 SADR, /2 SCT, /3 number of consecutive TReq,
  /4 time delay TReq, /5 time delay sync, /6 /7 min/max TSync propagation
  delay, /8 /9 min/max SPDO propagation delay, /10 best case TRes delay,
  /11 time request cycle, /12 Tx SPDO number), mapping 0x1800+n.

  Mapping sub 0 is the number of entries, subs 1..n are entries
  `index << 16 | sub << 8 | bits`; 0 is an unused entry. Rx SPDOs may map
  the dummy indices 1..7 (8, 8, 16, 32, 8, 16, 32 bits) to skip payload.
  Both mapping sub 0 and every entry must carry `:bef_wr` (the C installs
  `SPDO_SOD_*MappPara_CLBK` there), comm parameters must not carry
  `:bef_rd`. Mapped objects need `:pdo_map`, `:ro` (Tx) or `:wo` (Rx),
  and a length matching the entry unless `:no_len_chk`.

  ## Deviation

  The C keeps pointers to the comm parameters and re-validates a mapping
  entry in the before-write callback when it is written. Here
  `OpenSafety.SPDO` re-reads both from the SOD when the mapping is
  activated (SNMT SET TO OP), which is when the C first relies on them;
  `mapping_callback/1` is the callback to give the mapping objects, and
  does the checks that need no other object.
  """

  import Bitwise

  alias OpenSafety.SOD.Server, as: SOD

  @tx_comm 0x1C00
  @tx_comm_end 0x1FFE
  @tx_mapp 0xC000
  @rx_comm 0x1400
  @rx_comm_end 0x17FE
  @rx_mapp 0x1800

  # EPLScfg.h (contrib)
  @max_tx 100
  @max_rx 100
  @max_tx_entries 32
  @max_rx_entries 16
  @max_len 128

  @tx_subs [sadr: {1, :u16}, refresh_prescale: {2, :u16}, no_tres: {3, :u8}]

  @rx_subs [
    sadr: 1,
    sct: 2,
    no_consecutive_treq: 3,
    time_delay_treq: 4,
    time_delay_sync: 5,
    min_tsync_prop_delay: 6,
    max_tsync_prop_delay: 7,
    min_spdo_prop_delay: 8,
    max_spdo_prop_delay: 9,
    best_case_tres_delay: 10,
    time_request_cycle: 11,
    tx_spdo_no: 12
  ]

  # ab_dummyIdxToLen (bits), dummy index 1..7
  @dummy_bits {8, 8, 16, 32, 8, 16, 32}

  def max_tx, do: @max_tx
  def max_rx, do: @max_rx

  @doc """
  SPDO_InitAll: every Tx and Rx SPDO defined in the SOD, in order, with
  its communication parameters and mapping entries. `{:ok, %{tx: [cfg],
  rx: [cfg]}}` or `{:error, code, info}`; at least one Tx SPDO is
  mandatory.
  """
  def init(sod) do
    with {:ok, tx} <- scan(sod, :tx, @tx_comm, @tx_mapp, 0, false, []),
         :ok <- if(tx == [], do: {:error, :man_tx_spdo, 0}, else: :ok),
         {:ok, rx} <- scan(sod, :rx, @rx_comm, @rx_mapp, 0, false, []) do
      {:ok, %{tx: tx, rx: rx}}
    end
  end

  # InitTxSpdo / InitRxSpdo: SPDOs are numbered without gaps; a mapping
  # without communication parameters is an error.
  defp scan(_sod, dir, comm, _mapp, _n, _gap, acc)
       when (dir == :tx and comm > @tx_comm_end) or (dir == :rx and comm > @rx_comm_end),
       do: {:ok, Enum.reverse(acc)}

  defp scan(sod, dir, comm, mapp, n, gap, acc) do
    case SOD.attr_get(sod, comm, 0) do
      {:ok, _, _} when gap ->
        {:error, gap_code(dir), comm}

      {:ok, _, _} ->
        with {:ok, cfg} <- spdo_init(sod, dir, n, comm, mapp) do
          scan(sod, dir, comm + 1, mapp + 1, n + 1, gap, [cfg | acc])
        end

      {:error, _, abort} when abort in [:obj_does_not_exist, :sub_idx_does_not_exist] ->
        case SOD.attr_get(sod, mapp, 0) do
          {:ok, _, _} ->
            {:error, no_comm_code(dir), comm <<< 16 ||| mapp}

          {:error, _, abort} when abort in [:obj_does_not_exist, :sub_idx_does_not_exist] ->
            scan(sod, dir, comm + 1, mapp + 1, n + 1, true, acc)

          {:error, code, abort} ->
            {:error, code, abort}
        end

      {:error, code, abort} ->
        {:error, code, abort}
    end
  end

  defp gap_code(:tx), do: :tx_spdo_gap
  defp gap_code(:rx), do: :rx_spdo_gap
  defp no_comm_code(:tx), do: :no_tx_comm_para
  defp no_comm_code(:rx), do: :no_rx_comm_para

  # TxMappCommInit / RxMappCommInit
  defp spdo_init(_sod, :tx, n, comm, mapp) when n >= @max_tx,
    do: {:error, :no_tx_spdos, comm <<< 16 ||| mapp}

  defp spdo_init(_sod, :rx, n, comm, mapp) when n >= @max_rx,
    do: {:error, :no_rx_spdos, comm <<< 16 ||| mapp}

  defp spdo_init(sod, dir, _n, comm, mapp) do
    with {:ok, cfg} <- comm_para(sod, dir, comm),
         {:ok, mapping} <- mapping(sod, dir, mapp) do
      {:ok, Map.merge(cfg, %{comm: comm, mapp: mapp, mapping: mapping, len: 0})}
    end
  end

  @doc "Communication parameters of the SPDO at `comm` (SPDO_SetPtrTo*CommPara)."
  def comm_para(sod, :tx, comm) do
    Enum.reduce_while(@tx_subs, {:ok, %{}}, fn {key, {sub, _}}, {:ok, acc} ->
      case comm_value(sod, comm, sub, :bef_rd_tx) do
        {:ok, v} -> {:cont, {:ok, Map.put(acc, key, v)}}
        error -> {:halt, error}
      end
    end)
  end

  def comm_para(sod, :rx, comm) do
    Enum.reduce_while(@rx_subs, {:ok, %{}}, fn {key, sub}, {:ok, acc} ->
      case comm_value(sod, comm, sub, :bef_rd_rx) do
        {:ok, v} -> {:cont, {:ok, Map.put(acc, key, v)}}
        error -> {:halt, error}
      end
    end)
  end

  # SetPtrToTxCommPara / SetPtrToRxCommPara
  defp comm_value(sod, comm, sub, bef_rd_code) do
    case SOD.attr_get(sod, comm, sub) do
      {:ok, _h, attr} ->
        if :bef_rd in attr.attr do
          {:error, bef_rd_code, comm <<< 16 ||| sub}
        else
          SOD.get(sod, comm, sub)
        end

      error ->
        error
    end
  end

  @doc """
  The mapping at `mapp` (sub 0 and SPDO_SetMapp): a list of entries, each
  `%{index:, sub:, type:, len:}` (len in bytes), `%{dummy: true, len:}`, or
  `nil` for an unused entry.
  """
  def mapping(sod, dir, mapp) do
    with {:ok, n} <- mapping_count(sod, dir, mapp) do
      max = if dir == :tx, do: @max_tx_entries, else: @max_rx_entries

      cond do
        n == 0 -> {:ok, []}
        n > max -> {:error, err(dir, :mapp_entry_1), mapp}
        true -> entries(sod, dir, mapp, 1, n, [])
      end
    end
  end

  defp mapping_count(sod, dir, mapp) do
    case SOD.attr_get(sod, mapp, 0) do
      {:ok, _h, attr} ->
        if :bef_wr in attr.attr,
          do: SOD.get(sod, mapp, 0),
          else: {:error, err(dir, :bef_wr_sub_0), mapp}

      error ->
        error
    end
  end

  defp entries(_sod, _dir, _mapp, sub, n, acc) when sub > n, do: {:ok, Enum.reverse(acc)}

  defp entries(sod, dir, mapp, sub, n, acc) do
    case SOD.attr_get(sod, mapp, sub) do
      {:ok, _h, attr} ->
        if :bef_wr in attr.attr do
          with {:ok, value} <- SOD.get(sod, mapp, sub),
               {:ok, entry} <- mapped_obj(sod, dir, value) do
            entries(sod, dir, mapp, sub + 1, n, [entry | acc])
          end
        else
          {:error, err(dir, :bef_wr_sub_x), mapp <<< 16 ||| sub}
        end

      error ->
        error
    end
  end

  @doc "ConfigNewMappedObj: one mapping entry against the SOD."
  def mapped_obj(_sod, _dir, 0), do: {:ok, nil}

  def mapped_obj(sod, dir, entry) do
    index = entry >>> 16
    sub = entry >>> 8 &&& 0xFF
    bits = entry &&& 0xFF
    not_mappable = {:error, err(dir, :map_obj), :obj_not_mappable}

    cond do
      index >= 1 and index <= 7 ->
        if dir == :rx and bits == elem(@dummy_bits, index - 1),
          do: {:ok, %{dummy: true, len: div(bits, 8)}},
          else: not_mappable

      true ->
        case SOD.attr_get(sod, index, sub) do
          {:ok, h, attr} ->
            access = if dir == :tx, do: :ro, else: :wo

            len_ok = :no_len_chk in attr.attr or bits == attr.len * 8

            if len_ok and :pdo_map in attr.attr and access in attr.attr do
              case SOD.read(sod, h) do
                {:ok, _} -> {:ok, %{index: index, sub: sub, type: attr.type, len: div(bits, 8)}}
                {:error, :clbk_abort_br, _} -> not_mappable
                {:error, code, abort} -> {:error, code, abort}
              end
            else
              not_mappable
            end

          {:error, _, _} ->
            not_mappable
        end
    end
  end

  @doc """
  SPDO_MappActivate: every entry up to the count mapped, total length within
  `SPDO_cfg_MAX_LEN_OF_*_SPDO`. `{:ok, len}` or `{:error, code, info}`
  (`info` as the C: the SPDO index, or index << 16 | sub).
  """
  def activate(dir, idx, mapping) do
    max = if dir == :tx, do: @max_tx_entries, else: @max_rx_entries

    if length(mapping) > max do
      {:error, err(dir, :mapp_entry_3), idx}
    else
      mapping
      |> Enum.with_index(1)
      |> Enum.reduce_while({:ok, 0}, fn
        {nil, sub}, _ ->
          {:halt, {:error, err(dir, :obj_mapp_1), idx <<< 16 ||| sub}}

        {%{len: n}, _sub}, {:ok, len} when len + n > @max_len ->
          {:halt, {:error, err(dir, :too_long), idx}}

        {%{len: n}, _sub}, {:ok, len} ->
          {:cont, {:ok, len + n}}
      end)
    end
  end

  @doc """
  The before-write callback for mapping objects (SPDO_SOD_*MappPara_CLBK),
  for `:tx` or `:rx`: sub 0 is always accepted; an entry beyond the
  maximum number of entries, or of an SPDO beyond the maximum, is refused
  with `:local_control`. The entry itself is checked when the mapping is
  activated.
  """
  def mapping_callback(dir) do
    {start, max_spdo, max_entries} =
      if dir == :tx,
        do: {@tx_mapp, @max_tx, @max_tx_entries},
        else: {@rx_mapp, @max_rx, @max_rx_entries}

    fn
      :before_write, %{index: i, sub: s}, _data, _off, _size ->
        cond do
          i - start >= max_spdo -> {:abort, :local_control}
          s == 0 -> :ok
          s <= max_entries -> :ok
          true -> {:abort, :local_control}
        end

      _service, _o, _data, _off, _size ->
        :ok
    end
  end

  # SPDO_k_ERR_* names for the shared mapping code.
  defp err(:tx, :mapp_entry_1), do: :tx_mapp_entry_1
  defp err(:rx, :mapp_entry_1), do: :rx_mapp_entry_1
  defp err(:tx, :bef_wr_sub_0), do: :bef_wr_tx_sub_0
  defp err(:rx, :bef_wr_sub_0), do: :bef_wr_rx_sub_0
  defp err(:tx, :bef_wr_sub_x), do: :bef_wr_tx_sub_x
  defp err(:rx, :bef_wr_sub_x), do: :bef_wr_rx_sub_x
  defp err(:tx, :map_obj), do: :tx_map_obj
  defp err(:rx, :map_obj), do: :rx_map_obj
  defp err(:tx, :obj_mapp_1), do: :tx_obj_mapp_1
  defp err(:rx, :obj_mapp_1), do: :rx_obj_mapp_1
  defp err(:tx, :too_long), do: :tx_too_long
  defp err(:rx, :too_long), do: :rx_too_long
  defp err(:tx, :mapp_entry_3), do: :tx_mapp_entry_3
  defp err(:rx, :mapp_entry_3), do: :rx_mapp_entry_3
end
