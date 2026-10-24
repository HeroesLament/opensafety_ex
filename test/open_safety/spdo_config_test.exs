defmodule OpenSafety.SPDOConfigTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias OpenSafety.{Node, SPDO}
  alias OpenSafety.SOD.Server, as: SOD
  alias OpenSafety.SPDO.Config

  @udid <<0x00, 0x60, 0x65, 0x01, 0x02, 0x03>>
  @delay 2
  @pen_offset 1000

  ## Object dictionaries

  defp obj(i, s, type, len, attr, default \\ 0) do
    o = %{index: i, sub: s, type: type, len: len, attr: attr, default: default}
    if :bef_wr in attr, do: Map.put(o, :callback, cb(i)), else: o
  end

  defp cb(i) when i >= 0xC000, do: Config.mapping_callback(:tx)
  defp cb(_i), do: Config.mapping_callback(:rx)

  defp entry(i, s, bits), do: i <<< 16 ||| s <<< 8 ||| bits

  defp sdn_objs do
    [obj(0x1200, 1, :uint16, 2, [:rw], 1), obj(0x1200, 4, :octet_string, 6, [:rw], @udid)]
  end

  defp tx_objs(n, sadr, prescale, no_tres, entries, attr \\ [:rw]) do
    [
      obj(0x1C00 + n, 0, :uint8, 1, [:ro], 3),
      obj(0x1C00 + n, 1, :uint16, 2, attr, sadr),
      obj(0x1C00 + n, 2, :uint16, 2, [:rw], prescale),
      obj(0x1C00 + n, 3, :uint8, 1, [:rw], no_tres)
    ] ++ mapp_objs(0xC000 + n, entries)
  end

  defp rx_objs(n, sadr, tx_no, entries) do
    vals = [sadr, 50, 1, 20, 1000, 1, 10, 1, 10, 1, 100, tx_no]

    comm =
      vals
      |> Enum.with_index(1)
      |> Enum.map(fn
        {v, 1} -> obj(0x1400 + n, 1, :uint16, 2, [:rw], v)
        {v, 3} -> obj(0x1400 + n, 3, :uint8, 1, [:rw], v)
        {v, 12} -> obj(0x1400 + n, 12, :uint16, 2, [:rw], v)
        {v, s} -> obj(0x1400 + n, s, :uint32, 4, [:rw], v)
      end)

    [obj(0x1400 + n, 0, :uint8, 1, [:ro], 12) | comm] ++ mapp_objs(0x1800 + n, entries)
  end

  defp mapp_objs(mapp, entries) do
    [obj(mapp, 0, :uint8, 1, [:rw, :bef_wr], length(entries))] ++
      for s <- 1..max(length(entries), 1)//1 do
        obj(mapp, s, :uint32, 4, [:rw, :bef_wr], Enum.at(entries, s - 1, 0))
      end
  end

  # Producer, SADR 2: 0x6000/1 (u16) and 0x6000/2 (u8).
  defp pen_objs do
    sdn_objs() ++
      tx_objs(0, 2, 5, 1, [entry(0x6000, 1, 16), entry(0x6000, 2, 8)]) ++
      [
        obj(0x6000, 1, :uint16, 2, [:ro, :pdo_map]),
        obj(0x6000, 2, :uint8, 1, [:ro, :pdo_map])
      ]
  end

  # Consumer, SADR 1, TReqs on its Tx SPDO 1: 0x6200/1 (u16, default
  # 0x1111) and one dummy byte.
  defp ctl_objs do
    sdn_objs() ++
      tx_objs(0, 1, 10, 0, []) ++
      rx_objs(0, 2, 1, [entry(0x6200, 1, 16), entry(1, 0, 8)]) ++
      [obj(0x6200, 1, :uint16, 2, [:wo, :pdo_map], 0x1111)]
  end

  defp start(objects) do
    {:ok, sod} = SOD.start_link(objects)
    {SPDO.start_link(config: :sod, sod: sod), sod}
  end

  defp start!(objects) do
    {{:ok, spdo}, sod} = start(objects)
    {spdo, sod}
  end

  defp start_error(objects) do
    Process.flag(:trap_exit, true)
    {{:error, reason}, _sod} = start(objects)
    reason
  end

  defp events(pid) do
    receive do
      {:opensafety_spdo, ^pid, no, ev} -> [{no, ev} | events(pid)]
    after
      0 -> []
    end
  end

  defp run(ctl, pen, from, to, in_flight \\ [], silent \\ nil) do
    Enum.reduce(from..to, in_flight, fn ct, flight ->
      {due, flight} = Enum.split_with(flight, fn {at, _, _} -> at == ct end)

      Enum.each(due, fn
        {_, :to_ctl, bin} -> :ok = SPDO.process(ctl, ct, bin)
        {_, :to_pen, bin} -> :ok = SPDO.process(pen, ct + @pen_offset, bin)
      end)

      to_pen = SPDO.build(ctl, ct)
      to_ctl = if silent && ct >= silent, do: [], else: SPDO.build(pen, ct + @pen_offset)
      :ok = SPDO.check_timeout(ctl, ct)

      flight ++
        Enum.map(to_pen, &{ct + @delay, :to_pen, &1}) ++
        Enum.map(to_ctl, &{ct + @delay, :to_ctl, &1})
    end)
  end

  defp pair do
    {ctl, ctl_sod} = start!(ctl_objs())
    {pen, pen_sod} = start!(pen_objs())
    assert :ok = SPDO.activate_mapping(ctl)
    assert :ok = SPDO.activate_mapping(pen)
    :ok = SPDO.set_to_op(ctl, 0)
    :ok = SPDO.set_to_op(pen, @pen_offset)
    %{ctl: ctl, pen: pen, ctl_sod: ctl_sod, pen_sod: pen_sod}
  end

  ## Mapped process data

  test "Tx payload read from the SOD, Rx payload written into it" do
    %{ctl: ctl, pen: pen, ctl_sod: ctl_sod, pen_sod: pen_sod} = pair()

    :ok = SOD.poke(pen_sod, {0x6000, 1}, <<0xCD, 0xAB>>)
    :ok = SOD.poke(pen_sod, {0x6000, 2}, <<0x7E>>)
    assert :ok = SPDO.data_changed(pen, 1)
    assert {:error, :sod_mapped} = SPDO.put_data(pen, 1, <<1, 2, 3>>)

    run(ctl, pen, 0, 40)

    assert {1, {:data, <<0xCD, 0xAB, 0x7E>>}} in events(ctl)
    assert {:ok, <<0xCD, 0xAB>>} = SOD.peek(ctl_sod, {0x6200, 1}, 2)

    # Data frames carry the connection-valid bit; the consumer follows it.
    assert {1, %{1 => 0}} = SPDO.conn_valid(ctl)
  end

  test "safe state puts the mapped Rx objects back to their defaults" do
    %{ctl: ctl, pen: pen, ctl_sod: ctl_sod, pen_sod: pen_sod} = pair()
    :ok = SOD.poke(pen_sod, {0x6000, 1}, <<0x22, 0x33>>)
    :ok = SPDO.data_changed(pen, 1)

    flight = run(ctl, pen, 0, 40)
    assert {:ok, <<0x22, 0x33>>} = SOD.peek(ctl_sod, {0x6200, 1}, 2)

    run(ctl, pen, 41, 120, flight, 41)
    assert {:ok, <<0x11, 0x11>>} = SOD.peek(ctl_sod, {0x6200, 1}, 2)
  end

  test "leaving operational clears the connection-valid bits" do
    %{ctl: ctl, pen: pen} = pair()
    run(ctl, pen, 0, 40)
    assert {1, _} = SPDO.conn_valid(ctl)
    :ok = SPDO.set_to_pre_op(ctl)
    assert {0, _} = SPDO.conn_valid(ctl)
  end

  ## SPDO_InitAll errors

  test "at least one Tx SPDO" do
    assert {:spdo_init, :man_tx_spdo, 0} = start_error(sdn_objs())
  end

  test "SPDOs numbered without gaps" do
    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ tx_objs(2, 3, 10, 0, [])
    assert {:spdo_init, :tx_spdo_gap, 0x1C02} = start_error(objs)
  end

  test "a mapping needs communication parameters" do
    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ mapp_objs(0xC001, [])
    assert {:spdo_init, :no_tx_comm_para, 0x1C01_C001} = start_error(objs)
  end

  test "communication parameters without a before-read callback" do
    objs =
      sdn_objs() ++
        tx_objs(0, 1, 10, 0, [], [:rw, :bef_rd])

    objs = Enum.map(objs, &if(:bef_rd in &1.attr, do: Map.put(&1, :callback, cb(0)), else: &1))
    assert {:spdo_init, :bef_rd_tx, 0x1C00_0001} = start_error(objs)
  end

  test "mapped objects must be mappable in the SPDO's direction" do
    objs =
      sdn_objs() ++
        tx_objs(0, 1, 10, 0, [entry(0x6000, 1, 16)]) ++
        [obj(0x6000, 1, :uint16, 2, [:wo, :pdo_map])]

    assert {:spdo_init, :tx_map_obj, :obj_not_mappable} = start_error(objs)

    # Wrong length.
    objs =
      sdn_objs() ++
        tx_objs(0, 1, 10, 0, [entry(0x6000, 1, 8)]) ++
        [obj(0x6000, 1, :uint16, 2, [:ro, :pdo_map])]

    assert {:spdo_init, :tx_map_obj, :obj_not_mappable} = start_error(objs)

    # Dummies are for Rx SPDOs only.
    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, [entry(2, 0, 8)])
    assert {:spdo_init, :tx_map_obj, :obj_not_mappable} = start_error(objs)
  end

  test "mapping entries need the before-write callback" do
    objs =
      sdn_objs() ++
        tx_objs(0, 1, 10, 0, []) ++
        [obj(0xC001, 0, :uint8, 1, [:rw])] ++
        (tx_objs(1, 2, 10, 0, []) |> Enum.reject(&(&1.index == 0xC001)))

    assert {:spdo_init, :bef_wr_tx_sub_0, 0xC001} = start_error(objs)
  end

  test "the mapping callback refuses entries beyond the maximum" do
    f = Config.mapping_callback(:rx)
    assert :ok = f.(:before_write, %{index: 0x1800, sub: 0}, 0, 0, 0)
    assert :ok = f.(:before_write, %{index: 0x1800, sub: 16}, 0, 0, 0)
    assert {:abort, :local_control} = f.(:before_write, %{index: 0x1800, sub: 17}, 0, 0, 0)
    assert {:abort, :local_control} = f.(:before_write, %{index: 0x1800 + 100, sub: 1}, 0, 0, 0)
  end

  ## Activation errors (SPDO_ActivateTxSpdoMapping / Rx)

  defp activation_error(objs) do
    {spdo, _sod} = start!(objs)
    result = SPDO.activate_mapping(spdo)
    {result, Enum.find_value(events(spdo), fn {nil, {:error, c, i}} -> {c, i} end)}
  end

  test "Tx SPDO addresses unique" do
    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ tx_objs(1, 1, 10, 0, [])
    assert {{:error, :tx}, {:tadr, 1}} = activation_error(objs)
  end

  test "an Rx SPDO address must not be one of ours, nor used twice" do
    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ rx_objs(0, 1, 0, [])
    assert {{:error, :rx}, {:sadr, 0}} = activation_error(objs)

    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ rx_objs(0, 2, 1, []) ++ rx_objs(1, 2, 0, [])
    assert {{:error, :rx}, {:sadr, 1}} = activation_error(objs)
  end

  test "an Rx SPDO synchronizes over an active Tx SPDO of its own" do
    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ rx_objs(0, 2, 3, [])
    assert {{:error, :rx}, {:tx_spdo_num_2, 2}} = activation_error(objs)

    objs =
      sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ tx_objs(1, 0, 10, 0, []) ++ rx_objs(0, 2, 2, [])

    assert {{:error, :rx}, {:tx_spdo_num_1, 1}} = activation_error(objs)

    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ rx_objs(0, 2, 0, [])
    assert {{:error, :rx}, {:tx_spdo_num_3, -1}} = activation_error(objs)
  end

  test "one Rx SPDO per Tx SPDO" do
    objs = sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ rx_objs(0, 2, 1, []) ++ rx_objs(1, 3, 1, [])
    assert {{:error, :rx}, {:tx_no_rx_conn_1, 0}} = activation_error(objs)
  end

  test "every counted mapping entry mapped" do
    objs =
      (sdn_objs() ++ tx_objs(0, 1, 10, 0, []))
      |> Enum.map(fn
        %{index: 0xC000, sub: 0} = o -> %{o | default: 1}
        o -> o
      end)

    assert {{:error, :tx}, {:tx_obj_mapp_1, 1}} = activation_error(objs)
  end

  test "parameters are read again at activation" do
    {spdo, sod} = start!(sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ tx_objs(1, 2, 10, 0, []))
    assert :ok = SPDO.activate_mapping(spdo)
    :ok = SOD.put(sod, 0x1C01, 1, 1)
    assert {:error, :tx} = SPDO.activate_mapping(spdo)
  end

  ## SPDO_TxDataChanged

  test "data_changed checks the SPDO number" do
    {spdo, _} = start!(sdn_objs() ++ tx_objs(0, 1, 10, 0, []) ++ tx_objs(1, 0, 10, 0, []))
    assert {:error, :tx_spdo_num_4} = SPDO.data_changed(spdo, 0)
    assert {:error, :tx_spdo_num_4} = SPDO.data_changed(spdo, 101)
    assert {:error, :tx_spdo_num_2} = SPDO.data_changed(spdo, 3)
    assert {:error, :tx_spdo_num_1} = SPDO.data_changed(spdo, 2)
    assert :ok = SPDO.data_changed(spdo, 1)
  end

  ## SPDO_BuildTxSpdoIx

  test "build_one sends at most one frame, for processed Tx SPDOs only" do
    %{ctl: ctl, pen: pen} = pair()

    # The consumer's TReq goes out through its Tx SPDO 1.
    assert {1, [_treq]} = SPDO.build_one(ctl, 0, 1)
    assert {0, []} = SPDO.build_one(ctl, 0, 1)

    assert {0, []} = SPDO.build_one(ctl, 0, 2)
    assert [{nil, {:error, :free_frame_ptr_1, 0}}] = events(ctl)

    # The producer's data frame.
    assert {1, [_data]} = SPDO.build_one(pen, @pen_offset, 1)
  end

  ## SDN_Init

  test "the node needs a readable SDN object" do
    Process.flag(:trap_exit, true)

    objs = Enum.reject(pen_objs(), &(&1.index == 0x1200 and &1.sub == 1))
    assert {:error, {:sdn, :attr_inv, :sub_idx_does_not_exist}} = Node.start_link(objects: objs)

    objs =
      Enum.map(pen_objs(), fn
        %{index: 0x1200, sub: 1} = o -> %{o | attr: [:rw, :bef_rd]} |> Map.put(:callback, cb(0))
        o -> o
      end)

    assert {:error, {:sdn, :attr_inv, 0x1200_0100}} = Node.start_link(objects: objs)
  end

  test "a node with its SPDOs configured from the SOD" do
    {:ok, node} = Node.start_link(objects: pen_objs(), spdo_config: :sod)
    assert {:error, :sod_mapped} = Node.put_data(node, 1, <<0, 0, 0>>)
    assert :ok = Node.data_changed(node, 1)
    assert {0, %{}} = Node.conn_valid(node)
  end
end
