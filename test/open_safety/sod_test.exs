defmodule OpenSafety.SODTest do
  use ExUnit.Case, async: true

  alias OpenSafety.SOD

  defp od(extra \\ []) do
    [
      %{index: 0x1000, sub: 0, type: :uint32, len: 4, attr: [:ro_const], default: 0x1234},
      %{index: 0x1400, sub: 1, type: :uint16, len: 2, attr: [:rw], default: 2, range: {1, 1023}},
      %{index: 0x1400, sub: 2, type: :uint16, len: 2, attr: [:ro], default: 100},
      %{index: 0x1C00, sub: 1, type: :boolean, len: 1, attr: [:rw]},
      %{index: 0x2000, sub: 0, type: :visible_string, len: 8, attr: [:rw], default: "ab"},
      %{index: 0x2001, sub: 0, type: :domain, len: 16, attr: [:rw], act_len: 4}
    ] ++ extra
  end

  defp new!(objs \\ od()) do
    {:ok, sod} = SOD.new(objs)
    sod
  end

  describe "new/1 (SOD_Check, SetDefaultValues)" do
    test "defaults applied, zero without a default" do
      sod = new!()
      assert SOD.get(sod, 0x1000, 0) == {:ok, 0x1234}
      assert SOD.get(sod, 0x1400, 1) == {:ok, 2}
      assert SOD.get(sod, 0x1C00, 1) == {:ok, 0}
      assert SOD.read(sod, {0x2000, 0}) == {:ok, "ab" <> <<0::48>>}
    end

    test "empty dictionary" do
      assert SOD.new([]) == {:error, :od_is_empty, :general_error}
    end

    test "duplicate entry" do
      dup = %{index: 0x1400, sub: 1, type: :uint16, len: 2, attr: [:rw]}
      assert SOD.new(od([dup])) == {:error, :sod_not_sorted_2, {0x1400, 1}}
    end

    test "type length checks" do
      bad = %{index: 0x3000, sub: 0, type: :uint16, len: 4, attr: [:rw]}
      assert SOD.new([bad]) == {:error, :type_len_2, {0x3000, 0}}
      empty = %{index: 0x3000, sub: 0, type: :domain, len: 0, attr: [:rw]}
      assert SOD.new([empty]) == {:error, :type_len_5, {0x3000, 0}}
    end

    test "range low above high" do
      bad = %{index: 0x3000, sub: 0, type: :uint8, len: 1, attr: [:rw], range: {9, 3}}
      assert SOD.new([bad]) == {:error, :max_min_value_error, {0x3000, 0}}
    end

    test "range on a boolean" do
      bad = %{index: 0x3000, sub: 0, type: :boolean, len: 1, attr: [:rw], range: {0, 1}}
      assert SOD.new([bad]) == {:error, :no_range_checking, {0x3000, 0}}
    end

    test "attribute checks" do
      base = %{index: 0x3000, sub: 0, type: :uint8, len: 1}
      assert {:error, :attr_is_wrong_1, _} = SOD.new([Map.put(base, :attr, [])])
      assert {:error, :attr_is_wrong_2, _} = SOD.new([Map.put(base, :attr, [:crc])])
      assert {:error, :attr_is_wrong_3, _} = SOD.new([Map.put(base, :attr, [:ro_const, :ro])])
      assert {:error, :no_default_value, _} = SOD.new([Map.put(base, :attr, [:wo, :pdo_map])])
      assert {:error, :obj_clbk_1, _} = SOD.new([Map.put(base, :attr, [:rw, :aft_wr])])

      assert {:error, :obj_clbk_2, _} =
               SOD.new([Map.merge(base, %{attr: [:rw], callback: fn _, _, _, _, _ -> :ok end})])
    end

    test "a default outside its range" do
      bad = %{index: 0x3000, sub: 0, type: :uint8, len: 1, attr: [:rw], default: 9, range: {1, 5}}
      assert SOD.new([bad]) == {:error, :value_is_too_high_1, {0x3000, 0}}
    end

    test "only a range: zero must be in it" do
      bad = %{index: 0x3000, sub: 0, type: :uint8, len: 1, attr: [:rw], range: {1, 5}}
      assert SOD.new([bad]) == {:error, :value_is_too_low, {0x3000, 0}}
    end
  end

  describe "attr_get/3 and attr_next/2" do
    test "found, missing sub, missing index" do
      sod = new!()
      assert {:ok, {0x1400, 1}, %{type: :uint16}} = SOD.attr_get(sod, 0x1400, 1)
      assert SOD.attr_get(sod, 0x1400, 9) == {:error, :attr_get, :sub_idx_does_not_exist}
      assert SOD.attr_get(sod, 0x5000, 0) == {:error, :attr_get, :obj_does_not_exist}
    end

    test "iteration is in (index, sub) order" do
      sod = new!()
      {:ok, h1, _} = SOD.attr_next(sod, :first)
      {:ok, h2, _} = SOD.attr_next(sod, h1)
      assert [h1, h2] == [{0x1000, 0}, {0x1400, 1}]
      assert SOD.attr_next(sod, {0x2001, 0}) == :end
    end
  end

  describe "write/6" do
    test "in-range value" do
      sod = new!()
      assert {:ok, sod} = SOD.put(sod, 0x1400, 1, 500)
      assert SOD.get(sod, 0x1400, 1) == {:ok, 500}
    end

    test "range violations" do
      sod = new!()

      assert {{:error, :value_is_too_high_1, :value_is_too_high}, _} =
               SOD.put(sod, 0x1400, 1, 2000)

      assert {{:error, :value_is_too_low, :value_is_too_low}, _} = SOD.put(sod, 0x1400, 1, 0)
    end

    test "read-only: same value is a no-op, a new value is refused, overwrite allowed" do
      sod = new!()
      assert {:ok, ^sod} = SOD.put(sod, 0x1400, 2, 100)
      assert {{:error, :obj_not_writeable, :obj_not_writeable}, _} = SOD.put(sod, 0x1400, 2, 5)
      assert {:ok, sod} = SOD.put(sod, 0x1400, 2, 5, true)
      assert SOD.get(sod, 0x1400, 2) == {:ok, 5}
    end

    test "read-only constant refuses even overwrite" do
      sod = new!()

      assert {{:error, :obj_not_writeable, :obj_not_writeable}, _} =
               SOD.put(sod, 0x1000, 0, 1, true)
    end

    test "boolean must be 0 or 1" do
      sod = new!()

      assert {{:error, :value_is_too_high_2, :value_is_too_high}, _} =
               SOD.write(sod, {0x1C00, 1}, <<2>>)
    end

    test "visible string characters" do
      sod = new!()
      assert {:ok, sod} = SOD.put(sod, 0x2000, 0, "PENDANT")
      assert SOD.get(sod, 0x2000, 0) == {:ok, "PENDANT"}

      assert {{:error, :visible_str_invalid, :value_range_exceeded}, _} =
               SOD.put(sod, 0x2000, 0, <<0x07>>)
    end

    test "segmented access only for strings and domains" do
      sod = new!()

      assert {{:error, :type_offset_2, :general_error}, _} =
               SOD.write(sod, {0x1400, 1}, <<1>>, false, 1, 1)

      assert {:ok, sod} = SOD.write(sod, {0x2001, 0}, <<1, 2>>, false, 2, 2)
      assert SOD.read(sod, {0x2001, 0}, 0, 4) == {:ok, <<0, 0, 1, 2>>}
      assert SOD.read(sod, {0x1400, 1}, 1, 1) == {:error, :type_offset_1, :general_error}
      assert SOD.read(sod, {0x2001, 0}, 15, 2) == {:error, :offset_size_1, :len_is_too_high}
    end

    test "write disabled" do
      sod = new!()
      {:ok, sod} = SOD.disable_write(sod)

      assert {{:error, :sod_write_disabled, :present_device_state}, _} =
               SOD.put(sod, 0x1400, 1, 3)
    end
  end

  describe "callbacks" do
    defp cb_od(test_pid, before_write) do
      cb = fn service, o, data, off, size ->
        send(test_pid, {service, {o.index, o.sub}, data, off, size})
        if service == :before_write, do: before_write, else: :ok
      end

      [
        %{
          index: 0x3000,
          sub: 0,
          type: :uint8,
          len: 1,
          attr: [:rw, :bef_rd, :bef_wr, :aft_wr],
          callback: cb
        },
        %{
          index: 0x3001,
          sub: 0,
          type: :domain,
          len: 8,
          attr: [:rw, :aft_wr],
          callback: cb,
          act_len: 4
        }
      ]
    end

    test "before read, before write, after write" do
      sod = new!(cb_od(self(), :ok))
      assert {:ok, <<0>>} = SOD.read(sod, {0x3000, 0})
      assert_received {:before_read, {0x3000, 0}, nil, 0, 0}

      assert {:ok, _} = SOD.write(sod, {0x3000, 0}, <<7>>)
      assert_received {:before_write, {0x3000, 0}, <<7>>, 0, 0}
      assert_received {:after_write, {0x3000, 0}, nil, 0, 0}
    end

    test "before-write abort leaves the value" do
      sod = new!(cb_od(self(), {:abort, :local_control}))

      assert {{:error, :clbk_abort_bw, :local_control}, sod} = SOD.write(sod, {0x3000, 0}, <<7>>)
      assert SOD.get(sod, 0x3000, 0) == {:ok, 0}
    end

    test "after-write fires only when the segment reaches the actual length" do
      sod = new!(cb_od(self(), :ok))
      {:ok, sod} = SOD.write(sod, {0x3001, 0}, <<1, 2>>, false, 0, 2)
      refute_received {:after_write, _, _, _, _}
      {:ok, _} = SOD.write(sod, {0x3001, 0}, <<3, 4>>, false, 2, 2)
      assert_received {:after_write, {0x3001, 0}, nil, 2, 2}
    end
  end

  describe "lock and write enable" do
    test "lock is exclusive; unlock needs a lock" do
      sod = new!()
      {:ok, sod} = SOD.lock(sod)
      assert {{:error, :locking_failed, _}, _} = SOD.lock(sod)
      {:ok, sod} = SOD.unlock(sod)
      assert {{:error, :unlock_without_lock, _}, _} = SOD.unlock(sod)
    end

    test "disable refused while locked; enable only when disabled" do
      sod = new!()
      {:ok, locked} = SOD.lock(sod)
      assert {{:error, :disable_wr_failed, _}, _} = SOD.disable_write(locked)
      assert {{:error, :enable_wr_failed, _}, _} = SOD.enable_write(sod)
      {:ok, sod} = SOD.disable_write(sod)
      {:ok, sod} = SOD.enable_write(sod)
      assert SOD.write_access?(sod)
    end
  end

  describe "actual length" do
    test "set and get" do
      sod = new!()
      assert SOD.act_len_get(sod, {0x2001, 0}) == {:ok, 4}
      assert SOD.act_len_get(sod, {0x1400, 1}) == {:ok, 2}
      {:ok, sod} = SOD.act_len_set(sod, {0x2001, 0}, 16)
      assert SOD.act_len_get(sod, {0x2001, 0}) == {:ok, 16}
      assert {{:error, :act_len, _}, _} = SOD.act_len_set(sod, {0x2001, 0}, 17)
      assert {{:error, :act_len_type, _}, _} = SOD.act_len_set(sod, {0x1400, 1}, 1)
    end
  end
end
