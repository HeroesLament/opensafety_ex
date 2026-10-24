defmodule OpenSafety.SERRTest do
  use ExUnit.Case, async: true

  alias OpenSafety.{Frame, Node, SERR, SNMTM, SSDOC}
  alias OpenSafety.SOD.Server, as: SOD

  @udid <<0x00, 0x60, 0x65, 0x11, 0x22, 0x33>>
  @scm_udid <<0x00, 0x60, 0x65, 0xAA, 0xBB, 0xCC>>

  test "counters and C-style getters" do
    {:ok, s} = SERR.start_link(max_rx: 4, max_slots: 2)

    :ok = SERR.count_common(s, :sfs_crc1)
    :ok = SERR.count_spdo(s, 3, :sct_tout)
    :ok = SERR.count_spdo(s, 3, :sct_tout)
    :ok = SERR.count_acyc(s, 1, :snmt_retry)

    assert SERR.get_common(s, :sfs_crc1) == {:ok, 1}
    # SPDO and acyclic events also count in the common counters.
    assert SERR.get_common(s, :cyc_error) == {:ok, 2}
    assert SERR.get_common(s, :acyc_retry) == {:ok, 1}
    assert SERR.get_spdo(s, 3, :sct_tout) == {:ok, 2}
    assert SERR.get_spdo(s, 0, :sct_tout) == {:ok, 0}
    assert SERR.get_acyc(s, 1, :snmt_retry) == {:ok, 1}

    # Range checks as SERR_Get*StatCtr.
    assert SERR.get_spdo(s, 4, :sct_tout) == :error
    assert SERR.get_acyc(s, 2, :snmt_retry) == :error
    assert SERR.get_common(s, :nope) == :error

    # No server: counting is a no-op.
    assert SERR.count_common(nil, :sfs_crc1) == :ok
  end

  test "decode errors map to the SFS counters" do
    assert SERR.decode_event(:crc1) == :sfs_crc1
    assert SERR.decode_event(:crc2) == :sfs_crc2
    assert SERR.decode_event(:data_mismatch) == :sfs_data
    assert SERR.decode_event({:length, 20, 21}) == :sfs_length
    assert SERR.decode_event({:length, :too_long, 255}) == :sfs_too_long
    assert SERR.decode_event({:id_mismatch, 0x30, 0x32}) == :sfs_frm_id
    assert SERR.decode_event({:bad_tadr, 2000}) == :sfs_tadr_inv
  end

  describe "in a node" do
    defp objects do
      [
        %{index: 0x100C, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 100},
        %{index: 0x100C, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 3},
        %{index: 0x100D, sub: 0, type: :uint32, len: 4, attr: [:rw], default: 50},
        %{index: 0x100E, sub: 0, type: :uint8, len: 1, attr: [:rw], default: 0},
        %{index: 0x1018, sub: 7, type: :uint32, len: 4, attr: [:rw]},
        %{index: 0x1019, sub: 0, type: :octet_string, len: 6, attr: [:ro], default: @udid},
        %{index: 0x1200, sub: 1, type: :uint16, len: 2, attr: [:rw], default: 3},
        %{index: 0x1200, sub: 4, type: :octet_string, len: 6, attr: [:rw], default: @scm_udid},
        %{index: 0x1C00, sub: 1, type: :uint16, len: 2, attr: [:rw], default: 5}
      ]
    end

    defp bin(f) do
      {:ok, b} = Frame.encode(f, @scm_udid)
      b
    end

    setup do
      {:ok, node} = Node.start_link(objects: objects())
      %{node: node, serr: Node.services(node).serr}
    end

    test "a corrupted frame counts as an SFS error", %{node: node, serr: serr} do
      f = %Frame{id: 0x2C, adr: 5, sdn: 3, tadr: 1, data: <<8>>}
      <<a, b, c, d, e, rest::binary>> = bin(f)

      assert {:ok, []} =
               Node.process(node, 0, <<a, b, c, d, Bitwise.bxor(e, 0xFF), rest::binary>>)

      assert SERR.get_common(serr, :sfs_crc1) == {:ok, 1}
      assert SERR.get_common(serr, :acyc_reject) == {:ok, 0}
    end

    test "SNMT and SSDO frames the SSC cannot process are rejects", %{node: node, serr: serr} do
      # A response at a plain SN, and a request in Initialization.
      assert {:ok, []} =
               Node.process(node, 0, bin(%Frame{id: 0x2D, adr: 5, sdn: 3, tadr: 1, data: <<3>>}))

      assert {:ok, []} =
               Node.process(node, 0, bin(%Frame{id: 0x2C, adr: 5, sdn: 3, tadr: 1, data: <<8>>}))

      assert SERR.get_common(serr, :acyc_reject) == {:ok, 2}
    end

    test "an SPDO from another domain is a cyclic reject", %{node: node, serr: serr} do
      Node.services(node).spdo |> OpenSafety.SPDO.set_to_op(0)
      assert {:ok, []} = Node.process(node, 0, bin(%Frame{id: 0x30, adr: 7, sdn: 9, data: <<1>>}))
      assert {:ok, []} = Node.process(node, 0, bin(%Frame{id: 0x30, adr: 7, sdn: 3, data: <<1>>}))
      assert SERR.get_common(serr, :cyc_reject) == {:ok, 2}
    end
  end

  test "SNMTM and SSDOC timers count retries and timeouts per slot" do
    {:ok, serr} = SERR.start_link()

    {:ok, sod} =
      SOD.start_link([
        %{index: 0x1200, sub: 1, type: :uint16, len: 2, attr: [:rw], default: 3},
        %{index: 0x1200, sub: 2, type: :uint16, len: 2, attr: [:rw], default: 1},
        %{index: 0x1201, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 10},
        %{index: 0x1201, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 1},
        %{index: 0x1202, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 10},
        %{index: 0x1202, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 2}
      ])

    {:ok, m} = SNMTM.start_link(sod: sod, slots: 2, serr: serr)
    {:ok, c} = SSDOC.start_link(sod: sod, slots: 2, serr: serr)

    {:ok, _} = SNMTM.req_udid(m, 0, 0, 5)
    req = %{idx: 0x1018, sub: 1, type: :uint32, payload_len: 12, data_len: 4}
    {:ok, _} = SSDOC.send_read_req(c, 5, 0, 0, req)

    for ct <- [10, 20, 30] do
      SNMTM.build_request(m, ct, 4)
      SSDOC.build_request(c, ct, 4)
    end

    assert SERR.get_acyc(serr, 0, :snmt_retry) == {:ok, 2}
    assert SERR.get_acyc(serr, 0, :snmt_tout) == {:ok, 1}
    assert SERR.get_acyc(serr, 0, :ssdo_retry) == {:ok, 1}
    assert SERR.get_acyc(serr, 0, :ssdo_tout) == {:ok, 1}
    assert SERR.get_common(serr, :acyc_retry) == {:ok, 5}
  end
end
