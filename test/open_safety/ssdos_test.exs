defmodule OpenSafety.SSDOSTest do
  use ExUnit.Case, async: true

  alias OpenSafety.{Frame, SNMTS, SSDOS}
  alias OpenSafety.SOD.Server, as: SOD

  @sadr 5
  @sdn 3
  @scm 1

  defp objects do
    [
      %{index: 0x100C, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 100},
      %{index: 0x100C, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 3},
      %{index: 0x100D, sub: 0, type: :uint32, len: 4, attr: [:rw], default: 50},
      %{index: 0x100E, sub: 0, type: :uint8, len: 1, attr: [:rw], default: 2},
      %{index: 0x1018, sub: 7, type: :uint32, len: 4, attr: [:rw]},
      %{
        index: 0x1019,
        sub: 0,
        type: :octet_string,
        len: 6,
        attr: [:ro],
        default: <<1, 2, 3, 4, 5, 6>>
      },
      %{index: 0x1200, sub: 1, type: :uint16, len: 2, attr: [:rw], default: @sdn},
      %{index: 0x1200, sub: 4, type: :octet_string, len: 6, attr: [:rw]},
      %{index: 0x1C00, sub: 1, type: :uint16, len: 2, attr: [:rw], default: @sadr},
      %{index: 0x2000, sub: 0, type: :uint16, len: 2, attr: [:rw], range: {0, 0x2000}},
      %{index: 0x2001, sub: 0, type: :domain, len: 30, attr: [:rw], act_len: 0},
      %{index: 0x2002, sub: 0, type: :uint32, len: 4, attr: [:ro], default: 0xCAFEF00D},
      %{index: 0x2003, sub: 0, type: :uint8, len: 1, attr: [:wo]}
    ]
  end

  setup do
    {:ok, sod} = SOD.start_link(objects())
    {:ok, sn} = SNMTS.start_link(sod: sod)
    assert SNMTS.perform_trans_pre_op(sn, 0)
    {:ok, ss} = SSDOS.start_link(sod: sod, snmts: sn)
    %{sod: sod, ss: ss}
  end

  defp req(data, opts \\ []) do
    %Frame{
      id: Keyword.get(opts, :id, 0x38),
      adr: Keyword.get(opts, :adr, @sadr),
      sdn: @sdn,
      ct: 7,
      tr: 0,
      tadr: @scm,
      data: data
    }
  end

  defp io(ss, data, opts \\ []) do
    case SSDOS.process_request(ss, req(data, opts)) do
      {:reply, r} -> r.data
      other -> other
    end
  end

  defp errors do
    receive do
      {:opensafety_ssdos, _, {:error, code, _}} -> [code | errors()]
    after
      0 -> []
    end
  end

  test "expedited download", %{ss: ss, sod: sod} do
    assert io(ss, <<0x21, 0x2000::little-16, 0, 0x1234::little-16>>) ==
             <<0x21, 0x2000::little-16, 0>>

    assert SOD.get(sod, 0x2000, 0) == {:ok, 0x1234}
  end

  test "response mirrors addressing and CT", %{ss: ss} do
    {:reply, r} = SSDOS.process_request(ss, req(<<0x20, 0x2002::little-16, 0>>))
    assert {r.id, r.adr, r.tadr, r.sdn, r.ct} == {0x39, @scm, @sadr, @sdn, 7}
  end

  test "expedited upload", %{ss: ss} do
    assert io(ss, <<0x20, 0x2002::little-16, 0>>) ==
             <<0x20, 0x2002::little-16, 0, 0xCAFEF00D::little-32>>
  end

  test "aborts: range, not readable, missing object, bad command", %{ss: ss} do
    assert io(ss, <<0x21, 0x2000::little-16, 0, 0x3000::little-16>>) ==
             <<0x04, 0x2000::little-16, 0, 0x06090031::little-32>>

    assert io(ss, <<0x20, 0x2003::little-16, 0>>) ==
             <<0x04, 0x2003::little-16, 0, 0x06010001::little-32>>

    assert io(ss, <<0x20, 0x5000::little-16, 0>>) ==
             <<0x04, 0x5000::little-16, 0, 0x06020000::little-32>>

    assert io(ss, <<0x77, 0x2000::little-16, 0>>) ==
             <<0x04, 0x2000::little-16, 0, 0x05040001::little-32>>
  end

  test "segmented download, then segmented upload", %{ss: ss, sod: sod} do
    payload = for i <- 1..20, into: <<>>, do: <<i>>
    <<first::binary-size(4), mid::binary-size(11), last::binary-size(5)>> = payload

    # Initiate: 20 bytes, the first 4 in the request (max payload 12).
    assert io(ss, <<0x29, 0x2001::little-16, 0, 20::little-32, first::binary>>) ==
             <<0x29, 0x2001::little-16, 0>>

    assert SOD.locked?(sod)

    # Toggle set on the first segment, clear on the next.
    assert io(ss, <<0x19, mid::binary>>) == <<0x19>>
    assert io(ss, <<0x49, last::binary>>) == <<0x49>>

    refute SOD.locked?(sod)
    assert SOD.get(sod, 0x2001, 0) == {:ok, payload}

    # Upload it back: 20 > 12 - 4, so segmented; 4 bytes in the initiate.
    assert io(ss, <<0x20, 0x2001::little-16, 0>>) ==
             <<0x28, 0x2001::little-16, 0, 20::little-32, first::binary>>

    assert io(ss, <<0x18, 0x2001::little-16, 0>>) == <<0x18, mid::binary>>
    assert io(ss, <<0x08, 0x2001::little-16, 0>>) == <<0x48, last::binary>>
    refute SOD.locked?(sod)
  end

  test "wrong toggle bit is rejected without a response", %{ss: ss} do
    assert io(ss, <<0x29, 0x2001::little-16, 0, 20::little-32, 1, 2, 3, 4>>) ==
             <<0x29, 0x2001::little-16, 0>>

    assert io(ss, <<0x09, 1, 2, 3>>) == :rejected
    assert :toggle_bit in errors()
    assert SSDOS.state(ss) == :dwnld_wf_req_seg
  end

  test "abort from the client ends the transfer and unlocks", %{ss: ss, sod: sod} do
    assert io(ss, <<0x29, 0x2001::little-16, 0, 20::little-32, 1, 2, 3, 4>>) ==
             <<0x29, 0x2001::little-16, 0>>

    assert io(ss, <<0x04, 0x2001::little-16, 0, 0x08000000::little-32>>) == :rejected
    assert :abort_rx in errors()
    refute SOD.locked?(sod)
    assert SSDOS.state(ss) == :wf_req_init
  end

  test "request for another node is filtered", %{ss: ss} do
    assert io(ss, <<0x20, 0x2002::little-16, 0>>, adr: 9) == :rejected
    assert :req_dsadr in errors()
  end

  test "fast SSDO: longer payload, slim response ID", %{ss: ss, sod: sod} do
    data = :binary.copy(<<0x41>>, 18)

    {:reply, r} =
      SSDOS.process_request(ss, req(<<0x21, 0x2001::little-16, 0, data::binary>>, id: 0x3A))

    assert r.id == 0x3B
    assert SOD.get(sod, 0x2001, 0) == {:ok, data}
  end
end
