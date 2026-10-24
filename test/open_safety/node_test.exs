defmodule OpenSafety.NodeTest do
  use ExUnit.Case, async: true

  alias OpenSafety.{Frame, Node}

  @udid <<0x00, 0x60, 0x65, 0x11, 0x22, 0x33>>
  @scm_udid <<0x00, 0x60, 0x65, 0xAA, 0xBB, 0xCC>>
  @ts 0x0BADF00D
  @sadr 5
  @sdn 3
  @scm 1

  defp objects do
    [
      %{index: 0x100C, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 100},
      %{index: 0x100C, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 3},
      %{index: 0x100D, sub: 0, type: :uint32, len: 4, attr: [:rw], default: 50},
      %{index: 0x100E, sub: 0, type: :uint8, len: 1, attr: [:rw], default: 0xFF},
      %{index: 0x1018, sub: 7, type: :uint32, len: 4, attr: [:rw]},
      %{index: 0x1019, sub: 0, type: :octet_string, len: 6, attr: [:ro], default: @udid},
      %{index: 0x1200, sub: 1, type: :uint16, len: 2, attr: [:rw]},
      %{index: 0x1200, sub: 4, type: :octet_string, len: 6, attr: [:rw]},
      %{index: 0x1C00, sub: 1, type: :uint16, len: 2, attr: [:rw]}
    ]
  end

  # SCM side, by hand: encode a request, decode the node's answers.
  defp send_req(node, ct, id, data) do
    f = %Frame{id: id, adr: @sadr, sdn: @sdn, ct: 0, tr: 0, tadr: @scm, data: data}
    {:ok, bin} = Frame.encode(f, @scm_udid)
    {:ok, out} = Node.process(node, ct, bin)

    Enum.map(out, fn b ->
      {:ok, r} = Frame.decode(b, @scm_udid)
      r
    end)
  end

  test "boot over the wire, then SPDOs coded with the assigned SCM UDID" do
    {:ok, node} =
      Node.start_link(
        objects: objects(),
        tx: [%{sadr: @sadr, refresh_prescale: 10, no_tres: 1, len: 2}]
      )

    assert Node.perform_trans_pre_op(node, 0)

    assert [%{id: 0x2B}] = send_req(node, 0, 0x2A, @udid)

    assert [%{id: 0x2D, data: <<15, _::binary>>}] =
             send_req(node, 0, 0x2C, <<14, @scm_udid::binary>>)

    # SSDO: the SCM downloads the parameter timestamp while pre-operational.
    assert [%{id: 0x39, data: <<0x21, 0x1018::little-16, 7>>}] =
             send_req(node, 0, 0x38, <<0x21, 0x1018::little-16, 7, @ts::little-32>>)

    set_to_op = <<2, @ts::little-32>>
    assert [%{data: <<9>>}] = send_req(node, 0, 0x2C, set_to_op)
    assert [%{data: <<9>>}] = send_req(node, 0, 0x2C, set_to_op)
    assert_received {:opensafety_snmts, _, :calc_param_checksum}
    assert Node.pass_param_chksum_valid(node, true)
    assert [%{data: <<9>>}] = send_req(node, 0, 0x2C, set_to_op)
    assert_received {:opensafety_snmts, _, :switch_to_op_request}
    assert Node.enter_op_state(node, true)
    assert [%{data: <<3>>}] = send_req(node, 10, 0x2C, set_to_op)
    assert Node.sn_state(node) == :operational

    # Writes are refused once operational.
    assert [%{data: <<0x04, _::binary-size(3), 0x08000022::little-32>>}] =
             send_req(node, 11, 0x38, <<0x21, 0x1018::little-16, 7, 1::little-32>>)

    :ok = Node.put_data(node, 1, <<0xBE, 0xEF>>)
    [spdo] = Node.tick(node, 12)

    assert {:ok, %Frame{id: 0x31, adr: @sadr, sdn: @sdn, data: <<0xBE, 0xEF>>}} =
             Frame.decode(spdo, @scm_udid)

    # Without the SCM's UDID the SPDO does not decode.
    assert {:error, _} = Frame.decode(spdo, <<0::48>>)
  end

  test "responses addressed to an SCM are refused by an SN" do
    {:ok, node} = Node.start_link(objects: objects())
    f = %Frame{id: 0x39, adr: @sadr, sdn: @sdn, ct: 0, tr: 0, tadr: @scm, data: <<0x20, 0, 0, 0>>}
    {:ok, bin} = Frame.encode(f, <<0::48>>)
    assert {:ok, []} = Node.process(node, 0, bin)
    assert_received {:opensafety_ssc, ^node, {:error, :no_ssdo_client, 0x39}}
  end
end
