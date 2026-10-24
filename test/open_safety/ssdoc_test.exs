defmodule OpenSafety.SSDOCTest do
  use ExUnit.Case, async: true

  alias OpenSafety.{Frame, SNMTS, SSDOC, SSDOS}
  alias OpenSafety.SOD.Server, as: SOD

  @sadr 5
  @sdn 3
  @scm 1
  @blob for(i <- 1..40, into: <<>>, do: <<i>>)

  defp client_objects do
    [
      %{index: 0x1200, sub: 1, type: :uint16, len: 2, attr: [:rw], default: @sdn},
      %{index: 0x1200, sub: 2, type: :uint16, len: 2, attr: [:rw], default: @scm},
      %{index: 0x1201, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 20},
      %{index: 0x1201, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 1}
    ]
  end

  defp server_objects do
    [
      %{index: 0x100C, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 100},
      %{index: 0x100C, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 3},
      %{index: 0x100D, sub: 0, type: :uint32, len: 4, attr: [:rw], default: 50},
      %{index: 0x100E, sub: 0, type: :uint8, len: 1, attr: [:rw], default: 0},
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
      %{index: 0x2000, sub: 0, type: :domain, len: 40, attr: [:rw], default: @blob},
      %{index: 0x2001, sub: 0, type: :uint32, len: 4, attr: [:rw], default: 0xCAFEF00D},
      %{index: 0x2002, sub: 0, type: :domain, len: 64, attr: [:rw], act_len: 0}
    ]
  end

  setup do
    {:ok, csod} = SOD.start_link(client_objects())
    {:ok, client} = SSDOC.start_link(sod: csod, slots: 4)

    {:ok, ssod} = SOD.start_link(server_objects())
    {:ok, snmts} = SNMTS.start_link(sod: ssod)
    true = SNMTS.perform_trans_pre_op(snmts, 0)
    {:ok, server} = SSDOS.start_link(sod: ssod, snmts: snmts)

    %{client: client, server: server, ssod: ssod}
  end

  # Request frames to the server, responses back, until the transfer ends.
  defp exchange(_client, _server, [], effects), do: effects

  defp exchange(client, server, [req | rest], effects) do
    case SSDOS.process_request(server, req) do
      {:reply, resp} ->
        {_ok, frames, eff} = SSDOC.process_response(client, 0, resp)
        exchange(client, server, rest ++ frames, effects ++ eff)

      _no_response ->
        exchange(client, server, rest, effects)
    end
  end

  test "expedited upload", %{client: c, server: s} do
    req = %{idx: 0x2001, sub: 0, type: :uint32, payload_len: 12, data_len: 4}

    assert {:ok, %Frame{id: 0x38, adr: @sadr, tadr: @scm, sdn: @sdn, ct: 1} = f} =
             SSDOC.send_read_req(c, @sadr, 7, 0, req)

    assert f.data == <<0x20, 0x2001::little-16, 0>>
    assert [{:resp, 7, 4, 0, <<0xCAFEF00D::little-32>>}] = exchange(c, s, [f], [])
    assert SSDOC.available?(c)
  end

  test "segmented upload of a 40-byte domain", %{client: c, server: s} do
    req = %{idx: 0x2000, sub: 0, type: :domain, payload_len: 12, data_len: 64}
    {:ok, f} = SSDOC.send_read_req(c, @sadr, 2, 0, req)
    assert [{:resp, 2, 40, 0, @blob}] = exchange(c, s, [f], [])
  end

  test "segmented fast download", %{client: c, server: s, ssod: ssod} do
    data = for i <- 100..129, into: <<>>, do: <<i>>
    req = %{idx: 0x2002, sub: 0, type: :domain, payload_len: 22, data_len: 30, data: data}
    {:ok, f} = SSDOC.send_write_req(c, @sadr, 3, 0, req, true)
    assert f.id == 0x3A
    assert <<0x29, 0x2002::little-16, 0, 30::little-32, _::binary-size(14)>> = f.data
    assert [{:resp, 3, 30, 0, nil}] = exchange(c, s, [f], [])
    assert SOD.get(ssod, 0x2002, 0) == {:ok, data}
  end

  test "server abort reaches the caller", %{client: c, server: s} do
    req = %{idx: 0x3000, sub: 0, type: :uint32, payload_len: 12, data_len: 4}
    {:ok, f} = SSDOC.send_read_req(c, @sadr, 1, 0, req)
    assert [{:resp, 1, 0, 0x06020000, nil}] = exchange(c, s, [f], [])
    assert SSDOC.available?(c)
  end

  test "one transfer per SADR", %{client: c} do
    req = %{idx: 0x2001, sub: 0, type: :uint32, payload_len: 12, data_len: 4}
    {:ok, _} = SSDOC.send_read_req(c, @sadr, 1, 0, req)
    assert :error = SSDOC.send_read_req(c, @sadr, 2, 0, req)
    assert_received {:opensafety_ssdoc, ^c, {:error, :transfer_running, @sadr}}
  end

  test "retransmit, then abort on timeout", %{client: c} do
    req = %{idx: 0x2001, sub: 0, type: :uint32, payload_len: 12, data_len: 4}
    {:ok, f} = SSDOC.send_read_req(c, @sadr, 9, 0, req)

    assert {3, [], []} = SSDOC.build_request(c, 19, 3)
    assert {2, [^f], []} = SSDOC.build_request(c, 20, 3)

    # Retries used up: an abort frame with the request's header.
    assert {1, [abort], [{:resp, 9, 4, 0x05040000, nil}]} = SSDOC.build_request(c, 40, 2)
    assert abort.ct == f.ct
    assert abort.data == <<0x04, 0x2001::little-16, 0, 0x05040000::little-32>>
    assert SSDOC.available?(c)
  end

  test "response with a stale SANo is ignored", %{client: c, server: s} do
    req = %{idx: 0x2001, sub: 0, type: :uint32, payload_len: 12, data_len: 4}
    {:ok, f} = SSDOC.send_read_req(c, @sadr, 1, 0, req)
    {:reply, resp} = SSDOS.process_request(s, f)
    assert {false, [], []} = SSDOC.process_response(c, 0, %{resp | ct: resp.ct + 1})
    assert_received {:opensafety_ssdoc, ^c, {:error, :resp_sano_diff, _}}
    assert {true, [], [{:resp, 1, 4, 0, _}]} = SSDOC.process_response(c, 0, resp)
  end
end
