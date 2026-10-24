defmodule OpenSafety.SNMTMTest do
  use ExUnit.Case, async: true

  alias OpenSafety.{Frame, SNMTM}
  alias OpenSafety.SOD.Server, as: SOD

  @udid <<0x00, 0x60, 0x65, 0x11, 0x22, 0x33>>

  setup do
    {:ok, sod} =
      SOD.start_link([
        %{index: 0x1200, sub: 1, type: :uint16, len: 2, attr: [:rw], default: 3},
        %{index: 0x1200, sub: 2, type: :uint16, len: 2, attr: [:rw], default: 1},
        %{index: 0x1202, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 50},
        %{index: 0x1202, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 1}
      ])

    {:ok, m} = SNMTM.start_link(sod: sod, slots: 2)
    %{m: m}
  end

  defp resp(id, data, tadr \\ 5), do: %Frame{id: id, adr: 1, sdn: 3, tadr: tadr, data: data}

  test "requests are addressed from the SCM", %{m: m} do
    assert {:ok, f} = SNMTM.req_assgn_sadr(m, 0, 0, 5, @udid)
    assert {f.id, f.adr, f.tadr, f.sdn, f.ct, f.data} == {0x2A, 5, 1, 3, 0, @udid}

    assert {:ok, %{id: 0x2C, data: <<2, 0x1234::little-32>>}} =
             SNMTM.req_sn_trans(m, 0, 1, 6, :preop_to_op, 0x1234)

    # Two slots, both busy.
    refute SNMTM.available?(m)
    assert :error = SNMTM.req_guarding(m, 0, 2, 7)
    assert_received {:opensafety_snmtm, ^m, {:error, :no_fsm_avail_req_guard, 0}}
  end

  test "responses are assigned by UDID, by address, by command", %{m: m} do
    {:ok, _} = SNMTM.req_assgn_sadr(m, 0, 4, 5, @udid)
    {:ok, _} = SNMTM.req_sn_trans(m, 0, 9, 6, :preop_to_op, 1)

    # BUSY answers SET TO OP; it does not match the SADR assignment.
    assert {true, [{:resp, 9, 6, 3, <<9>>}]} = SNMTM.process_response(m, 0, resp(0x2D, <<9>>, 6))
    assert {true, [{:resp, 4, 5, 3, @udid}]} = SNMTM.process_response(m, 0, resp(0x2B, @udid))
    assert SNMTM.available?(m)

    # Nothing outstanding: not assigned.
    assert {false, []} = SNMTM.process_response(m, 0, resp(0x2D, <<3>>, 6))
    assert_received {:opensafety_snmtm, ^m, {:error, :resp_not_assigned, 0x2D}}
  end

  test "responses to another SADR are rejected; reset guarding is not", %{m: m} do
    {:ok, _} = SNMTM.req_guarding(m, 0, 0, 5)
    assert {false, []} = SNMTM.process_response(m, 0, %{resp(0x2D, <<3>>) | adr: 2})
    assert_received {:opensafety_snmtm, ^m, {:error, :resp_rej_wrong_dsadr, 2}}

    rst = %Frame{id: 0x2F, adr: 1, sdn: 1, tadr: 1, data: <<>>}
    assert {true, [:reset_guard]} = SNMTM.process_response(m, 0, rst)
  end

  test "repeat on timeout, then report it", %{m: m} do
    {:ok, f} = SNMTM.req_udid(m, 0, 3, 5)
    assert {2, [], []} = SNMTM.build_request(m, 49, 2)
    assert {1, [^f], []} = SNMTM.build_request(m, 50, 2)
    assert {2, [], [{:timeout, 3}]} = SNMTM.build_request(m, 100, 2)
    assert_received {:opensafety_snmtm, ^m, {:error, :no_resp_received, 3}}
    assert SNMTM.available?(m)
  end
end
