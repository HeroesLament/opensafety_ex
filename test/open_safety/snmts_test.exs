defmodule OpenSafety.SNMTSTest do
  use ExUnit.Case, async: true

  alias OpenSafety.{Frame, SNMTS}
  alias OpenSafety.SOD.Server, as: SOD

  @udid <<0x00, 0x60, 0x65, 0x11, 0x22, 0x33>>
  @scm_udid <<0x00, 0x60, 0x65, 0xAA, 0xBB, 0xCC>>
  @param_ts 0x1234_5678

  # SN at SADR 5, SDN 3 once assigned; SCM at SADR 1.
  @sadr 5
  @sdn 3
  @scm 1

  defp sod_objects do
    [
      %{index: 0x100C, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 100},
      %{index: 0x100C, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 3},
      %{index: 0x100D, sub: 0, type: :uint32, len: 4, attr: [:rw], default: 50},
      %{index: 0x100E, sub: 0, type: :uint8, len: 1, attr: [:rw], default: 2},
      %{index: 0x1018, sub: 7, type: :uint32, len: 4, attr: [:rw], default: @param_ts},
      %{index: 0x1019, sub: 0, type: :octet_string, len: 6, attr: [:ro], default: @udid},
      %{index: 0x1200, sub: 1, type: :uint16, len: 2, attr: [:rw]},
      %{index: 0x1200, sub: 4, type: :octet_string, len: 6, attr: [:rw]},
      %{index: 0x1C00, sub: 1, type: :uint16, len: 2, attr: [:rw]}
    ]
  end

  setup do
    {:ok, sod} = SOD.start_link(sod_objects())
    {:ok, sn} = SNMTS.start_link(sod: sod)
    %{sod: sod, sn: sn}
  end

  defp req(id, data, opts \\ []) do
    %Frame{
      id: id,
      adr: Keyword.get(opts, :adr, @sadr),
      sdn: Keyword.get(opts, :sdn, @sdn),
      ct: 0,
      tr: 0,
      tadr: @scm,
      data: data
    }
  end

  defp ext(data, opts \\ []), do: req(0x2C, data, opts)

  defp errors do
    receive do
      {:opensafety_snmts, _, {:error, code, _}} -> [code | errors()]
    after
      0 -> []
    end
  end

  # Drive the node to Operational; returns nothing, asserts each step.
  defp boot(sn, sod) do
    assert SNMTS.perform_trans_pre_op(sn, 0)
    assert SNMTS.fsm_state(sn) == :wf_sadr_ass_step1

    # UDID request, answered before any address is assigned.
    assert {:reply, r} = SNMTS.process_request(sn, 0, req(0x28, <<>>, sdn: 1))
    assert {r.id, r.adr, r.tadr, r.data} == {0x29, @scm, @sadr, @udid}

    # SADR + SDN assignment, two passes through the state machine.
    assert {:reply, r} = SNMTS.process_request(sn, 0, req(0x2A, @udid))
    assert {r.id, r.adr, r.sdn, r.tadr, r.data} == {0x2B, @scm, @sdn, @sadr, @udid}
    assert SOD.get(sod, 0x1C00, 1) == {:ok, @sadr}
    assert SOD.get(sod, 0x1200, 1) == {:ok, @sdn}
    assert SNMTS.fsm_state(sn) == :wf_udid_scm_ass

    # The SCM's UDID.
    assert {:reply, r} = SNMTS.process_request(sn, 0, ext(<<14, @scm_udid::binary>>))
    assert {r.id, r.data} == {0x2D, <<15, @scm_udid::binary>>}
    assert SOD.get(sod, 0x1200, 4) == {:ok, @scm_udid}

    set_to_op = ext(<<2, @param_ts::little-32>>)

    # SET TO OP 1: parameters processed, mapping activation next.
    assert {:reply, %{data: <<9>>}} = SNMTS.process_request(sn, 0, set_to_op)
    assert SNMTS.fsm_state(sn) == :wf_set_to_op1_step2

    # Mapping activated; the application is asked for the checksum.
    assert {:reply, %{data: <<9>>}} = SNMTS.process_request(sn, 0, set_to_op)
    assert_received {:opensafety_snmts, ^sn, :calc_param_checksum}
    assert SNMTS.pass_param_chksum_valid(sn, true)
    assert SNMTS.fsm_state(sn) == :wf_set_to_op2

    # SET TO OP 2: timestamp matches; the application is asked to confirm.
    assert {:reply, %{data: <<9>>}} = SNMTS.process_request(sn, 0, set_to_op)
    assert_received {:opensafety_snmts, ^sn, :switch_to_op_request}
    assert SNMTS.enter_op_state(sn, true)

    # SET TO OP 3: Operational.
    assert {:reply, %{data: <<3>>}} = SNMTS.process_request(sn, 10, set_to_op)
    assert SNMTS.sn_state(sn) == :operational
  end

  test "boot-up to operational", %{sn: sn, sod: sod} do
    boot(sn, sod)
    assert errors() == []
  end

  test "SADR assignment with a foreign UDID is ignored", %{sn: sn} do
    assert SNMTS.perform_trans_pre_op(sn, 0)
    assert :rejected = SNMTS.process_request(sn, 0, req(0x2A, <<1, 2, 3, 4, 5, 6>>))
    assert :rx_udid_uneven in errors()
    assert SNMTS.fsm_state(sn) == :wf_sadr_ass_step1
  end

  test "requests for another address are rejected once assigned", %{sn: sn, sod: sod} do
    boot(sn, sod)
    assert :rejected = SNMTS.process_request(sn, 20, ext(<<8>>, adr: 9))
    assert :req_rej_inv_dsadr in errors()
  end

  test "wrong parameter timestamp fails with SN FAIL, acknowledged", %{sn: sn, sod: sod} do
    assert SNMTS.perform_trans_pre_op(sn, 0)
    {:reply, _} = SNMTS.process_request(sn, 0, req(0x2A, @udid))
    {:reply, _} = SNMTS.process_request(sn, 0, ext(<<14, @scm_udid::binary>>))
    bad = ext(<<2, 0xDEAD::little-32>>)
    {:reply, _} = SNMTS.process_request(sn, 0, bad)
    {:reply, _} = SNMTS.process_request(sn, 0, bad)
    assert SNMTS.pass_param_chksum_valid(sn, true)

    assert {:reply, %{data: <<7, 4, 1>>}} = SNMTS.process_request(sn, 0, bad)
    assert :param_timestamp_inv in errors()
    assert SNMTS.fsm_state(sn) == :wf_set_to_op1_step1

    # SN ACK for that failure reaches the application. No response, and
    # the C reports FALSE for it, so the SSC counts it as a reject.
    assert :rejected = SNMTS.process_request(sn, 0, ext(<<12, 4, 1>>))
    assert_received {:opensafety_snmts, ^sn, {:error_ack, 4, 1}}
    _ = sod
  end

  test "guarding keeps it operational; life time expiry drops it", %{sn: sn, sod: sod} do
    boot(sn, sod)
    # Guarding at 50 restarts life guarding: 100 per guard, factor 3.
    assert {:reply, %{data: <<3>>}} = SNMTS.process_request(sn, 50, ext(<<8>>))
    assert SNMTS.timer_check(sn, 149, 1) == []
    assert SNMTS.sn_state(sn) == :operational
    assert SNMTS.timer_check(sn, 150, 1) == []
    assert SNMTS.timer_check(sn, 250, 1) == []
    assert SNMTS.sn_state(sn) == :operational
    assert SNMTS.timer_check(sn, 350, 1) == []
    assert SNMTS.sn_state(sn) == :pre_operational
    assert SNMTS.fsm_state(sn) == :wf_set_to_op1_step1
    assert :life_time_elapsed in errors()
  end

  test "pre-operational refresh sends reset-guarding, up to the retry limit", %{sn: sn} do
    assert SNMTS.perform_trans_pre_op(sn, 0)
    assert SNMTS.timer_check(sn, 49, 1) == []
    assert [%Frame{id: 0x2F, adr: 1, sdn: 1, tadr: 1}] = SNMTS.timer_check(sn, 50, 1)
    assert [_] = SNMTS.timer_check(sn, 100, 1)
    # Two retries configured (0x100E): no more.
    assert SNMTS.timer_check(sn, 150, 1) == []
  end

  test "SET TO PREOP in operational", %{sn: sn, sod: sod} do
    boot(sn, sod)
    assert {:reply, %{data: <<1>>}} = SNMTS.process_request(sn, 20, ext(<<0>>))
    assert SNMTS.sn_state(sn) == :pre_operational
  end

  describe "with an SPDO layer" do
    defp spdo(rx) do
      {:ok, spdo} =
        OpenSafety.SPDO.start_link(
          sdn: @sdn,
          scm_udid: @scm_udid,
          tx: [%{sadr: @sadr, refresh_prescale: 10, no_tres: 1, len: 1}],
          rx: rx
        )

      spdo
    end

    test "operational switches the SPDO layer, pre-operational stops it", %{sod: sod} do
      spdo = spdo([])
      {:ok, sn} = SNMTS.start_link(sod: sod, spdo: spdo)
      boot(sn, sod)
      assert [_frame] = OpenSafety.SPDO.build(spdo, 11)

      assert {:reply, _} = SNMTS.process_request(sn, 20, ext(<<0>>))
      assert OpenSafety.SPDO.build(spdo, 30) == []
    end

    test "bad Rx SPDO configuration fails mapping activation", %{sod: sod} do
      # Two Rx SPDOs from the same source address.
      rx = %{
        sadr: 7,
        sct: 50,
        no_consecutive_treq: 1,
        time_delay_treq: 20,
        time_delay_sync: 1000,
        min_tsync_prop_delay: 1,
        max_tsync_prop_delay: 10,
        min_spdo_prop_delay: 1,
        max_spdo_prop_delay: 10,
        best_case_tres_delay: 1,
        time_request_cycle: 100,
        tx_spdo_no: 1
      }

      {:ok, sn} = SNMTS.start_link(sod: sod, spdo: spdo([rx, rx]))
      assert SNMTS.perform_trans_pre_op(sn, 0)
      {:reply, _} = SNMTS.process_request(sn, 0, req(0x2A, @udid))
      {:reply, _} = SNMTS.process_request(sn, 0, ext(<<14, @scm_udid::binary>>))
      set_to_op = ext(<<2, @param_ts::little-32>>)
      {:reply, _} = SNMTS.process_request(sn, 0, set_to_op)

      assert {:reply, %{data: <<7, 4, 2>>}} = SNMTS.process_request(sn, 0, set_to_op)
      assert SNMTS.fsm_state(sn) == :wf_set_to_op1_step1
    end
  end
end
