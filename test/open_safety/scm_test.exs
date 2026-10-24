defmodule OpenSafety.SCMTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias OpenSafety.{Node, SCM}
  alias OpenSafety.SOD.Server, as: SOD

  # One SCM node (SADR 1) configures one SN (SADR 5) in domain 3, over
  # encoded frames, both driven by a shared consecutive time.

  @sn_udid <<0x00, 0x60, 0x65, 0x11, 0x22, 0x33>>
  @scm_udid <<0x00, 0x60, 0x65, 0xAA, 0xBB, 0xCC>>
  @ts 0x0BADF00D
  @crc <<0xC1, 0xC2, 0xC3, 0xC4>>
  @vendor 0x00000002
  @product 0x00001234
  @revision 0x00010000
  @sadr 5
  @sdn 3
  @params for(i <- 1..30, into: <<>>, do: <<i>>)

  # The node part both kinds of node share (SNMTS: life guarding, refresh).
  defp node_objects(udid, sadr, sdn) do
    [
      %{index: 0x100C, sub: 1, type: :uint32, len: 4, attr: [:rw], default: 100},
      %{index: 0x100C, sub: 2, type: :uint8, len: 1, attr: [:rw], default: 3},
      %{index: 0x100D, sub: 0, type: :uint32, len: 4, attr: [:rw], default: 50},
      %{index: 0x100E, sub: 0, type: :uint8, len: 1, attr: [:rw], default: 0xFF},
      %{index: 0x1018, sub: 7, type: :uint32, len: 4, attr: [:rw], default: @ts},
      %{index: 0x1019, sub: 0, type: :octet_string, len: 6, attr: [:ro], default: udid},
      %{index: 0x1200, sub: 1, type: :uint16, len: 2, attr: [:rw], default: sdn},
      %{index: 0x1200, sub: 4, type: :octet_string, len: 6, attr: [:rw]},
      %{index: 0x1C00, sub: 1, type: :uint16, len: 2, attr: [:rw], default: sadr}
    ]
  end

  defp sn_objects do
    node_objects(@sn_udid, 0, 0) ++
      [
        %{index: 0x1018, sub: 1, type: :uint32, len: 4, attr: [:ro], default: @vendor},
        %{index: 0x1018, sub: 2, type: :uint32, len: 4, attr: [:ro], default: @product},
        %{index: 0x1018, sub: 3, type: :uint32, len: 4, attr: [:ro], default: @revision},
        %{index: 0x1018, sub: 6, type: :domain, len: 4, attr: [:rw], default: @crc},
        %{index: 0x101A, sub: 0, type: :domain, len: 64, attr: [:rw], act_len: 0}
      ]
  end

  # The SCM's configuration of SN 0. `cfg` overrides defaults by
  # {index, sub}; `:extra` adds objects.
  defp scm_objects(cfg \\ %{}, extra \\ []) do
    sn = 0xC400

    defaults = %{
      {0x101B, 1} => %{type: :uint8, len: 1, default: 0},
      {0x1200, 2} => %{type: :uint16, len: 2, default: 1},
      {0x1201, 1} => %{type: :uint32, len: 4, default: 50},
      {0x1201, 2} => %{type: :uint8, len: 1, default: 2},
      {0x1202, 1} => %{type: :uint32, len: 4, default: 50},
      {0x1202, 2} => %{type: :uint8, len: 1, default: 2},
      {sn, 1} => %{type: :uint16, len: 2, default: @sadr},
      {sn, 2} => %{type: :uint32, len: 4, default: @vendor},
      {sn, 3} => %{type: :uint32, len: 4, default: @product},
      {sn, 4} => %{type: :uint32, len: 4, default: @revision},
      {sn, 5} => %{type: :uint8, len: 1, default: 0},
      {sn, 7} => %{type: :uint32, len: 4, default: @ts},
      {sn, 8} => %{type: :uint16, len: 2, default: 12},
      {sn, 9} => %{type: :uint32, len: 4, default: 10},
      {sn, 14} => %{type: :domain, len: 4, default: @crc},
      {sn, 15} => %{type: :domain, len: 16},
      {0xCC00 + @sadr, 0} => %{type: :uint8, len: 1, default: 1},
      {0xCC00 + @sadr, 1} => %{type: :octet_string, len: 6, default: @sn_udid}
    }

    node = node_objects(@scm_udid, 1, @sdn)

    node =
      Enum.map(node, fn o ->
        if {o.index, o.sub} == {0x1200, 4}, do: Map.put(o, :default, @scm_udid), else: o
      end)

    scm =
      defaults
      |> Map.merge(cfg)
      |> Enum.map(fn {{i, s}, o} -> Map.merge(%{index: i, sub: s, attr: [:rw]}, o) end)

    node ++ scm ++ extra
  end

  defp start(scm_objects, scm_opts \\ []) do
    {:ok, scm} = Node.start_link(objects: scm_objects, scm: scm_opts)
    {:ok, sn} = Node.start_link(objects: sn_objects())
    assert Node.perform_trans_pre_op(sn, 0)
    assert Node.scm_activate(scm)
    %{scm: scm, sn: sn, sn_snmts: Node.services(sn).snmts, scm_svc: Node.services(scm).scm}
  end

  # Frames back and forth until both sides are quiet.
  defp pump(_n, _ct, [], []), do: :ok

  defp pump(n, ct, to_sn, to_scm) do
    from_sn =
      Enum.flat_map(to_sn, fn b ->
        {:ok, out} = Node.process(n.sn, ct, b)
        out
      end)

    from_scm =
      Enum.flat_map(to_scm, fn b ->
        {:ok, out} = Node.process(n.scm, ct, b)
        out
      end)

    pump(n, ct, from_scm, from_sn)
  end

  # The SN application: always agrees.
  defp sn_app(n) do
    snmts = n.sn_snmts

    receive do
      {:opensafety_snmts, ^snmts, :calc_param_checksum} ->
        Node.pass_param_chksum_valid(n.sn, true)
        sn_app(n)

      {:opensafety_snmts, ^snmts, :switch_to_op_request} ->
        Node.enter_op_state(n.sn, true)
        sn_app(n)
    after
      0 -> :ok
    end
  end

  defp cycle(n, ct) do
    sn_app(n)
    pump(n, ct, Node.tick(n.scm, ct, 4), Node.tick(n.sn, ct, 1))
  end

  # Run 1 ms cycles from `ct` until `done?` holds; returns that time.
  defp run_until(n, ct, limit, done?) do
    cond do
      done?.() ->
        ct

      ct > limit ->
        flunk("not done by #{limit}: #{inspect(SCM.sn(n.scm_svc, 0))}")

      true ->
        cycle(n, ct)
        run_until(n, ct + 1, limit, done?)
    end
  end

  defp run_for(n, from, to), do: Enum.each(from..to, &cycle(n, &1))

  defp sn_status(n), do: elem(SCM.sn(n.scm_svc, 0), 1)

  defp scm_msgs(scm) do
    receive do
      {:opensafety_scm, ^scm, msg} -> [msg | scm_msgs(scm)]
    after
      0 -> []
    end
  end

  test "boot: SADR, SCM UDID, device check, checksum equal, operational, guarded" do
    n = start(scm_objects())
    t = run_until(n, 0, 1000, fn -> sn_status(n) == :ok end)

    assert Node.sn_state(n.sn) == :operational
    assert SCM.sn(n.scm_svc, 0) == {:wf_guard_timer, :ok}
    assert SOD.get(Node.services(n.scm).sod, 0xC400, 5) == {:ok, 129}

    # The SN learnt its address, domain and the SCM's UDID.
    sod = Node.services(n.sn).sod
    assert SOD.get(sod, 0x1C00, 1) == {:ok, @sadr}
    assert SOD.get(sod, 0x1200, 1) == {:ok, @sdn}
    assert SOD.get(sod, 0x1200, 4) == {:ok, @scm_udid}

    # Checksums were equal: no parameter download.
    assert SOD.get(sod, 0x101A, 0) == {:ok, <<>>}

    msgs = scm_msgs(n.scm_svc)
    assert {:node_status, @sadr, :missing, :valid} in msgs
    assert {:node_status, @sadr, :valid, :ok} in msgs
    assert [] == for({:error, _, _} = e <- msgs, do: e)

    # Guarding keeps the SN alive well past its life time (3 x 100).
    run_for(n, t, t + 1000)
    assert Node.sn_state(n.sn) == :operational
    assert SCM.sn(n.scm_svc, 0) |> elem(1) == :ok
    assert [] == for({:error, _, _} = e <- scm_msgs(n.scm_svc), do: e)
    refute_received {:opensafety_snmtm, _, {:error, _, _}}
    refute_received {:opensafety_ssdoc, _, {:error, _, _}}
    refute_received {:opensafety_ssdos, _, {:error, _, _}}
  end

  test "checksum differs: back to pre-op, parameter set downloaded, then operational" do
    objects =
      scm_objects(%{
        {0xC400, 14} => %{type: :domain, len: 4, default: <<0, 0, 0, 0>>},
        {0xC400, 10} => %{type: :uint32, len: 4, default: byte_size(@params)},
        {0xC400, 11} => %{type: :domain, len: 30, default: @params}
      })

    n = start(objects)
    run_until(n, 0, 2000, fn -> sn_status(n) == :ok end)

    assert Node.sn_state(n.sn) == :operational
    assert SOD.get(Node.services(n.sn).sod, 0x101A, 0) == {:ok, @params}
    # The SN's checksum was uploaded into 0xC400/15.
    {:ok, rem} = SOD.read(Node.services(n.scm).sod, {0xC400, 15})
    assert binary_part(rem, 0, 4) == @crc
  end

  test "checksum differs and no parameter set is configured: wrong parameters" do
    n = start(scm_objects(%{{0xC400, 14} => %{type: :domain, len: 4, default: <<0, 0, 0, 0>>}}))
    run_until(n, 0, 1000, fn -> sn_status(n) == :wrong_param end)
    assert {:idle2, :wrong_param} = SCM.sn(n.scm_svc, 0)
  end

  test "wrong vendor: invalid" do
    n = start(scm_objects(%{{0xC400, 2} => %{type: :uint32, len: 4, default: 0x99}}))
    run_until(n, 0, 1000, fn -> sn_status(n) == :invalid end)
    assert Node.sn_state(n.sn) == :pre_operational
  end

  test "UDID mismatch (ACM): operator acknowledges, the new UDID is taken" do
    other = <<9, 9, 9, 9, 9, 9>>

    n =
      start(scm_objects(%{{0xCC00 + @sadr, 1} => %{type: :octet_string, len: 6, default: other}}))

    scm = n.scm_svc

    # SADR assignment to the configured UDID goes unanswered; the SCM asks
    # the SN for its UDID and finds the real one.
    t = run_until(n, 0, 1000, fn -> SCM.sn(scm, 0) == {:wf_operator_ack, :udid_mismatch} end)
    assert {:udid_mismatch, @sadr, @sn_udid, 0} in scm_msgs(scm)

    # Waits for the operator.
    run_for(n, t, t + 300)
    assert SCM.sn(scm, 0) == {:wf_operator_ack, :udid_mismatch}

    assert SCM.operator_ack(scm, 0)
    run_until(n, t + 301, t + 2000, fn -> sn_status(n) == :ok end)

    assert Node.sn_state(n.sn) == :operational
    assert SOD.get(Node.services(n.scm).sod, 0xCC00 + @sadr, 1) == {:ok, @sn_udid}
  end

  test "application API refuses acknowledgements in the wrong state" do
    n = start(scm_objects())
    refute SCM.operator_ack(n.scm_svc, 0)
    refute SCM.sn_fail_ack(n.scm_svc, 0, 1, 1)
    refute SCM.operator_ack(n.scm_svc, 7)
    refute SCM.operator_ack(n.scm_svc, 500)
    msgs = scm_msgs(n.scm_svc)
    assert {:error, :param2_err, 0} in msgs
    assert {:error, :param4_err, 0} in msgs
    assert {:error, :param2_err, 7} in msgs
    assert {:error, :param1_err, 500} in msgs
  end

  test "SCM SET TO OP / SET TO STOP over SNMT, unanswered" do
    {:ok, scm} = Node.start_link(objects: scm_objects(), scm: true)
    svc = Node.services(scm).scm

    ext = fn cmd ->
      f = %OpenSafety.Frame{id: 0x2C, adr: 1, sdn: @sdn, tadr: 9, data: <<cmd>>}
      {:ok, bin} = OpenSafety.Frame.encode(f, @scm_udid)
      Node.process(scm, 0, bin)
    end

    assert SCM.state(svc) == :stopped
    assert {:ok, []} = ext.(6)
    assert SCM.state(svc) == :active
    assert {:ok, []} = ext.(4)
    assert SCM.state(svc) == :stopped
    # Processed (no response), not rejected.
    assert OpenSafety.SERR.get_common(Node.services(scm).serr, :acyc_reject) == {:ok, 0}
  end

  test "no SN configured: activation fails, stays stopped" do
    objects = Enum.reject(scm_objects(), &(&1.index == 0xC400))
    {:ok, scm} = Node.start_link(objects: objects, scm: true)
    refute Node.scm_activate(scm)
    svc = Node.services(scm).scm
    assert SCM.state(svc) == :stopped
    assert_received {:opensafety_scm, ^svc, {:error, :sod_read_err, 0}}
  end
end
