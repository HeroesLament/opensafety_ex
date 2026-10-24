defmodule OpenSafety.SPDOTest do
  use ExUnit.Case, async: true

  alias OpenSafety.SPDO

  @udid <<0x00, 0x60, 0x65, 0x01, 0x02, 0x03>>
  @sdn 1

  # Times in CT ticks.
  @delay 2
  @pendant_offset 1000

  # Controller: consumes the pendant's SPDO (SADR 2) and sends its TReqs on
  # its own Tx SPDO (SADR 1). Consumer only, so no TRes from it.
  defp controller do
    {:ok, pid} =
      SPDO.start_link(
        sdn: @sdn,
        scm_udid: @udid,
        tx: [%{sadr: 1, refresh_prescale: 10, no_tres: 0, len: 0}],
        rx: [
          %{
            sadr: 2,
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
            tx_spdo_no: 1,
            len: 2
          }
        ]
      )

    pid
  end

  # Pendant: produces two bytes on SADR 2 and answers one TRes per TReq.
  defp pendant do
    {:ok, pid} =
      SPDO.start_link(
        sdn: @sdn,
        scm_udid: @udid,
        tx: [%{sadr: 2, refresh_prescale: 5, no_tres: 1, len: 2}]
      )

    pid
  end

  # Advance both nodes from ct `from` to `to`, delivering each frame `@delay`
  # ticks after it was built. `silent` stops the pendant transmitting from
  # that tick on. Returns frames still in flight.
  defp run(ctl, pen, from, to, in_flight \\ [], silent \\ nil) do
    Enum.reduce(from..to, in_flight, fn ct, flight ->
      {due, flight} = Enum.split_with(flight, fn {at, _, _} -> at == ct end)

      Enum.each(due, fn
        {_, :to_ctl, bin} -> :ok = SPDO.process(ctl, ct, bin)
        {_, :to_pen, bin} -> :ok = SPDO.process(pen, ct + @pendant_offset, bin)
      end)

      to_pen = SPDO.build(ctl, ct)

      to_ctl =
        if silent && ct >= silent, do: [], else: SPDO.build(pen, ct + @pendant_offset)

      :ok = SPDO.check_timeout(ctl, ct)

      flight ++
        Enum.map(to_pen, &{ct + @delay, :to_pen, &1}) ++
        Enum.map(to_ctl, &{ct + @delay, :to_ctl, &1})
    end)
  end

  defp events(ctl) do
    receive do
      {:opensafety_spdo, ^ctl, no, ev} -> [{no, ev} | events(ctl)]
    after
      0 -> []
    end
  end

  setup do
    ctl = controller()
    pen = pendant()
    :ok = SPDO.set_to_op(ctl, 0)
    :ok = SPDO.set_to_op(pen, @pendant_offset)
    %{ctl: ctl, pen: pen}
  end

  test "time sync, then valid data within the propagation window", %{ctl: ctl, pen: pen} do
    :ok = SPDO.put_data(pen, 1, <<0xAB, 0xCD>>)
    run(ctl, pen, 0, 40)

    ev = events(ctl)
    assert {1, {:data, <<0xAB, 0xCD>>}} in ev
    refute Enum.any?(ev, &match?({_, {:error, _, _}}, &1))

    assert {:ok, %{data: <<0xAB, 0xCD>>, prop_delay: 4}} = SPDO.rx_status(ctl, 1, 40)
  end

  test "the first frame after sync only seeds the CT check", %{ctl: ctl, pen: pen} do
    # TReq at 0, TRes built by the pendant at 2, received at 4: synced at 4.
    run(ctl, pen, 0, 4)
    assert events(ctl) == []
    assert SPDO.rx_status(ctl, 1, 4) == :invalid
  end

  test "SCT expiry when the producer goes silent", %{ctl: ctl, pen: pen} do
    flight = run(ctl, pen, 0, 40)
    assert {:ok, _} = SPDO.rx_status(ctl, 1, 40)
    _ = events(ctl)

    run(ctl, pen, 41, 120, flight, 41)

    ev = events(ctl)
    assert {1, :safe_state} in ev
    assert {1, {:error, :sct_timer, 0}} in ev
    assert SPDO.rx_status(ctl, 1, 120) == :invalid
  end

  test "connection-valid bit follows the consumer's time sync", %{ctl: ctl} do
    # Before sync the controller's TReq carries no connection-valid bit.
    [treq] = SPDO.build(ctl, 0)
    {:ok, f} = OpenSafety.Frame.decode(treq, @udid)
    assert f.id == 0x32
    assert f.tadr == 2
  end

  test "pre-operational ignores frames and builds nothing" do
    ctl = controller()
    assert SPDO.build(ctl, 0) == []
    assert SPDO.check_timeout(ctl, 100) == :ok
  end
end
