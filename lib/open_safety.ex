defmodule OpenSafety do
  @moduledoc """
  openSAFETY safety layer in pure Elixir.

  Black-channel protocol: everything here is transport-agnostic and
  operates on binaries. Written to the AtomVM subset (binaries, Bitwise,
  tuples, maps; no OTP-only modules) so the same code runs on an ESP32 and
  on the host.

  * `OpenSafety.CRC` - CRC-8 and the two CRC-16 frame checksums.
  * `OpenSafety.Frame` - two-sub-frame encode/decode and verification.

  Reference implementation: the B&R openSAFETY stack 1.4 (BSD), mirrored
  at github.com/rknall/openSAFETY.
  """
end
