defmodule OpenSafety.SPDO.Time do
  @moduledoc """
  Consecutive-time arithmetic, as the C stack does it.

  CT is a free-running 32-bit counter supplied by the caller (`dw_ct` in
  the C API); frames carry its low 16 bits. All comparisons are modular so
  the counter may wrap.
  """

  import Bitwise

  @doc "Truncate to 32 bits."
  def u32(x), do: x &&& 0xFFFF_FFFF

  @doc "Truncate to 16 bits."
  def u16(x), do: x &&& 0xFFFF

  @doc """
  `EPLS_TIMEOUT(act, to)` from EPLStypes.h: true once `act` has reached
  `to`, modulo 2^32.
  """
  def timeout?(act, to), do: u32(act - to) < 0x8000_0000

  @doc """
  `CT_VALID(act, last)` from SPDOrxConsSm.c: `act` is ahead of `last`,
  modulo 2^16.
  """
  def ct_ahead?(act, last), do: u16(act - last) < 0x8000
end
