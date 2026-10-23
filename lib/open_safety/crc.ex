defmodule OpenSafety.CRC do
  @moduledoc """
  The three openSAFETY frame checksums.

  All three are plain MSB-first CRCs: init 0, no input or output
  reflection, no final XOR. They match the reveng catalogue entries
  CRC-8/OPENSAFETY, CRC-16/OPENSAFETY-A and CRC-16/OPENSAFETY-B.

  | function    | poly   | reveng name           |
  |-------------|--------|-----------------------|
  | `crc8/1`    | 0x2F   | CRC-8/OPENSAFETY      |
  | `crc16_a/1` | 0x5935 | CRC-16/OPENSAFETY-A   |
  | `crc16_b/1` | 0x755B | CRC-16/OPENSAFETY-B   |

  CRC-8 covers sub frames with payload 0..8 bytes. Long (9..254 byte)
  frames use CRC-16 B (0x755B), except slim SSDO which uses CRC-16 A
  (0x5935). `OpenSafety.Frame` makes that choice; this module only
  computes.

  Provenance. The stack does not implement its frame CRCs; SFS calls
  `SHNF_Crc8Calc`, `SHNF_Crc16Calc` and `SHNF_Crc16CalcSlim`, which the
  integrator supplies. `SHNF.h` (1.4) binds them by name:

      #define SHNF_Crc16Calc(a,b,c)      HNFiff_Crc16_755B_CalcSwp(a,b,c)
      #define SHNF_Crc16CalcSlim(a,b,c)  HNFiff_Crc16CalcSwp(a,b,c)

  so regular frames are 0x755B, and slim takes the other openSAFETY
  CRC-16, 0x5935. Wireshark 4.x agrees: it tries 0x755B first and labels
  0x5935 "Slim SSDO CRC16". The integration guide pairs the two the other
  way round; the header is what compiles. 0x5935 on regular frames is the
  pre-2011 protocol (Wireshark's original dissector, and SFS's 2011
  "changes for new CRC polynomial").

  Not to be confused with `src/tools/oschecksum` in the C distribution,
  which defines `CRC16_POLY 0xBAAD` and `0xAC9A`. Those are the same two
  polynomials written in Koopman notation (0xBAAD = 0x755B, 0xAC9A =
  0x5935), but oschecksum's code XORs them in as if they were normal
  form, so its CRC-16 equals neither frame CRC. It is the parameter
  checksum tool, not the wire CRC.

  Tables are built at compile time and stored as tuples so lookup is
  `elem/2`, which AtomVM supports.
  """

  import Bitwise

  @crc8_poly 0x2F
  @crc16_poly 0x5935
  @crc16_slim_poly 0x755B

  # Table entry i is the CRC of the single byte i: the byte shifted
  # through the register eight times.
  crc8_entry = fn poly ->
    fn i ->
      Enum.reduce(1..8, i, fn _, crc ->
        if (crc &&& 0x80) != 0 do
          bxor(crc <<< 1, poly) &&& 0xFF
        else
          crc <<< 1 &&& 0xFF
        end
      end)
    end
  end

  crc16_entry = fn poly ->
    fn i ->
      Enum.reduce(1..8, i <<< 8, fn _, crc ->
        if (crc &&& 0x8000) != 0 do
          bxor(crc <<< 1, poly) &&& 0xFFFF
        else
          crc <<< 1 &&& 0xFFFF
        end
      end)
    end
  end

  @crc8_table List.to_tuple(Enum.map(0..255, crc8_entry.(@crc8_poly)))
  @crc16_table List.to_tuple(Enum.map(0..255, crc16_entry.(@crc16_poly)))
  @crc16_slim_table List.to_tuple(Enum.map(0..255, crc16_entry.(@crc16_slim_poly)))

  @doc "CRC-8, poly 0x2F."
  @spec crc8(binary()) :: 0..0xFF
  def crc8(bin) when is_binary(bin), do: crc8(bin, 0)

  defp crc8(<<>>, crc), do: crc
  defp crc8(<<b, rest::binary>>, crc), do: crc8(rest, elem(@crc8_table, bxor(b, crc)))

  @doc "CRC-16/OPENSAFETY-A, poly 0x5935."
  @spec crc16_a(binary()) :: 0..0xFFFF
  def crc16_a(bin) when is_binary(bin), do: crc16(bin, 0, @crc16_table)

  @doc "CRC-16/OPENSAFETY-B, poly 0x755B."
  @spec crc16_b(binary()) :: 0..0xFFFF
  def crc16_b(bin) when is_binary(bin), do: crc16(bin, 0, @crc16_slim_table)

  defp crc16(<<>>, crc, _table), do: crc

  defp crc16(<<b, rest::binary>>, crc, table) do
    idx = bxor(b, crc >>> 8)
    crc16(rest, bxor(crc <<< 8 &&& 0xFFFF, elem(table, idx)), table)
  end
end
