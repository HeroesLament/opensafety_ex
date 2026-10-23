defmodule OpenSafety.FrameTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias OpenSafety.{CRC, Frame}

  @udid <<0x00, 0x60, 0x65, 0x01, 0x02, 0x03>>

  defp spdo(data, overrides \\ []) do
    struct!(
      %Frame{id: 0x31, adr: 0x123, sdn: 0x2A5, ct: 0xBEEF, tadr: 0, tr: 0, data: data},
      overrides
    )
  end

  defp roundtrip(frame, opts \\ []) do
    {:ok, bin} = Frame.encode(frame, @udid, opts)
    assert byte_size(bin) == Frame.frame_length(byte_size(frame.data), frame.id)
    {:ok, decoded} = Frame.decode(bin, @udid, opts)
    {bin, decoded}
  end

  describe "round trip" do
    test "short SPDO (CRC-8)" do
      f = spdo(<<1, 2, 3, 4>>)
      {_bin, d} = roundtrip(f)
      assert d == f
    end

    test "SPDO with empty payload: the UDID XOR reaches SF2's CRC byte" do
      f = spdo(<<>>)
      {bin, d} = roundtrip(f)
      assert d == f
      assert byte_size(bin) == 11
    end

    test "boundary payloads 8 (CRC-8) and 9 (CRC-16)" do
      for le <- [8, 9] do
        f = spdo(:binary.copy(<<0xA5>>, le))
        {bin, d} = roundtrip(f)
        assert d == f
        assert byte_size(bin) == if(le == 8, do: 27, else: 31)
      end
    end

    test "maximum payload 254" do
      f = spdo(:crypto.strong_rand_bytes(254))
      {bin, d} = roundtrip(f)
      assert d == f
      assert byte_size(bin) == 4 + 5 + 4 + 2 * 254
    end

    test "SPDO time request carries TADR and TR" do
      f = spdo(<<9, 8, 7>>, id: 0x32, tadr: 0x3FE, tr: 0x2B)
      {_bin, d} = roundtrip(f)
      assert d == f
    end

    test "SNMT frames skip the UDID XOR" do
      f = %Frame{id: 0x28, adr: 5, sdn: 1, ct: 0, tadr: 1, tr: 0, data: <<>>}
      {:ok, bin} = Frame.encode(f, @udid)
      assert {:ok, ^f} = Frame.decode(bin, <<0, 0, 0, 0, 0, 0>>)
    end

    test "non-SNMT frames depend on the SCM UDID" do
      {:ok, bin} = Frame.encode(spdo(<<1>>), @udid)
      assert {:error, _} = Frame.decode(bin, <<1, 2, 3, 4, 5, 6>>)
    end

    test "slim SSDO: payload once, CRC-16 0x755B when long" do
      for le <- [3, 20] do
        f = %Frame{
          id: 0x3A,
          adr: 7,
          sdn: 1,
          ct: 1,
          tadr: 9,
          tr: 0,
          data: :binary.copy(<<0x5A>>, le)
        }

        {bin, d} = roundtrip(f)
        assert d == f
        assert byte_size(bin) == 4 + 5 + 2 * if(le > 8, do: 2, else: 1) + le
      end
    end

    test "frame2_first option" do
      f = spdo(:crypto.strong_rand_bytes(12))
      {bin, d} = roundtrip(f, frame2_first: true)
      assert d == f
      {:ok, default_order} = Frame.encode(f, @udid)
      assert bin != default_order
    end
  end

  describe "byte layout" do
    test "SF1 header and CRC-8 are where SFSser.c puts them" do
      f = spdo(<<0x11, 0x22>>)
      {:ok, bin} = Frame.encode(f, @udid)
      <<sf1::binary-size(7), sf2_coded::binary>> = bin

      # ADR low byte, ID<<2 | ADR bits 8..9 (0x31<<2 | 0x01 = 0xC5), LE, CT low byte
      assert <<0x23, 0xC5, 2, 0xEF, 0x11, 0x22, crc1>> = sf1
      assert crc1 == CRC.crc8(binary_part(sf1, 0, 6))

      # Undo the UDID XOR on SF2 by hand
      <<c::binary-size(6), tail::binary>> = sf2_coded
      sf2 = :crypto.exor(c, @udid) <> tail
      sdn_lo = 0x2A5 &&& 0xFF
      sdn_hi = 0x2A5 >>> 8
      assert <<a, i, 0xBE, 0, 0, 0x11, 0x22, crc2>> = sf2
      assert a == bxor(0x23, sdn_lo)
      assert i == bxor(0x31 <<< 2 ||| 0x01, sdn_hi)
      assert crc2 == CRC.crc8(binary_part(sf2, 0, 7))
    end

    test "CRC-16 is little-endian on the wire" do
      f = spdo(:binary.copy(<<0x33>>, 9))
      {:ok, bin} = Frame.encode(f, @udid)
      sf1 = binary_part(bin, 0, 4 + 9 + 2)
      <<body::binary-size(13), crc::little-16>> = sf1
      assert crc == CRC.crc16_b(body)
    end

    test "long slim SSDO uses CRC-16 0x5935 (SHNF_Crc16CalcSlim)" do
      f = %Frame{id: 0x3A, adr: 7, sdn: 1, ct: 1, tadr: 9, data: :binary.copy(<<1>>, 20)}
      {:ok, bin} = Frame.encode(f, @udid)
      <<body::binary-size(24), crc::little-16, _::binary>> = bin
      assert crc == CRC.crc16_a(body)
    end
  end

  describe "rejection" do
    setup do
      {:ok, bin} = Frame.encode(spdo(<<1, 2, 3, 4, 5>>), @udid)
      %{bin: bin}
    end

    test "every single-bit flip is caught", %{bin: bin} do
      for byte <- 0..(byte_size(bin) - 1), bit <- 0..7 do
        <<pre::binary-size(byte), b, post::binary>> = bin
        flipped = <<pre::binary, bxor(b, 1 <<< bit), post::binary>>
        assert {:error, _} = Frame.decode(flipped, @udid), "flip byte #{byte} bit #{bit} accepted"
      end
    end

    test "truncated and padded frames", %{bin: bin} do
      assert {:error, {:length, _, _}} =
               Frame.decode(binary_part(bin, 0, byte_size(bin) - 1), @udid)

      assert {:error, {:length, _, _}} = Frame.decode(bin <> <<0>>, @udid)
      assert {:error, :too_short} = Frame.decode(<<1, 2>>, @udid)
    end

    test "sub frames with valid CRCs but different payloads" do
      # Build SF2 from a different payload, then stitch with SF1 of the original.
      {:ok, a} = Frame.encode(spdo(<<1, 2, 3>>), @udid)
      {:ok, b} = Frame.encode(spdo(<<1, 2, 4>>), @udid)
      stitched = binary_part(a, 0, 8) <> binary_part(b, 8, byte_size(b) - 8)
      assert {:error, :data_mismatch} = Frame.decode(stitched, @udid)
    end

    test "TADR 0 is only legal for SPDO data-only" do
      for id <- [0x30, 0x31] do
        {:ok, bin} = Frame.encode(spdo(<<1>>, id: id, tadr: 0), @udid)
        assert {:ok, _} = Frame.decode(bin, @udid)
      end

      {:ok, bin} = Frame.encode(spdo(<<1>>, id: 0x32, tadr: 0), @udid)
      assert {:error, {:bad_tadr, 0}} = Frame.decode(bin, @udid)
    end
  end

  describe "encode header checks (checkTxFrameHeader)" do
    test "out-of-range fields" do
      assert {:error, {:bad_sadr, 0}} = Frame.encode(spdo(<<>>, adr: 0), @udid)
      assert {:error, {:bad_sadr, 0x400}} = Frame.encode(spdo(<<>>, adr: 0x400), @udid)
      assert {:error, {:bad_id, 0x36}} = Frame.encode(spdo(<<>>, id: 0x36), @udid)
      assert {:error, {:bad_sdn, 0}} = Frame.encode(spdo(<<>>, sdn: 0), @udid)
      assert {:error, {:bad_tadr, 0x400}} = Frame.encode(spdo(<<>>, tadr: 0x400), @udid)
      assert {:error, {:bad_tr, 0x40}} = Frame.encode(spdo(<<>>, tr: 0x40), @udid)
      assert {:error, {:bad_le, _}} = Frame.encode(spdo(:binary.copy(<<0>>, 255)), @udid)
    end
  end
end
