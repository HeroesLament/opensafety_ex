defmodule OpenSafety.CRCTest do
  use ExUnit.Case, async: true

  alias OpenSafety.CRC

  # Catalogue check values (CRC over ASCII "123456789"), from the reveng
  # catalogue as carried by the Rust `crc` crate: CRC_8_OPENSAFETY,
  # CRC_16_OPENSAFETY_A, CRC_16_OPENSAFETY_B.
  @check "123456789"

  test "CRC-8/OPENSAFETY check value" do
    assert CRC.crc8(@check) == 0x3E
  end

  test "CRC-16/OPENSAFETY-A check value" do
    assert CRC.crc16_a(@check) == 0x5D38
  end

  test "CRC-16/OPENSAFETY-B check value" do
    assert CRC.crc16_b(@check) == 0x20FE
  end

  test "single-byte CRC-16 matches the head of Wireshark's 0x5935 table" do
    # crc16_precompiled_5935 in wsutil: 0x0000, 0x5935, 0xB26A, 0xEB5F, 0x3DE1, ...
    assert Enum.map(0..4, &CRC.crc16_a(<<&1>>)) == [0x0000, 0x5935, 0xB26A, 0xEB5F, 0x3DE1]
  end

  test "empty input is zero for all three" do
    assert {CRC.crc8(<<>>), CRC.crc16_a(<<>>), CRC.crc16_b(<<>>)} == {0, 0, 0}
  end

  test "a message followed by its CRC has zero remainder" do
    msg = :crypto.strong_rand_bytes(40)
    assert CRC.crc8(msg <> <<CRC.crc8(msg)>>) == 0
    assert CRC.crc16_a(msg <> <<CRC.crc16_a(msg)::16>>) == 0
    assert CRC.crc16_b(msg <> <<CRC.crc16_b(msg)::16>>) == 0
  end
end
