# Cross-check the codec against Wireshark's openSAFETY dissector.
#
# Encodes a spread of frames, one per UDP datagram to port 9877 (the
# dissector's default openSAFETY/UDP port), and writes them to a pcap. Then
# run tshark over it with the same SCM UDID and read back what the
# dissector decoded and whether it accepted both CRCs:
#
#   mix run scripts/wireshark_check.exs /tmp/opensafety_check.pcap
#   tshark -r /tmp/opensafety_check.pcap \
#     -o opensafety.scm_udid:00:60:65:01:02:03 -o opensafety.scm_udid_autoset:FALSE \
#     -o opensafety.classify_transport:FALSE \
#     -T fields -E header=y -e frame.number -e opensafety.msg.id \
#     -e opensafety.msg.sender -e opensafety.msg.receiver -e opensafety.length \
#     -e opensafety.crc.valid -e opensafety.crc2.valid -e opensafety.spdo.ct \
#     -e _ws.expert.message
#
# classify_transport must be off: the UDP entry point hands frames to the
# package dissector as acyclic data, and with classification on it drops
# every SPDO as misclassified (SPDOs are cyclic). SNMT/SSDO show up either
# way.
#
# Expect no expert messages. Wireshark tries CRC-16 0x755B first and warns
# "Frame 1 SPDO CRC is Slim SSDO CRC16 0x5935" if a regular frame carries
# the slim polynomial.
#
# The dissector is an independent implementation (B&R, GPL, in Wireshark
# since 1.6), so agreement here is the cross-language wire-format proof.

alias OpenSafety.Frame

import Bitwise

path = List.first(System.argv()) || "/tmp/opensafety_check.pcap"
udid = <<0x00, 0x60, 0x65, 0x01, 0x02, 0x03>>

frames = [
  {"SPDO data-only, LE 0, TADR 0", %Frame{id: 0x30, adr: 0x011, sdn: 1, ct: 0x0102, data: <<>>}},
  {"SPDO conn-valid, LE 4",
   %Frame{id: 0x31, adr: 0x123, sdn: 0x2A5, ct: 0xBEEF, data: <<1, 2, 3, 4>>}},
  {"SPDO LE 8 (last CRC-8)",
   %Frame{id: 0x31, adr: 0x3FF, sdn: 0x3FF, ct: 0xFFFF, data: :binary.copy(<<0xA5>>, 8)}},
  {"SPDO LE 9 (first CRC-16)",
   %Frame{id: 0x31, adr: 2, sdn: 3, ct: 4, data: :binary.copy(<<0x5A>>, 9)}},
  {"SPDO LE 254",
   %Frame{id: 0x30, adr: 0x200, sdn: 0x100, ct: 0x8000, data: :binary.copy(<<0x3C>>, 254)}},
  {"SPDO time request",
   %Frame{id: 0x32, adr: 0x045, sdn: 7, ct: 0x1234, tadr: 0x3FE, tr: 0x2B, data: <<9, 8, 7>>}},
  {"SPDO time response",
   %Frame{id: 0x34, adr: 0x046, sdn: 7, ct: 0x1235, tadr: 0x045, tr: 0x2B, data: <<0, 0, 0, 0>>}},
  {"SNMT request UDID", %Frame{id: 0x28, adr: 5, sdn: 1, ct: 0, tadr: 1, data: <<>>}},
  {"SSDO service request, LE 12",
   %Frame{
     id: 0x38,
     adr: 6,
     sdn: 1,
     ct: 2,
     tadr: 1,
     data: <<0x20, 0x00, 0x18, 0x10, 0x01>> <> :binary.copy(<<0>>, 7)
   }},
  {"slim SSDO request, LE 3", %Frame{id: 0x3A, adr: 7, sdn: 1, ct: 1, tadr: 9, data: <<0x20, 0, 0>>}},
  {"slim SSDO request, LE 20",
   %Frame{id: 0x3A, adr: 7, sdn: 1, ct: 1, tadr: 9, data: :binary.copy(<<0x11>>, 20)}}
]

ip_checksum = fn header ->
  sum =
    for <<word::16 <- header>>, reduce: 0 do
      acc -> acc + word
    end

  sum = (sum &&& 0xFFFF) + (sum >>> 16)
  sum = (sum &&& 0xFFFF) + (sum >>> 16)
  bxor(sum, 0xFFFF)
end

datagram = fn payload ->
  udp_len = 8 + byte_size(payload)
  udp = <<9877::16, 9877::16, udp_len::16, 0::16, payload::binary>>
  total = 20 + udp_len
  hdr = <<0x45, 0, total::16, 0::16, 0::16, 64, 17, 0::16, 10, 0, 0, 1, 10, 0, 0, 2>>
  <<pre::binary-size(10), 0::16, post::binary>> = hdr
  <<pre::binary, ip_checksum.(hdr)::16, post::binary, udp::binary>>
end

# pcap, little-endian, LINKTYPE_RAW (101): records start at the IPv4 header.
global =
  <<0xA1B2C3D4::little-32, 2::little-16, 4::little-16, 0::little-32, 0::little-32,
    65535::little-32, 101::little-32>>

records =
  frames
  |> Enum.with_index(1)
  |> Enum.map(fn {{label, frame}, n} ->
    {:ok, bin} = Frame.encode(frame, udid)
    {:ok, ^frame} = Frame.decode(bin, udid)
    IO.puts("#{String.pad_leading(Integer.to_string(n), 2)}  #{label}  (#{byte_size(bin)} bytes)")
    pkt = datagram.(bin)

    <<n::little-32, 0::little-32, byte_size(pkt)::little-32, byte_size(pkt)::little-32,
      pkt::binary>>
  end)

File.write!(path, [global | records])
IO.puts("wrote #{length(frames)} frames to #{path}")
