# opensafety_ex

openSAFETY safety layer in pure Elixir, written to the AtomVM subset so the
same code runs on an ESP32 and on the host. Black channel: everything
operates on binaries and is transport-agnostic.

Reference implementation: B&R openSAFETY stack 1.4 (BSD), mirrored at
`github.com/rknall/openSAFETY` (cloned to `../opensafety`). The 1.5.x
source is no longer published.

## Status

| Module             | State                                              |
|--------------------|----------------------------------------------------|
| `OpenSafety.CRC`   | CRC-8 0x2F, CRC-16 0x5935 and 0x755B               |
| `OpenSafety.Frame` | two-sub-frame encode/decode, all rx checks of SFS  |
| SPDO producer/consumer, SCT, time sync | not started                    |
| transports (UDP, ESP-NOW, UART)        | not started                    |

## Verification

* `mix test`: CRC catalogue check values, byte layout against `SFSser.c`,
  round trips for every frame class, every single-bit flip rejected.
* `scripts/wireshark_check.exs`: writes a pcap of encoded frames; tshark's
  openSAFETY dissector (independent B&R implementation) decodes them with
  both CRCs valid and no expert warnings. Command line in the script
  header.
* `test/open_safety/c_reference_test.exs` (tag `c_reference`, excluded by
  default): drives the stack's own `SFSser.c`/`SFSdeser.c`/`SFSmain.c`,
  linked unmodified into a stub harness on the `harness` branch of
  `../opensafety`. Checks byte equality of encode output, cross-decoding
  in both directions over every payload length, and that single-bit
  corruptions get the same accept/reject decision and error class.

      ../opensafety/src/harness/build.sh
      OPENSAFETY_C_HARNESS=../opensafety/src/harness/sfs_harness \
        mix test --include c_reference

## CRC-16 assignment

Long (LE > 8) frames use CRC-16 0x755B, slim SSDO uses 0x5935. That is
how `SHNF.h` in stack 1.4 binds `SHNF_Crc16Calc` and `SHNF_Crc16CalcSlim`,
and what Wireshark 4.x expects; the integration guide states the reverse.
See `OpenSafety.CRC`.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE.md`.
