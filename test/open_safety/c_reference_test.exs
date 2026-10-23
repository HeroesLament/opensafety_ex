defmodule OpenSafety.CReferenceTest do
  @moduledoc """
  Cross-check `OpenSafety.Frame` against the B&R stack's own SFS code.

  Needs the harness from the `harness` branch of the C reference repo
  (`../opensafety`, `src/harness/build.sh`), pointed to by
  `OPENSAFETY_C_HARNESS`:

      OPENSAFETY_C_HARNESS=../opensafety/src/harness/sfs_harness mix test --include c_reference

  The harness links SFSser.c, SFSdeser.c and SFSmain.c unmodified and
  stubs only SOD, SERR and SHNF, so encode bytes, accept/reject decisions
  and error classes all come from the stack itself.
  """

  use ExUnit.Case, async: false

  import Bitwise

  alias OpenSafety.Frame

  @moduletag :c_reference

  @udid <<0x00, 0x60, 0x65, 0x01, 0x02, 0x03>>
  @ids [0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2F] ++
         [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x38, 0x39, 0x3A, 0x3B]

  # SFSerr.h codes (values from the 1.4 build) to Frame.decode error classes.
  @c_errors %{
    0x2301 => :length,
    0x2302 => :length,
    0x2303 => :length,
    0x2304 => :id_mismatch,
    0x2306 => :data_mismatch,
    0x2307 => :crc1,
    0x2308 => :crc1,
    0x2309 => :crc2,
    0x230A => :crc2,
    0x230D => :bad_sadr,
    0x230E => :bad_sdn,
    0x2318 => :bad_tadr
  }

  # Per-test, not setup_all: port replies go to the owning process, and
  # setup_all runs in a different one from the tests.
  setup do
    case System.get_env("OPENSAFETY_C_HARNESS") do
      nil ->
        raise "set OPENSAFETY_C_HARNESS to the built sfs_harness binary"

      path ->
        port =
          Port.open({:spawn_executable, Path.expand(path)}, [:binary, :use_stdio, {:line, 8192}])

        "ok" = call(port, "udid " <> Base.encode16(@udid, case: :lower))
        %{port: port}
    end
  end

  defp call(port, line) do
    Port.command(port, line <> "\n")

    receive do
      {^port, {:data, {:eol, reply}}} -> reply
    after
      2_000 -> raise "harness timeout on: #{line}"
    end
  end

  defp hex(<<>>), do: "-"
  defp hex(bin), do: Base.encode16(bin, case: :lower)
  defp unhex("-"), do: <<>>
  defp unhex(s), do: Base.decode16!(s, case: :mixed)

  defp c_encode(port, f) do
    fields = Enum.map([f.id, f.adr, f.sdn, f.ct, f.tadr, f.tr], &Integer.to_string(&1, 16))

    case String.split(call(port, Enum.join(["enc" | fields] ++ [hex(f.data)], " "))) do
      ["ok", frame] -> {:ok, unhex(frame)}
      ["err", code, _add] -> {:error, String.to_integer(code, 16)}
    end
  end

  defp c_decode(port, bin) do
    case String.split(call(port, "dec " <> hex(bin))) do
      ["ok", id, adr, sdn, ct, tadr, tr, data] ->
        [id, adr, sdn, ct, tadr, tr] =
          Enum.map([id, adr, sdn, ct, tadr, tr], &String.to_integer(&1, 16))

        {:ok, %Frame{id: id, adr: adr, sdn: sdn, ct: ct, tadr: tadr, tr: tr, data: unhex(data)}}

      ["err", code, _add] ->
        {:error, String.to_integer(code, 16)}
    end
  end

  # Random frame the receive path will accept: TADR 0 only on SPDO data-only.
  defp random_frame(le) do
    id = Enum.random(@ids)
    tadr_min = if (id &&& 0x3E) == 0x30, do: 0, else: 1

    %Frame{
      id: id,
      adr: Enum.random(1..0x3FF),
      sdn: Enum.random(1..0x3FF),
      ct: Enum.random(0..0xFFFF),
      tadr: Enum.random(tadr_min..0x3FF),
      tr: Enum.random(0..0x3F),
      data: :crypto.strong_rand_bytes(le)
    }
  end

  defp frames do
    # Every payload length at least twice, plus a random spread.
    lengths =
      Enum.to_list(0..254) ++ Enum.to_list(0..254) ++ for(_ <- 1..500, do: Enum.random(0..254))

    Enum.map(lengths, &random_frame/1)
  end

  defp class({:error, {tag, _}}), do: tag
  defp class({:error, {tag, _, _}}), do: tag
  defp class({:error, tag}), do: tag

  test "C transmit buffer equals Frame.encode with frame2_first", %{port: port} do
    for f <- frames() do
      assert {:ok, c_bin} = c_encode(port, f)
      assert {:ok, ^c_bin} = Frame.encode(f, @udid, frame2_first: true), inspect(f)
    end
  end

  test "Frame.decode accepts the C transmit buffer", %{port: port} do
    for f <- frames() do
      {:ok, c_bin} = c_encode(port, f)
      assert {:ok, ^f} = Frame.decode(c_bin, @udid, frame2_first: true)
    end
  end

  test "SFS_FrmDeSerialize accepts Frame.encode output (SF1 first)", %{port: port} do
    for f <- frames() do
      {:ok, bin} = Frame.encode(f, @udid)
      assert {:ok, ^f} = c_decode(port, bin), inspect(f)
    end
  end

  test "transmit header checks reject the same inputs", %{port: port} do
    bad = [
      %Frame{id: 0x31, adr: 0, sdn: 1, data: <<>>},
      %Frame{id: 0x31, adr: 0x400, sdn: 1, data: <<>>},
      %Frame{id: 0x36, adr: 1, sdn: 1, data: <<>>},
      %Frame{id: 0x31, adr: 1, sdn: 0, data: <<>>},
      %Frame{id: 0x31, adr: 1, sdn: 0x400, data: <<>>},
      %Frame{id: 0x31, adr: 1, sdn: 1, tadr: 0x400, data: <<>>},
      %Frame{id: 0x31, adr: 1, sdn: 1, tr: 0x40, data: <<>>}
    ]

    for f <- bad do
      assert {:error, _} = c_encode(port, f), inspect(f)
      assert {:error, _} = Frame.encode(f, @udid), inspect(f)
    end
  end

  test "single-bit corruption: same accept/reject decision and error class", %{port: port} do
    for f <- Enum.take_random(frames(), 120), byte_size(f.data) <= 40 do
      {:ok, bin} = Frame.encode(f, @udid)

      for byte <- 0..(byte_size(bin) - 1) do
        bit = Enum.random(0..7)
        <<pre::binary-size(byte), b, post::binary>> = bin
        mutated = <<pre::binary, bxor(b, 1 <<< bit), post::binary>>

        ours = Frame.decode(mutated, @udid)
        theirs = c_decode(port, mutated)
        where = "#{inspect(f)} byte #{byte} bit #{bit}"

        case {ours, theirs} do
          {{:ok, a}, {:ok, b}} ->
            assert a == b, where

          {{:error, {:bad_id, _}}, {:error, _}} ->
            # Our extra check fires first; the stack still rejects.
            :ok

          {{:error, _} = e, {:error, code}} ->
            assert class(e) == Map.fetch!(@c_errors, code), where

          other ->
            flunk("decision differs: #{inspect(other)} at #{where}")
        end
      end
    end
  end

  test "truncated and extended frames are rejected by both", %{port: port} do
    for f <- Enum.take_random(frames(), 100) do
      {:ok, bin} = Frame.encode(f, @udid)

      for mutated <- [binary_part(bin, 0, byte_size(bin) - 1), bin <> <<0>>] do
        assert {:error, {:length, _, _}} = Frame.decode(mutated, @udid)
        assert {:error, code} = c_decode(port, mutated)
        assert Map.fetch!(@c_errors, code) == :length
      end
    end
  end
end
