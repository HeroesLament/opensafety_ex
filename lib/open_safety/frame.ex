defmodule OpenSafety.Frame do
  @moduledoc """
  openSAFETY frame codec: one frame is two redundant sub frames.

  Mirrors `SFS_FrmSerialize` (`SFSser.c`) and `SFS_FrmDeSerialize`
  (`SFSdeser.c`) from the B&R stack 1.4. Pure function, no state: SPDO
  timing, consecutive time bookkeeping and the SCT watchdog live a layer
  up.

  ## Wire layout

  Sub frame ONE, then sub frame TWO (the default; see `:frame2_first`).

      SF1:  ADR_lo | ID<<2 | ADR_hi | LE | CT_lo | DATA[LE] | CRC1
      SF2:  ADR_lo ^ SDN_lo | (ID<<2 | ADR_hi) ^ SDN_hi | CT_hi |
            TADR_lo | TR<<2 | TADR_hi | DATA[LE] | CRC2

  * ADR (SADR) and TADR are 10 bit, SDN 10 bit, ID and TR 6 bit, CT 16 bit
    split across the two sub frames.
  * CRC is CRC-8 when LE <= 8, else CRC-16 little-endian on the wire
    (`SFS_NET_CPY16`).
  * Long frames use CRC-16 0x755B, except slim SSDO which uses 0x5935
    (`OpenSafety.CRC` has the provenance).
  * Slim SSDO (ID 0x3A, 0x3B) carries DATA only in SF1; SF2 is header plus
    CRC.
  * After SF2's CRC is computed, its first six bytes are XORed with the
    six-byte UDID of the SCM (`SFS_ScmUdidCode`), except for SNMT frames
    (ID & 0x38 == 0x28). With LE = 0 the sixth byte is SF2's CRC.

  The C stack hands SHNF a transmit buffer with SF2 before SF1 ("twisted
  in tx dir"; confirmed by the harness on the `harness` branch of the C
  repo), while `SFS_FrmDeSerialize` and Wireshark's UDP dissector expect
  SF1 first. Pass `frame2_first: true` to produce or accept the stack's
  own transmit order.

  ## Deviation from the C stack

  `decode/3` rejects frame IDs outside the valid set. The C receive path
  leaves that to the dispatcher (SSC); a codec that refuses unknown IDs up
  front costs nothing and removes one way for garbage to reach a state
  machine.
  """

  import Bitwise

  alias OpenSafety.CRC

  @enforce_keys [:id, :adr, :sdn]
  defstruct id: nil, adr: nil, sdn: nil, ct: 0, tadr: 0, tr: 0, data: <<>>

  @type t :: %__MODULE__{
          id: 0..0x3F,
          adr: 1..0x3FF,
          sdn: 1..0x3FF,
          ct: 0..0xFFFF,
          tadr: 0..0x3FF,
          tr: 0..0x3F,
          data: binary()
        }

  @type udid :: <<_::48>>

  @type decode_error ::
          :too_short
          | {:length, expected :: non_neg_integer(), got :: non_neg_integer()}
          | {:bad_id, 0..0x3F}
          | {:bad_sadr, non_neg_integer()}
          | {:id_mismatch, 0..0x3F, 0..0x3F}
          | {:bad_sdn, non_neg_integer()}
          | {:bad_tadr, non_neg_integer()}
          | :crc1
          | :crc2
          | :data_mismatch

  @max_le 0xFE
  @max_le_short 8

  # Valid 6-bit frame IDs, from ao_LookUpFrmId in SFSser.c.
  @ids %{
    0x28 => :snmt_request_udid,
    0x29 => :snmt_response_udid,
    0x2A => :snmt_assign_sadr,
    0x2B => :snmt_sadr_assigned,
    0x2C => :snmt_service_request,
    0x2D => :snmt_service_response,
    0x2F => :snmt_sn_reset_guarding_scm,
    0x30 => :spdo_data_only,
    0x31 => :spdo_data_only_conn_valid,
    0x32 => :spdo_time_request,
    0x33 => :spdo_time_request_conn_valid,
    0x34 => :spdo_time_response,
    0x35 => :spdo_time_response_conn_valid,
    0x38 => :ssdo_service_request,
    0x39 => :ssdo_service_response,
    0x3A => :ssdo_slim_service_request,
    0x3B => :ssdo_slim_service_response
  }

  @doc "Name of a frame ID, or `nil` if the ID is not valid."
  @spec id_name(non_neg_integer()) :: atom() | nil
  def id_name(id), do: Map.get(@ids, id)

  @doc "True for the 6-bit IDs the stack will transmit."
  @spec valid_id?(non_neg_integer()) :: boolean()
  def valid_id?(id), do: Map.has_key?(@ids, id)

  @doc "True for SNMT frames, which skip the SCM UDID XOR."
  @spec snmt?(non_neg_integer()) :: boolean()
  def snmt?(id), do: (id &&& 0x38) == 0x28

  @doc "True for slim (fast) SSDO frames, whose payload is not doubled."
  @spec slim?(non_neg_integer()) :: boolean()
  def slim?(id), do: id == 0x3A or id == 0x3B

  @doc """
  Total encoded length for a payload of `le` bytes and frame ID `id`.
  """
  @spec frame_length(0..0xFE, 0..0x3F) :: pos_integer()
  def frame_length(le, id) do
    copies = if slim?(id), do: 1, else: 2
    4 + 5 + 2 * crc_len(le) + copies * le
  end

  @doc """
  Serialize a frame.

  Header checks follow `checkTxFrameHeader`: SADR 1..1023, ID in the valid
  set, SDN 1..1023, LE <= 254, TADR <= 1023, TR <= 63. CT must fit 16 bits.

  Options: `frame2_first: boolean()` (default false).
  """
  @spec encode(t(), udid(), keyword()) :: {:ok, binary()} | {:error, term()}
  def encode(%__MODULE__{} = f, <<_::binary-size(6)>> = scm_udid, opts \\ []) do
    with :ok <- check_tx(f) do
      {:ok, build(f, scm_udid, Keyword.get(opts, :frame2_first, false))}
    end
  end

  @doc """
  Deserialize and verify a frame.

  Checks follow `SFS_FrmDeSerialize` in its order: length against LE,
  SADR range, SF1/SF2 ID agreement, SDN range, TADR range (TADR 0 allowed
  only for SPDO data-only), CRC1, CRC2, payload equality. Plus the frame-ID
  check described in the module doc.

  Options: as for `encode/3`.
  """
  @spec decode(binary(), udid(), keyword()) :: {:ok, t()} | {:error, decode_error()}
  def decode(bin, <<_::binary-size(6)>> = scm_udid, opts \\ []) when is_binary(bin) do
    frame2_first = Keyword.get(opts, :frame2_first, false)

    with {:ok, sf1, sf2} <- split(bin, frame2_first) do
      verify(sf1, sf2, scm_udid)
    end
  end

  ## Encode

  defp check_tx(%__MODULE__{} = f) do
    cond do
      not is_integer(f.adr) or f.adr < 1 or f.adr > 0x3FF -> {:error, {:bad_sadr, f.adr}}
      not is_integer(f.id) or not valid_id?(f.id) -> {:error, {:bad_id, f.id}}
      not is_integer(f.sdn) or f.sdn < 1 or f.sdn > 0x3FF -> {:error, {:bad_sdn, f.sdn}}
      not is_binary(f.data) or byte_size(f.data) > @max_le -> {:error, {:bad_le, f.data}}
      not is_integer(f.tadr) or f.tadr < 0 or f.tadr > 0x3FF -> {:error, {:bad_tadr, f.tadr}}
      not is_integer(f.tr) or f.tr < 0 or f.tr > 0x3F -> {:error, {:bad_tr, f.tr}}
      not is_integer(f.ct) or f.ct < 0 or f.ct > 0xFFFF -> {:error, {:bad_ct, f.ct}}
      true -> :ok
    end
  end

  defp build(f, scm_udid, frame2_first) do
    le = byte_size(f.data)
    sf1_id = bor(f.id <<< 2, f.adr >>> 8 &&& 0x03)
    sf2_id = bxor(sf1_id, f.sdn >>> 8 &&& 0x03)
    sf2_adr = bxor(f.adr &&& 0xFF, f.sdn &&& 0xFF)
    sf2_tr = bor(f.tr <<< 2, f.tadr >>> 8 &&& 0x03)
    sf2_data = if slim?(f.id), do: <<>>, else: f.data

    sf1 = <<f.adr &&& 0xFF, sf1_id, le, f.ct &&& 0xFF, f.data::binary>>
    sf2 = <<sf2_adr, sf2_id, f.ct >>> 8, f.tadr &&& 0xFF, sf2_tr, sf2_data::binary>>

    sf1 = sf1 <> crc(sf1, le, f.id)
    sf2 = udid_code(sf2 <> crc(sf2, le, f.id), f.id, scm_udid)

    if frame2_first, do: sf2 <> sf1, else: sf1 <> sf2
  end

  ## Decode

  # LE and ID are read from SF1, which sits at the front unless frame2_first.
  # With frame2_first the SF2 length (and so the split point) depends on LE,
  # which is only in SF1, so the frame is split from the back.
  defp split(bin, false) when byte_size(bin) >= 3 do
    <<_adr, id_byte, le, _::binary>> = bin
    id = id_byte >>> 2

    with :ok <- check_length(bin, le, id) do
      sf1_len = 4 + le + crc_len(le)
      <<sf1::binary-size(sf1_len), sf2::binary>> = bin
      {:ok, sf1, sf2}
    end
  end

  defp split(bin, true) when byte_size(bin) >= 3 do
    split_frame2_first(bin)
  end

  defp split(_bin, _), do: {:error, :too_short}

  # SF1 is the tail: 4 + LE + crc. Try each LE the length admits; the
  # length equation has at most one solution per CRC width and ID class,
  # so pick the one whose SF1 header agrees with it.
  defp split_frame2_first(bin) do
    total = byte_size(bin)

    candidate =
      Enum.find_value(0..@max_le, fn le ->
        sf1_len = 4 + le + crc_len(le)

        if sf1_len < total do
          <<_::binary-size(total - sf1_len), sf1::binary>> = bin
          <<_adr, id_byte, sf1_le, _::binary>> = sf1
          id = id_byte >>> 2

          if sf1_le == le and frame_length(le, id) == total do
            <<sf2::binary-size(total - sf1_len), _::binary>> = bin
            {sf1, sf2}
          end
        end
      end)

    case candidate do
      {sf1, sf2} -> {:ok, sf1, sf2}
      nil -> {:error, {:length, nil, total}}
    end
  end

  defp check_length(_bin, le, _id) when le > @max_le, do: {:error, {:length, nil, le}}

  defp check_length(bin, le, id) do
    expected = frame_length(le, id)
    if byte_size(bin) == expected, do: :ok, else: {:error, {:length, expected, byte_size(bin)}}
  end

  defp verify(sf1, sf2_coded, scm_udid) do
    <<adr_lo, sf1_id, le, ct_lo, rest1::binary>> = sf1
    id = sf1_id >>> 2
    sf2 = udid_code(sf2_coded, id, scm_udid)
    <<sf2_adr, sf2_id, ct_hi, tadr_lo, sf2_tr, rest2::binary>> = sf2

    adr = bor(adr_lo, (sf1_id &&& 0x03) <<< 8)
    sdn = bxor(bor(sf2_adr, (sf2_id &&& 0x03) <<< 8), adr)
    tadr = bor(tadr_lo, (sf2_tr &&& 0x03) <<< 8)
    id2 = sf2_id >>> 2

    data2_len = if slim?(id), do: 0, else: le
    clen = crc_len(le)
    <<data1::binary-size(le), crc1::binary-size(clen)>> = rest1
    <<data2::binary-size(data2_len), crc2::binary-size(clen)>> = rest2
    sf1_body = binary_part(sf1, 0, 4 + le)
    sf2_body = binary_part(sf2, 0, 5 + data2_len)

    cond do
      not valid_id?(id) ->
        {:error, {:bad_id, id}}

      adr < 1 ->
        {:error, {:bad_sadr, adr}}

      id != id2 ->
        {:error, {:id_mismatch, id, id2}}

      sdn < 1 ->
        {:error, {:bad_sdn, sdn}}

      tadr < 1 and (id &&& 0x3E) != 0x30 ->
        {:error, {:bad_tadr, tadr}}

      crc(sf1_body, le, id) != crc1 ->
        {:error, :crc1}

      crc(sf2_body, le, id) != crc2 ->
        {:error, :crc2}

      not slim?(id) and data1 != data2 ->
        {:error, :data_mismatch}

      true ->
        {:ok,
         %__MODULE__{
           id: id,
           adr: adr,
           sdn: sdn,
           ct: bor(ct_lo, ct_hi <<< 8),
           tadr: tadr,
           tr: sf2_tr >>> 2,
           data: data1
         }}
    end
  end

  ## Shared

  defp crc_len(le) when le <= @max_le_short, do: 1
  defp crc_len(_le), do: 2

  defp crc(body, le, _id) when le <= @max_le_short, do: <<CRC.crc8(body)>>

  # SHNF_Crc16CalcSlim (0x5935) for slim SSDO, SHNF_Crc16Calc (0x755B) otherwise.
  defp crc(body, _le, id) do
    value = if slim?(id), do: CRC.crc16_a(body), else: CRC.crc16_b(body)
    <<value::little-16>>
  end

  # XOR is its own inverse, so this both encodes and decodes.
  defp udid_code(sf2, id, scm_udid) do
    if snmt?(id) do
      sf2
    else
      <<a, b, c, d, e, g, rest::binary>> = sf2
      <<u1, u2, u3, u4, u5, u6>> = scm_udid

      <<bxor(a, u1), bxor(b, u2), bxor(c, u3), bxor(d, u4), bxor(e, u5), bxor(g, u6),
        rest::binary>>
    end
  end
end
