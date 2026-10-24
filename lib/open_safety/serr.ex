defmodule OpenSafety.SERR do
  @moduledoc """
  Error statistics (`SERRmain.c`: `SERR_CountCommonEvt`,
  `SERR_CountSpdoEvt`, `SERR_CountAcycEvt` and their getters): one counter
  server per node, passed to the services as their `:serr` option. A
  service without one counts nothing.

  `SERR_SetError` itself is not here: every service reports errors to its
  owner as `{:error, code, info}` messages.

  ## Counters

  Common (`SERR_t_STATEVT_COMMON`), per node:

    * `:sfs_length`, `:sfs_too_long`, `:sfs_frm_id`, `:sfs_sadr_inv`,
      `:sfs_sdn_inv`, `:sfs_tadr_inv`, `:sfs_crc1`, `:sfs_crc2`, `:sfs_data`
      - frames rejected by deserialization (`count_decode/2` maps
      `OpenSafety.Frame.decode/3` errors to these)
    * `:cyc_reject` - SPDO for another domain, or for no Rx SPDO of ours
    * `:cyc_error` - every SPDO event below
    * `:acyc_reject` - SNMT/SSDO frame the SSC could not process
    * `:acyc_retry` - every acyclic event below

  Per Rx SPDO (`SERR_t_STATEVT_SPDO`, index from 0): `:inv_ct`,
  `:sct_tout`, `:prop_short`, `:prop_long`, `:payload`, `:tr_exp`,
  `:tr_time1`, `:tr_time2`, `:tr_late`, `:tr_inv`, `:tr_prop_long`,
  `:tr_prop_short`.

  Per SNMTM/SSDOC slot (`SERR_t_STATEVT_ACYC`; the C indexes by slot,
  not by SN): `:ssdo_tout`, `:ssdo_retry`, `:snmt_tout`, `:snmt_retry`.

  ## Options

    * `:max_rx` - `SPDO_cfg_MAX_NO_RX_SPDO` for the getter's range check
      (default 1023)
    * `:max_slots` - `SCM_cfg_MAX_NUM_OF_NODES` (default 101)
  """

  use GenServer

  @common ~w(sfs_length sfs_too_long sfs_frm_id sfs_sadr_inv sfs_sdn_inv sfs_tadr_inv
             sfs_crc1 sfs_crc2 sfs_data cyc_reject cyc_error acyc_reject acyc_retry)a

  @spdo ~w(inv_ct sct_tout prop_short prop_long payload tr_exp tr_time1 tr_time2
           tr_late tr_inv tr_prop_long tr_prop_short)a

  @acyc ~w(ssdo_tout ssdo_retry snmt_tout snmt_retry)a

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts)

  @doc "SERR_CountCommonEvt"
  def count_common(nil, _evt), do: :ok
  def count_common(s, evt) when evt in @common, do: GenServer.call(s, {:count, :common, nil, evt})

  @doc "SERR_CountSpdoEvt: also counts `:cyc_error`."
  def count_spdo(nil, _idx, _evt), do: :ok
  def count_spdo(s, idx, evt) when evt in @spdo, do: GenServer.call(s, {:count, :spdo, idx, evt})

  @doc "SERR_CountAcycEvt: also counts `:acyc_retry`."
  def count_acyc(nil, _slot, _evt), do: :ok

  def count_acyc(s, slot, evt) when evt in @acyc,
    do: GenServer.call(s, {:count, :acyc, slot, evt})

  @doc "Count a `OpenSafety.Frame.decode/3` error as SFS_FrmDeSerialize does."
  def count_decode(s, reason), do: count_common(s, decode_event(reason))

  @doc "SERR_GetCommonStatCtr: `{:ok, n}` or `:error`."
  def get_common(s, evt), do: GenServer.call(s, {:get, :common, nil, evt})

  @doc "SERR_GetSpdoStatCtr"
  def get_spdo(s, idx, evt), do: GenServer.call(s, {:get, :spdo, idx, evt})

  @doc "SERR_GetAcycStatCtr"
  def get_acyc(s, slot, evt), do: GenServer.call(s, {:get, :acyc, slot, evt})

  @doc "All non-zero counters: `%{common: %{}, spdo: %{idx => %{}}, acyc: %{slot => %{}}}`."
  def stats(s), do: GenServer.call(s, :stats)

  @doc false
  def decode_event(:too_short), do: :sfs_length
  def decode_event({:length, :too_long, _le}), do: :sfs_too_long
  def decode_event({:length, _, _}), do: :sfs_length
  def decode_event({:bad_id, _}), do: :sfs_frm_id
  def decode_event({:id_mismatch, _, _}), do: :sfs_frm_id
  def decode_event({:bad_sadr, _}), do: :sfs_sadr_inv
  def decode_event({:bad_sdn, _}), do: :sfs_sdn_inv
  def decode_event({:bad_tadr, _}), do: :sfs_tadr_inv
  def decode_event(:crc1), do: :sfs_crc1
  def decode_event(:crc2), do: :sfs_crc2
  def decode_event(:data_mismatch), do: :sfs_data

  @impl true
  def init(opts) do
    {:ok,
     %{
       max_rx: Keyword.get(opts, :max_rx, 1023),
       max_slots: Keyword.get(opts, :max_slots, 101),
       common: %{},
       spdo: %{},
       acyc: %{}
     }}
  end

  @impl true
  def handle_call({:count, :common, _, evt}, _from, s), do: {:reply, :ok, inc_common(s, evt)}

  def handle_call({:count, :spdo, idx, evt}, _from, s) do
    s = %{s | spdo: inc_in(s.spdo, idx, evt)}
    {:reply, :ok, inc_common(s, :cyc_error)}
  end

  def handle_call({:count, :acyc, slot, evt}, _from, s) do
    s = %{s | acyc: inc_in(s.acyc, slot, evt)}
    {:reply, :ok, inc_common(s, :acyc_retry)}
  end

  def handle_call({:get, :common, _, evt}, _from, s) do
    reply = if evt in @common, do: {:ok, Map.get(s.common, evt, 0)}, else: :error
    {:reply, reply, s}
  end

  def handle_call({:get, :spdo, idx, evt}, _from, s) do
    reply =
      if evt in @spdo and is_integer(idx) and idx >= 0 and idx < s.max_rx,
        do: {:ok, s.spdo |> Map.get(idx, %{}) |> Map.get(evt, 0)},
        else: :error

    {:reply, reply, s}
  end

  def handle_call({:get, :acyc, slot, evt}, _from, s) do
    reply =
      if evt in @acyc and is_integer(slot) and slot >= 0 and slot < s.max_slots,
        do: {:ok, s.acyc |> Map.get(slot, %{}) |> Map.get(evt, 0)},
        else: :error

    {:reply, reply, s}
  end

  def handle_call(:stats, _from, s), do: {:reply, Map.take(s, [:common, :spdo, :acyc]), s}

  defp inc_common(s, evt), do: %{s | common: Map.update(s.common, evt, 1, &(&1 + 1))}

  defp inc_in(map, key, evt) do
    Map.update(map, key, %{evt => 1}, fn m -> Map.update(m, evt, 1, &(&1 + 1)) end)
  end
end
