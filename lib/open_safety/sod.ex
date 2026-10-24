defmodule OpenSafety.SOD do
  @moduledoc """
  The safety object dictionary (`SODmain.c`, `SODattr.c`, `SODcheck.c`,
  `SODlock.c`, `SODactLen.c`) as a pure data structure.

  ## Objects

  `new/1` takes the application's object list (`SAPL_ps_OD` in C), one map
  per (index, sub-index):

      %{
        index: 0x1400, sub: 2,
        type: :uint16,               # see @types
        len: 2,                      # bytes; max length for strings/domains
        attr: [:rw, :crc],           # see @attrs
        default: 100,                # value, or binary for strings/domains
        range: {1, 65535},           # optional {low, high}
        act_len: 0,                  # strings/domains only, default len
        callback: fun                # with :bef_rd / :bef_wr / :aft_wr
      }

  Callbacks are `fun(service, object, data, offset, size)` returning `:ok`
  or `{:abort, abort_code}`, with `service` one of `:before_read`,
  `:before_write`, `:after_write` (`SOD_t_SERVICE`).

  ## Values

  Every object is held as its little-endian wire bytes, as the C keeps raw
  memory: `len` bytes, strings and domains included, with `act_len` the
  used part. That keeps segmented SSDO access (offset, size) one-to-one.
  `get/3` and `put/4` convert to and from Elixir values.

  ## Handles

  A handle is the `{index, sub}` key, where the C uses the object's
  address.

  ## Results

  Queries return `{:ok, ...}` or `{:error, code, abort}`; operations that
  change the dictionary return `{result, sod}`, because a C write can fail
  after it has already changed data (an after-write callback abort).
  `code` is named after `SOD_k_ERR_*`, `abort` after `SOD_ABT_*`.

  ## Deviations from the C stack

    * The object list need not be sorted; duplicates are still rejected
      (`:sod_not_sorted_2`).
    * No pointer-to-pointer objects (`SOD_k_ATTR_P2P`) and no application
      objects (`SAPL_SOD_*Clbk`): both are C memory-layout mechanisms.
    * `attr_next/2` takes the previous handle instead of keeping a cursor
      inside the dictionary.
  """

  @types ~w(boolean int8 int16 int32 uint8 uint16 uint32 real32
            int64 uint64 real64 visible_string octet_string domain)a

  @attrs ~w(pdo_map ro_const ro wo rw crc bef_rd bef_wr aft_wr no_len_chk)a

  @strings [:visible_string, :octet_string, :domain]

  defstruct objects: %{}, keys: {}, locked: false, write_enabled: true

  @type key :: {non_neg_integer(), non_neg_integer()}
  @type t :: %__MODULE__{}
  @type error :: {:error, atom(), atom()}

  ## Construction (SOD_Init: InitFlags, InitAddr, SOD_Check, SetDefaultValues)

  @spec new([map()]) :: {:ok, t()} | error()
  def new([]), do: {:error, :od_is_empty, :general_error}

  def new(objects) when is_list(objects) do
    with :ok <- check_unique(objects),
         {:ok, objs} <- check_all(objects, %{}),
         {:ok, objs} <- set_defaults(objs) do
      keys = objs |> Map.keys() |> Enum.sort() |> List.to_tuple()
      {:ok, %__MODULE__{objects: objs, keys: keys}}
    end
  end

  defp check_unique(objects) do
    dup =
      objects
      |> Enum.map(&{&1.index, &1.sub})
      |> Enum.frequencies()
      |> Enum.find(fn {_k, n} -> n > 1 end)

    case dup do
      nil -> :ok
      {{i, s}, _} -> {:error, :sod_not_sorted_2, {i, s}}
    end
  end

  defp check_all([], acc), do: {:ok, acc}

  defp check_all([o | rest], acc) do
    o = normalize(o)
    key = {o.index, o.sub}

    with :ok <- data_type_check(o),
         :ok <- range_allowed(o),
         :ok <- attr_check(o) do
      check_all(rest, Map.put(acc, key, o))
    else
      {:error, code} -> {:error, code, key}
    end
  end

  defp normalize(o) do
    attr = o |> Map.get(:attr, []) |> expand_attr()

    o
    |> Map.put(:attr, attr)
    |> Map.put_new(:default, nil)
    |> Map.put_new(:range, nil)
    |> Map.put_new(:callback, nil)
    |> Map.put_new(:act_len, Map.get(o, :len, 0))
  end

  defp expand_attr(list) do
    Enum.flat_map(list, fn
      :rw -> [:ro, :wo]
      a -> [a]
    end)
    |> Enum.uniq()
  end

  # DataTypeCheck
  defp data_type_check(%{type: t, len: len} = o) when t in @types do
    expected =
      case t do
        t when t in [:boolean, :int8, :uint8] -> {1, :type_len_1}
        t when t in [:int16, :uint16] -> {2, :type_len_2}
        t when t in [:int32, :uint32, :real32] -> {4, :type_len_3}
        # The C reports 64-bit length errors as TYPE_LEN_4 and empty
        # strings as TYPE_LEN_5 (the reverse of its own error strings).
        t when t in [:int64, :uint64, :real64] -> {8, :type_len_4}
        t when t in @strings -> :string
        _ -> :unsupported
      end

    case expected do
      :unsupported -> {:error, :type_not_supported}
      :string when len == 0 -> {:error, :type_len_5}
      :string -> :ok
      {^len, _} -> range_order(o)
      {_, code} -> {:error, code}
    end
  end

  defp data_type_check(_o), do: {:error, :type_not_supported}

  defp range_order(%{range: {lo, hi}}) when hi < lo, do: {:error, :max_min_value_error}
  defp range_order(_o), do: :ok

  defp range_allowed(%{type: t, range: r}) when r != nil and (t == :boolean or t in @strings),
    do: {:error, :no_range_checking}

  defp range_allowed(_o), do: :ok

  # AttrCheck
  defp attr_check(%{attr: attr} = o) do
    has = &(&1 in attr)
    cb_flags = has.(:bef_rd) or has.(:bef_wr) or has.(:aft_wr)

    cond do
      attr == [] or Enum.any?(attr, &(&1 not in @attrs)) -> {:error, :attr_is_wrong_1}
      not (has.(:ro_const) or has.(:ro) or has.(:wo)) -> {:error, :attr_is_wrong_2}
      has.(:ro_const) and (has.(:ro) or has.(:wo)) -> {:error, :attr_is_wrong_3}
      has.(:pdo_map) and has.(:wo) and o.default == nil -> {:error, :no_default_value}
      cb_flags and o.callback == nil -> {:error, :obj_clbk_1}
      not cb_flags and o.callback != nil -> {:error, :obj_clbk_2}
      true -> :ok
    end
  end

  # SetDefaultValues: zero when there is neither default nor range; the
  # range-checked zero when there is only a range; else the default.
  defp set_defaults(objs) do
    Enum.reduce_while(objs, {:ok, objs}, fn {key, o}, {:ok, acc} ->
      zero = :binary.copy(<<0>>, o.len)

      {value, check} =
        cond do
          o.default == nil and o.range == nil -> {zero, false}
          o.default == nil -> {zero, true}
          true -> {encode!(o, o.default), true}
        end

      if check do
        case data_valid(o, value, 0, 0) do
          :ok -> {:cont, {:ok, Map.put(acc, key, Map.put(o, :data, value))}}
          {:error, code, _abort} -> {:halt, {:error, code, key}}
        end
      else
        {:cont, {:ok, Map.put(acc, key, Map.put(o, :data, value))}}
      end
    end)
  end

  ## Lookup (SOD_AttrGet, SOD_AttrGetNext, SOD_HdlValid)

  @doc "Attributes of an object: `{:ok, handle, attr}`."
  @spec attr_get(t(), non_neg_integer(), non_neg_integer()) ::
          {:ok, key(), map()} | error()
  def attr_get(%__MODULE__{} = sod, index, sub) do
    case Map.fetch(sod.objects, {index, sub}) do
      {:ok, o} ->
        {:ok, {index, sub}, attr_of(o)}

      :error ->
        abort =
          if Enum.any?(Map.keys(sod.objects), fn {i, _} -> i == index end),
            do: :sub_idx_does_not_exist,
            else: :obj_does_not_exist

        {:error, :attr_get, abort}
    end
  end

  @doc """
  Object after `handle` in (index, sub) order, or the first with
  `:first`. Returns `{:ok, handle, attr}` or `:end`.
  """
  def attr_next(%__MODULE__{keys: keys} = sod, :first) do
    if tuple_size(keys) == 0, do: :end, else: at(sod, 0)
  end

  def attr_next(%__MODULE__{keys: keys} = sod, handle) do
    case index_of(keys, handle, 0) do
      nil -> {:error, :obj_hdl_invalid, :local_control}
      i when i + 1 < tuple_size(keys) -> at(sod, i + 1)
      _ -> :end
    end
  end

  defp at(sod, i) do
    key = elem(sod.keys, i)
    {:ok, key, attr_of(Map.fetch!(sod.objects, key))}
  end

  defp index_of(keys, key, i) when i < tuple_size(keys) do
    if elem(keys, i) == key, do: i, else: index_of(keys, key, i + 1)
  end

  defp index_of(_keys, _key, _i), do: nil

  defp attr_of(o),
    do: %{attr: o.attr, type: o.type, len: o.len, default: o.default, act_len: o.act_len}

  ## Read (SOD_Read)

  @doc """
  Read `size` bytes at `offset` (both 0: the whole object, `len` bytes).
  Segmented access only for strings and domains.
  """
  @spec read(t(), key(), non_neg_integer(), non_neg_integer()) :: {:ok, binary()} | error()
  def read(%__MODULE__{} = sod, handle, offset \\ 0, size \\ 0) do
    with {:ok, o} <- fetch(sod, handle),
         :ok <- segment_ok(o, offset, size, :type_offset_1),
         :ok <- bounds(o, offset, size, :offset_size_1),
         :ok <- callback(o, :bef_rd, :before_read, nil, offset, size, :clbk_abort_br) do
      n = if size == 0, do: o.len - offset, else: size
      {:ok, binary_part(o.data, offset, n)}
    end
  end

  ## Write (SOD_Write)

  @doc """
  Write `data` at `offset`. With offset and size 0 the whole object is
  written and `data` must be `len` bytes. `overwrite` lets the stack write
  read-only (but not read-only-constant) objects.

  Returns `{:ok | error, sod}`.
  """
  @spec write(t(), key(), binary(), boolean(), non_neg_integer(), non_neg_integer()) ::
          {:ok | error(), t()}
  def write(%__MODULE__{} = sod, handle, data, overwrite \\ false, offset \\ 0, size \\ 0) do
    result =
      with :ok <- writable_sod(sod),
           {:ok, o} <- fetch(sod, handle),
           :ok <- segment_ok(o, offset, size, :type_offset_2),
           :ok <- bounds(o, offset, size, :offset_size_2),
           :ok <- data_size(o, data, offset, size) do
        if read_only_same?(o, data, overwrite) do
          :unchanged
        else
          with :ok <- object_writeable(o, overwrite),
               :ok <- data_valid(o, data, offset, size),
               :ok <- callback(o, :bef_wr, :before_write, data, offset, size, :clbk_abort_bw) do
            {:copy, o}
          end
        end
      end

    case result do
      :unchanged ->
        {:ok, sod}

      {:copy, o} ->
        o = data_cpy(o, data, offset, size)
        sod = %{sod | objects: Map.put(sod.objects, handle, o)}
        {after_write(o, offset, size), sod}

      error ->
        {error, sod}
    end
  end

  defp writable_sod(%{write_enabled: true}), do: :ok
  defp writable_sod(_sod), do: {:error, :sod_write_disabled, :present_device_state}

  defp data_size(o, data, 0, 0) do
    if byte_size(data) == o.len, do: :ok, else: {:error, :data_len, :len_does_not_match}
  end

  defp data_size(_o, data, _offset, size) do
    if byte_size(data) == size, do: :ok, else: {:error, :data_len, :len_does_not_match}
  end

  # ObjectReadOnly: writing a read-only scalar with its current value is a
  # successful no-op.
  defp read_only_same?(o, data, overwrite) do
    :ro in o.attr and :wo not in o.attr and not overwrite and o.type not in @strings and
      data == o.data
  end

  # ObjectWriteable
  defp object_writeable(o, overwrite) do
    cond do
      overwrite and :ro_const not in o.attr -> :ok
      :wo in o.attr -> :ok
      true -> {:error, :obj_not_writeable, :obj_not_writeable}
    end
  end

  # DataValid
  defp data_valid(%{type: :boolean}, <<b>>, _off, _size) when b in [0, 1], do: :ok

  defp data_valid(%{type: :boolean}, _data, _off, _size),
    do: {:error, :value_is_too_high_2, :value_is_too_high}

  defp data_valid(%{type: :visible_string} = o, data, 0, 0),
    do: visible_string_check(binary_part(data, 0, o.len))

  defp data_valid(%{type: :visible_string}, data, _off, size),
    do: visible_string_check(binary_part(data, 0, size))

  defp data_valid(%{type: t}, _data, _off, _size) when t in [:domain, :octet_string], do: :ok

  defp data_valid(%{range: nil}, _data, _off, _size), do: :ok

  defp data_valid(%{range: {lo, hi}} = o, data, _off, _size) do
    v = decode!(o.type, data)

    cond do
      hi < v -> {:error, :value_is_too_high_1, :value_is_too_high}
      lo > v -> {:error, :value_is_too_low, :value_is_too_low}
      true -> :ok
    end
  end

  # VisibleStringCheck: 0x00 or 0x20..0x7E.
  defp visible_string_check(<<>>), do: :ok
  defp visible_string_check(<<0, rest::binary>>), do: visible_string_check(rest)

  defp visible_string_check(<<c, rest::binary>>) when c >= 0x20 and c <= 0x7E,
    do: visible_string_check(rest)

  defp visible_string_check(_), do: {:error, :visible_str_invalid, :value_range_exceeded}

  # DataCpy
  defp data_cpy(o, data, 0, 0), do: %{o | data: data}

  defp data_cpy(o, data, offset, size) do
    <<pre::binary-size(offset), _::binary-size(size), post::binary>> = o.data
    %{o | data: pre <> data <> post}
  end

  # CallAfterWriteClbk: only once the whole object (or its actual length)
  # has been written.
  defp after_write(o, offset, size) do
    act = if o.type in @strings, do: o.act_len, else: o.len

    if (offset == 0 and size == 0) or offset + size == act,
      do: callback(o, :aft_wr, :after_write, nil, offset, size, :clbk_abort_aw),
      else: :ok
  end

  ## Lock and write enable (SODlock.c)

  @doc "SOD_Lock: one lock for the whole dictionary (an SSDO transfer)."
  def lock(%__MODULE__{locked: true} = sod),
    do: {{:error, :locking_failed, :present_device_state}, sod}

  def lock(%__MODULE__{} = sod), do: {:ok, %{sod | locked: true}}

  def unlock(%__MODULE__{locked: true} = sod), do: {:ok, %{sod | locked: false}}

  def unlock(%__MODULE__{} = sod),
    do: {{:error, :unlock_without_lock, :present_device_state}, sod}

  def locked?(%__MODULE__{locked: l}), do: l

  @doc "SOD_EnableSodWrite: only valid while disabled."
  def enable_write(%__MODULE__{write_enabled: false} = sod),
    do: {:ok, %{sod | write_enabled: true}}

  def enable_write(sod), do: {{:error, :enable_wr_failed, :general_error}, sod}

  @doc "SOD_DisableSodWrite: refused while locked or already disabled."
  def disable_write(%__MODULE__{write_enabled: true, locked: false} = sod),
    do: {:ok, %{sod | write_enabled: false}}

  def disable_write(sod), do: {{:error, :disable_wr_failed, :general_error}, sod}

  def write_access?(%__MODULE__{write_enabled: w}), do: w

  ## Actual length (SODactLen.c)

  def act_len_set(%__MODULE__{} = sod, handle, len) do
    case fetch(sod, handle) do
      {:ok, %{type: t} = o} when t in @strings and len <= o.len ->
        {:ok, %{sod | objects: Map.put(sod.objects, handle, %{o | act_len: len})}}

      {:ok, %{type: t}} when t in @strings ->
        {{:error, :act_len, :general_error}, sod}

      {:ok, _} ->
        {{:error, :act_len_type, :general_error}, sod}

      error ->
        {error, sod}
    end
  end

  def act_len_get(%__MODULE__{} = sod, handle) do
    with {:ok, o} <- fetch(sod, handle) do
      {:ok, if(o.type in @strings, do: o.act_len, else: o.len)}
    end
  end

  ## Typed access for the stack's own use

  @doc """
  Decoded value of an object. Strings and domains return their bytes up
  to the actual length.
  """
  def get(%__MODULE__{} = sod, index, sub) do
    with {:ok, data} <- read(sod, {index, sub}) do
      o = Map.fetch!(sod.objects, {index, sub})

      {:ok,
       if(o.type in @strings, do: binary_part(data, 0, o.act_len), else: decode!(o.type, data))}
    end
  end

  @doc """
  Write a decoded value. Strings are zero-padded to their length, and set
  the actual length to the bytes given.
  """
  def put(%__MODULE__{} = sod, index, sub, value, overwrite \\ false) do
    case fetch(sod, {index, sub}) do
      {:ok, o} ->
        {result, sod} = write(sod, {index, sub}, encode!(o, value), overwrite)

        if result == :ok and o.type in @strings,
          do: act_len_set(sod, {index, sub}, byte_size(value)),
          else: {result, sod}

      error ->
        {error, sod}
    end
  end

  ## Direct access (the C's object pointers)

  @doc """
  The first `n` bytes of an object's memory, without access checks or
  callbacks: what the C's SPDO mapping reads through its stored data
  pointers.
  """
  def peek(%__MODULE__{} = sod, handle, n) do
    with {:ok, o} <- fetch(sod, handle) do
      {:ok, binary_part(o.data, 0, min(n, o.len))}
    end
  end

  @doc """
  Overwrite the first bytes of an object's memory, without access checks,
  range checks or callbacks (the SPDO Rx mapping's `memcpy` into the
  object).
  """
  def poke(%__MODULE__{} = sod, handle, bin) do
    case fetch(sod, handle) do
      {:ok, o} when byte_size(bin) <= o.len ->
        o = data_cpy(o, bin, 0, byte_size(bin))
        {:ok, %{sod | objects: Map.put(sod.objects, handle, o)}}

      {:ok, _o} ->
        {{:error, :offset_size_2, :len_is_too_high}, sod}

      error ->
        {error, sod}
    end
  end

  @doc "The first `n` bytes of an object back to its default (`SPDO_RxSpdoToSafeState`)."
  def poke_default(%__MODULE__{} = sod, handle, n) do
    with {:ok, o} <- fetch(sod, handle) do
      default = if o.default == nil, do: :binary.copy(<<0>>, o.len), else: encode!(o, o.default)
      poke(sod, handle, binary_part(default, 0, min(n, o.len)))
    else
      error -> {error, sod}
    end
  end

  ## Abort codes (SOD_t_ABORT_CODES)

  @aborts %{
    no_error: 0x00000000,
    ssdo_time_out: 0x05040000,
    cmd_id_invalid: 0x05040001,
    block_size_invalid: 0x05040002,
    seq_num_invalid: 0x05040003,
    out_of_memory: 0x05040005,
    unsupported_access: 0x06010000,
    obj_not_readable: 0x06010001,
    obj_not_writeable: 0x06010002,
    obj_does_not_exist: 0x06020000,
    obj_not_mappable: 0x06040041,
    spdo_length_exceeded: 0x06040042,
    gen_param_incomp: 0x06040043,
    gen_internal_incomp: 0x06040047,
    hw_error: 0x06060000,
    len_does_not_match: 0x06070010,
    len_is_too_high: 0x06070012,
    len_is_too_low: 0x06070013,
    sub_idx_does_not_exist: 0x06090011,
    value_range_exceeded: 0x06090030,
    value_is_too_high: 0x06090031,
    value_is_too_low: 0x06090032,
    max_min_value_error: 0x06090036,
    general_error: 0x08000000,
    data_can_not_stored: 0x08000020,
    local_control: 0x08000021,
    present_device_state: 0x08000022,
    obj_is_busy: 0x08000023
  }

  @doc "Wire value of an SSDO abort code (`SOD_ABT_*`)."
  def abort_code(atom) when is_atom(atom), do: Map.fetch!(@aborts, atom)
  def abort_code(n) when is_integer(n), do: n

  @doc "Abort code name for a wire value, or the integer if unknown."
  def abort_name(n) do
    Enum.find_value(@aborts, n, fn {k, v} -> if v == n, do: k end)
  end

  ## Helpers

  defp fetch(sod, handle) do
    case Map.fetch(sod.objects, handle) do
      {:ok, o} -> {:ok, o}
      :error -> {:error, :obj_hdl_invalid, :local_control}
    end
  end

  defp segment_ok(o, offset, size, code) do
    if (offset != 0 or size != 0) and o.type not in @strings,
      do: {:error, code, :general_error},
      else: :ok
  end

  defp bounds(o, offset, size, code) do
    if offset < o.len and size <= o.len - offset,
      do: :ok,
      else: {:error, code, :len_is_too_high}
  end

  defp callback(o, flag, service, data, offset, size, code) do
    if flag in o.attr do
      case o.callback.(service, o, data, offset, size) do
        :ok -> :ok
        {:abort, abort} -> {:error, code, abort}
      end
    else
      :ok
    end
  end

  @doc false
  def encode!(%{type: t, len: len}, v) when t in @strings do
    pad = len - byte_size(v)
    if pad < 0, do: raise(ArgumentError, "value longer than #{len} bytes")
    v <> :binary.copy(<<0>>, pad)
  end

  def encode!(%{type: :boolean}, true), do: <<1>>
  def encode!(%{type: :boolean}, false), do: <<0>>
  def encode!(%{type: :boolean}, v), do: <<v>>
  def encode!(%{type: :uint8}, v), do: <<v::8>>
  def encode!(%{type: :int8}, v), do: <<v::signed-8>>
  def encode!(%{type: :uint16}, v), do: <<v::little-16>>
  def encode!(%{type: :int16}, v), do: <<v::signed-little-16>>
  def encode!(%{type: :uint32}, v), do: <<v::little-32>>
  def encode!(%{type: :int32}, v), do: <<v::signed-little-32>>
  def encode!(%{type: :uint64}, v), do: <<v::little-64>>
  def encode!(%{type: :int64}, v), do: <<v::signed-little-64>>
  def encode!(%{type: :real32}, v), do: <<v::float-little-32>>
  def encode!(%{type: :real64}, v), do: <<v::float-little-64>>

  @doc false
  def decode!(:boolean, <<b>>), do: b
  def decode!(:uint8, <<v::8>>), do: v
  def decode!(:int8, <<v::signed-8>>), do: v
  def decode!(:uint16, <<v::little-16>>), do: v
  def decode!(:int16, <<v::signed-little-16>>), do: v
  def decode!(:uint32, <<v::little-32>>), do: v
  def decode!(:int32, <<v::signed-little-32>>), do: v
  def decode!(:uint64, <<v::little-64>>), do: v
  def decode!(:int64, <<v::signed-little-64>>), do: v
  def decode!(:real32, <<v::float-little-32>>), do: v
  def decode!(:real64, <<v::float-little-64>>), do: v
end
