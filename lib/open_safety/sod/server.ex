defmodule OpenSafety.SOD.Server do
  @moduledoc """
  One node's object dictionary, owned by a process so the node's services
  (SPDO, SNMTS, SSDOS) share it. A thin `gen_server` over
  `OpenSafety.SOD`; every call maps to the function of the same name.

  The C stack is single-threaded and its services call `SOD_*` directly;
  serializing through one process gives the same one-access-at-a-time
  guarantee.
  """

  use GenServer

  alias OpenSafety.SOD

  def start_link(objects, opts \\ []), do: GenServer.start_link(__MODULE__, objects, opts)

  def attr_get(s, index, sub), do: GenServer.call(s, {:attr_get, index, sub})
  def attr_next(s, handle), do: GenServer.call(s, {:attr_next, handle})

  def read(s, handle, offset \\ 0, size \\ 0),
    do: GenServer.call(s, {:read, handle, offset, size})

  def write(s, handle, data, overwrite \\ false, offset \\ 0, size \\ 0),
    do: GenServer.call(s, {:write, handle, data, overwrite, offset, size})

  def get(s, index, sub), do: GenServer.call(s, {:get, index, sub})

  def put(s, index, sub, value, overwrite \\ false),
    do: GenServer.call(s, {:put, index, sub, value, overwrite})

  def lock(s), do: GenServer.call(s, :lock)
  def unlock(s), do: GenServer.call(s, :unlock)
  def locked?(s), do: GenServer.call(s, :locked?)
  def enable_write(s), do: GenServer.call(s, :enable_write)
  def disable_write(s), do: GenServer.call(s, :disable_write)
  def write_access?(s), do: GenServer.call(s, :write_access?)
  def act_len_set(s, handle, len), do: GenServer.call(s, {:act_len_set, handle, len})
  def act_len_get(s, handle), do: GenServer.call(s, {:act_len_get, handle})
  def peek(s, handle, n), do: GenServer.call(s, {:peek, handle, n})
  def poke(s, handle, bin), do: GenServer.call(s, {:poke, handle, bin})
  def poke_default(s, handle, n), do: GenServer.call(s, {:poke_default, handle, n})

  @impl true
  def init(objects) do
    case SOD.new(objects) do
      {:ok, sod} -> {:ok, sod}
      {:error, code, where} -> {:stop, {code, where}}
    end
  end

  @impl true
  def handle_call({:attr_get, i, s}, _from, sod), do: {:reply, SOD.attr_get(sod, i, s), sod}
  def handle_call({:attr_next, h}, _from, sod), do: {:reply, SOD.attr_next(sod, h), sod}
  def handle_call({:read, h, o, n}, _from, sod), do: {:reply, SOD.read(sod, h, o, n), sod}
  def handle_call({:get, i, s}, _from, sod), do: {:reply, SOD.get(sod, i, s), sod}
  def handle_call(:locked?, _from, sod), do: {:reply, SOD.locked?(sod), sod}
  def handle_call(:write_access?, _from, sod), do: {:reply, SOD.write_access?(sod), sod}
  def handle_call({:act_len_get, h}, _from, sod), do: {:reply, SOD.act_len_get(sod, h), sod}
  def handle_call({:peek, h, n}, _from, sod), do: {:reply, SOD.peek(sod, h, n), sod}

  def handle_call(req, _from, sod) do
    {result, sod} =
      case req do
        {:write, h, d, ow, o, n} -> SOD.write(sod, h, d, ow, o, n)
        {:put, i, s, v, ow} -> SOD.put(sod, i, s, v, ow)
        :lock -> SOD.lock(sod)
        :unlock -> SOD.unlock(sod)
        :enable_write -> SOD.enable_write(sod)
        :disable_write -> SOD.disable_write(sod)
        {:act_len_set, h, l} -> SOD.act_len_set(sod, h, l)
        {:poke, h, b} -> SOD.poke(sod, h, b)
        {:poke_default, h, n} -> SOD.poke_default(sod, h, n)
      end

    {:reply, result, sod}
  end
end
