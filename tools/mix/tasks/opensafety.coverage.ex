defmodule Mix.Tasks.Opensafety.Coverage do
  @shortdoc "Report how much of the C openSAFETY stack is implemented in Elixir"

  @moduledoc """
  Port coverage of the B&R openSAFETY stack 1.4.

      mix opensafety.coverage [--c-src PATH] [--out FILE] [--list]

  1. **Inventory.** Every function definition in the stack's `SN/` (safety
     node) and `SCM/` (configuration manager) sources, with its SLOC, via
     `OpenSafety.Coverage.CParser`.
  2. **Manifest.** `coverage/manifest.exs` classifies functions:

       * `:ported` - behaviour implemented in Elixir (named counterpart)
       * `:partial` - implemented in part; the note says what is missing
       * `:replaced` - a C mechanism the Elixir design does differently, by
         design (object pointers into the SOD, instance tables, the frame
         buffer handshake); counted as covered
       * `:na` - not applicable: control-flow monitoring, unit-test
         accessors, multi-instance plumbing; excluded from the denominator
       * anything unlisted is `:missing`

     Keys are `"File.c:Function"` or `"File.c:*"` for a whole file; a
     function entry wins over its file's wildcard.
  3. **Report.** Markdown, per module (file prefix) and per function.
     Coverage is SLOC-weighted: `(ported + replaced) / (total - na)`, with
     `partial` shown separately rather than given an arbitrary weight.

  `--list` prints the raw inventory as TSV instead. `--c-src` defaults to
  `$OPENSAFETY_C_SRC`, else `../opensafety/src/eplssrc`. `--out` defaults
  to `COVERAGE.md`.

  Manifest entries that match no function are reported as stale, so the
  manifest cannot silently drift from the C tree.
  """

  use Mix.Task

  alias OpenSafety.Coverage.CParser

  @dirs ~w(SN SCM)
  @manifest "coverage/manifest.exs"

  # File-name prefix -> module, longest prefix first.
  @modules [
    {"SNMTS", "SNMTS"},
    {"SNMTM", "SNMTM"},
    {"SSDOS", "SSDOS"},
    {"SSDOC", "SSDOC"},
    {"SPDO", "SPDO"},
    {"SFS", "SFS"},
    {"SOD", "SOD"},
    {"SSC", "SSC"},
    {"SDN", "SDN"},
    {"SERR", "SERR"},
    {"SCFM", "SCFM"},
    {"SCM", "SCM"}
  ]

  @impl true
  def run(argv) do
    {opts, _, _} = OptionParser.parse(argv, strict: [c_src: :string, out: :string, list: :boolean])

    root =
      opts[:c_src] || System.get_env("OPENSAFETY_C_SRC") ||
        Path.expand("../opensafety/src/eplssrc", File.cwd!())

    unless File.dir?(Path.join(root, "SN")), do: Mix.raise("C sources not found at #{root}")

    inventory = inventory(root)

    if opts[:list] do
      Enum.each(inventory, fn f ->
        IO.puts(Enum.join([f.dir, f.file, f.name, f.line, f.sloc, f.static], "\t"))
      end)
    else
      manifest = load_manifest()
      rows = classify(inventory, manifest)
      stale = stale(inventory, manifest)
      out = opts[:out] || "COVERAGE.md"
      File.write!(out, report(rows, stale, root))
      summary(rows, stale, out)
    end
  end

  ## Inventory

  defp inventory(root) do
    for dir <- @dirs,
        path <- Path.wildcard(Path.join([root, dir, "*.c"])) |> Enum.sort(),
        file = Path.basename(path),
        f <- CParser.functions(path) do
      Map.merge(f, %{dir: dir, file: file, module: module(file)})
    end
  end

  defp module(file) do
    Enum.find_value(@modules, "other", fn {prefix, mod} ->
      if String.starts_with?(file, prefix), do: mod
    end)
  end

  ## Manifest

  defp load_manifest do
    if File.exists?(@manifest) do
      {m, _} = Code.eval_file(@manifest)
      m
    else
      %{}
    end
  end

  defp classify(inventory, manifest) do
    Enum.map(inventory, fn f ->
      entry =
        Map.get(manifest, "#{f.file}:#{f.name}") || Map.get(manifest, "#{f.file}:*") ||
          {:missing, nil, nil}

      {status, elixir, note} = normalize(entry)
      Map.merge(f, %{status: status, elixir: elixir, note: note})
    end)
  end

  defp normalize({s, e, n}), do: {s, e, n}
  defp normalize({s, e}), do: {s, e, nil}
  defp normalize(s) when is_atom(s), do: {s, nil, nil}

  defp stale(inventory, manifest) do
    names = MapSet.new(inventory, &"#{&1.file}:#{&1.name}")
    files = MapSet.new(inventory, & &1.file)

    manifest
    |> Map.keys()
    |> Enum.reject(fn key ->
      case String.split(key, ":") do
        [file, "*"] -> MapSet.member?(files, file)
        _ -> MapSet.member?(names, key)
      end
    end)
    |> Enum.sort()
  end

  ## Report

  defp totals(rows) do
    sum = fn status -> rows |> Enum.filter(&(&1.status == status)) |> Enum.map(& &1.sloc) |> Enum.sum() end
    total = rows |> Enum.map(& &1.sloc) |> Enum.sum()
    na = sum.(:na)

    %{
      functions: length(rows),
      total: total,
      ported: sum.(:ported),
      replaced: sum.(:replaced),
      partial: sum.(:partial),
      missing: sum.(:missing),
      na: na,
      applicable: total - na
    }
  end

  defp pct(_n, 0), do: "-"
  defp pct(n, d), do: :erlang.float_to_binary(100 * n / d, decimals: 1) <> "%"

  defp covered(t), do: pct(t.ported + t.replaced, t.applicable)
  defp with_partial(t), do: pct(t.ported + t.replaced + t.partial, t.applicable)

  defp report(rows, stale, root) do
    all = totals(rows)
    by_module = rows |> Enum.group_by(& &1.module) |> Enum.sort_by(fn {m, _} -> order(m) end)

    [
      "# openSAFETY C stack: Elixir port coverage\n\n",
      "Generated by `mix opensafety.coverage` from `#{Path.relative_to_cwd(root)}` ",
      "and `#{@manifest}`. Do not edit by hand.\n\n",
      "SLOC-weighted. **Covered** = (ported + replaced) / applicable; ",
      "**with partial** adds partially ported functions at full weight. ",
      "Applicable excludes `na` (control-flow monitoring, unit-test accessors, ",
      "multi-instance plumbing).\n\n",
      "## Overall\n\n",
      "| Functions | SLOC | Applicable | Ported | Replaced | Partial | Missing | Covered | With partial |\n",
      "|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n",
      "| #{all.functions} | #{all.total} | #{all.applicable} | #{all.ported} | #{all.replaced} | ",
      "#{all.partial} | #{all.missing} | **#{covered(all)}** | #{with_partial(all)} |\n\n",
      "## By module\n\n",
      "| Module | Role | Functions | Applicable SLOC | Ported | Replaced | Partial | Missing | Covered | With partial |\n",
      "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n",
      Enum.map(by_module, fn {m, rs} ->
        t = totals(rs)

        "| #{m} | #{role(m)} | #{t.functions} | #{t.applicable} | #{t.ported} | #{t.replaced} | " <>
          "#{t.partial} | #{t.missing} | #{covered(t)} | #{with_partial(t)} |\n"
      end),
      "\n",
      stale_section(stale),
      "## Functions\n\n",
      Enum.map(by_module, fn {m, rs} ->
        [
          "### #{m}\n\n",
          "| Function | File:line | SLOC | Status | Elixir | Note |\n",
          "|---|---|---:|---|---|---|\n",
          Enum.map(rs, fn f ->
            "| `#{f.name}` | #{f.file}:#{f.line} | #{f.sloc} | #{f.status} | " <>
              "#{code(f.elixir)} | #{f.note || ""} |\n"
          end),
          "\n"
        ]
      end)
    ]
    |> IO.iodata_to_binary()
  end

  defp stale_section([]), do: []

  defp stale_section(keys) do
    ["## Stale manifest entries\n\n", Enum.map(keys, &"- `#{&1}`\n"), "\n"]
  end

  defp code(nil), do: ""
  defp code(s), do: "`#{s}`"

  defp order(m), do: Enum.find_index(@modules, fn {_, x} -> x == m end) || 99

  defp role("SFS"), do: "frame serialize / deserialize"
  defp role("SPDO"), do: "process data, time sync, SCT"
  defp role("SNMTS"), do: "node management, slave"
  defp role("SSDOS"), do: "service data, server"
  defp role("SOD"), do: "object dictionary"
  defp role("SSC"), do: "frame dispatch, init"
  defp role("SDN"), do: "safety domain number"
  defp role("SERR"), do: "error reporting"
  defp role("SCFM"), do: "control-flow monitoring"
  defp role("SNMTM"), do: "node management, master"
  defp role("SSDOC"), do: "service data, client"
  defp role("SCM"), do: "configuration manager"
  defp role(_), do: ""

  defp summary(rows, stale, out) do
    t = totals(rows)

    Mix.shell().info(
      "#{t.functions} C functions, #{t.applicable} applicable SLOC: " <>
        "covered #{covered(t)}, with partial #{with_partial(t)}. Wrote #{out}."
    )

    if stale != [], do: Mix.shell().error("#{length(stale)} stale manifest entries")
  end
end
