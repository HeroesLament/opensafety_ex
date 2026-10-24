defmodule OpenSafety.Coverage.CParser do
  @moduledoc """
  Function inventory of a C source file: name, first line, and source lines
  of code (SLOC), without a C toolchain.

  Good enough for the openSAFETY stack's house style, which is regular:
  definitions start at column 0, bodies are brace-delimited, no K&R
  declarations. The parser:

    * blanks comments and string/char literals (line numbers preserved),
    * tracks brace depth, and at depth 0 collects the text before each `{`,
    * calls it a function definition when that text ends in
      `name(params)` and is not a control statement, aggregate, or
      initializer.

  SLOC counts non-blank, non-preprocessor lines from the signature to the
  closing brace. Conditional compilation is not evaluated: a function
  defined in two `#if` branches is reported twice, each with its own line.
  """

  @keywords ~w(if else for while do switch return sizeof struct union enum typedef)

  @type func :: %{
          name: String.t(),
          line: pos_integer(),
          sloc: non_neg_integer(),
          static: boolean()
        }

  @spec functions(Path.t()) :: [func()]
  def functions(path) do
    path
    |> File.read!()
    |> blank()
    |> String.split("\n")
    |> Enum.with_index(1)
    |> scan(0, [], nil, [])
  end

  # Replace comments and literals with nothing, keeping their newlines.
  defp blank(src) do
    keep_newlines = fn m -> String.duplicate("\n", count_nl(m)) end

    src
    |> then(&Regex.replace(~r{/\*.*?\*/}s, &1, keep_newlines))
    |> then(&Regex.replace(~r{//[^\n]*}, &1, ""))
    |> then(&Regex.replace(~r{"(?:\\.|[^"\\\n])*"}, &1, "\"\""))
    |> then(&Regex.replace(~r{'(?:\\.|[^'\\\n])+'}, &1, "' '"))
  end

  defp count_nl(s), do: s |> String.graphemes() |> Enum.count(&(&1 == "\n"))

  # depth: brace depth; header: depth-0 lines since the last statement end;
  # cur: the function being read.
  defp scan([], _depth, _header, _cur, acc), do: Enum.reverse(acc)

  defp scan([{line, n} | rest], depth, header, cur, acc) do
    trimmed = String.trim(line)

    cond do
      String.starts_with?(trimmed, "#") ->
        # Preprocessor lines neither count nor break a header.
        scan(rest, depth, header, cur, acc)

      depth == 0 and cur == nil ->
        at_top(line, n, trimmed, rest, header, acc)

      true ->
        cur = if trimmed == "", do: cur, else: %{cur | sloc: cur.sloc + 1}
        depth = depth + delta(line)

        if depth == 0,
          do: scan(rest, 0, [], nil, [cur | acc]),
          else: scan(rest, depth, header, cur, acc)
    end
  end

  defp at_top(line, n, trimmed, rest, header, acc) do
    case :binary.match(line, "{") do
      :nomatch ->
        header =
          cond do
            trimmed == "" -> header
            String.ends_with?(trimmed, ";") or String.ends_with?(trimmed, "}") -> []
            true -> header ++ [{n, trimmed}]
          end

        scan(rest, 0, header, nil, acc)

      {pos, _} ->
        before = String.trim(binary_part(line, 0, pos))
        sig_lines = if before == "", do: header, else: header ++ [{n, before}]
        sig = sig_lines |> Enum.map_join(" ", &elem(&1, 1)) |> String.trim()
        depth = delta(line)

        case function_name(sig) do
          nil ->
            # Aggregate or initializer at file scope: skip its braces.
            skip(rest, depth, acc)

          name ->
            first = if sig_lines == [], do: n, else: elem(hd(sig_lines), 0)
            sloc = length(sig_lines) + if(before == "", do: 1, else: 0)

            cur = %{
              name: name,
              line: first,
              static: String.starts_with?(sig, "static "),
              sloc: sloc
            }

            if depth == 0,
              do: scan(rest, 0, [], nil, [cur | acc]),
              else: scan(rest, depth, [], cur, acc)
        end
    end
  end

  defp skip(rest, 0, acc), do: scan(rest, 0, [], nil, acc)
  defp skip([], _depth, acc), do: Enum.reverse(acc)
  defp skip([{line, _n} | rest], depth, acc), do: skip(rest, depth + delta(line), acc)

  defp delta(line) do
    line
    |> String.graphemes()
    |> Enum.reduce(0, fn
      "{", d -> d + 1
      "}", d -> d - 1
      _, d -> d
    end)
  end

  defp function_name(sig) do
    with false <- String.contains?(sig, "="),
         [_, name] <- Regex.run(~r/([A-Za-z_]\w*)\s*\((?:[^()]|\([^()]*\))*\)\s*$/, sig),
         [first | _] <- String.split(sig),
         false <- first in @keywords,
         false <- name in @keywords do
      name
    else
      _ -> nil
    end
  end
end
