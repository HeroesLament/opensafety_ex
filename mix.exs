defmodule OpenSafety.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/HeroesLament/opensafety_ex"

  def project do
    [
      app: :opensafety_ex,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: @source_url
    ]
  end

  # Library, not an OTP application. It must also run on AtomVM, so it
  # starts nothing and depends on nothing beyond what AtomVM's stdlib
  # provides: binaries, Bitwise, tuples.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # tools/ holds host-only mix tasks (C coverage analysis). Kept out of
  # :prod so a dependent project, which compiles this as :prod, never packs
  # them into an AtomVM image.
  defp elixirc_paths(:prod), do: ["lib"]
  defp elixirc_paths(_), do: ["lib", "tools"]

  defp deps do
    []
  end

  defp description do
    """
    openSAFETY safety layer in pure Elixir: frame codec, CRCs, and (later)
    SPDO producer/consumer, written to the AtomVM subset so the same code
    runs on an ESP32 pendant and on the host. Reference: the B&R openSAFETY
    stack 1.4.
    """
  end

  defp package do
    [
      licenses: ["MIT", "Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md LICENSE.md LICENSE-MIT LICENSE-APACHE)
    ]
  end
end
