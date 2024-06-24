defmodule UeberauthSlack.MixProject do
  use Mix.Project

  def project do
    [
      app: :ueberauth_slack,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:oauth2, "~> 1.0 or ~> 2.0"},
      {:ueberauth, "~> 0.7"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
