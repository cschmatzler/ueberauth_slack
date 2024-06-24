# Überauth Slack

> Slack OAuth2 strategy for Überauth.

## Installation

1. Add `:ueberauth_slack` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [
        {:ueberauth_slack, "~> 0.1"}
      ]
    end
    ```

3. Add Slack to your Überauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        slack: {Ueberauth.Strategy.Slack, []}
      ]
    ```

4. Update your provider configuration:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.Slack.OAuth,
      client_id: System.get_env("SLACK_CLIENT_ID"),
      client_secret: System.get_env("SLACK_CLIENT_SECRET")
    ```

## Calling

Depending on the configured url you can initiate the request through:

    /auth/slack

Or with options:

    /auth/slack?scope=channels:read

Scope can be configured either explicitly as a `scope` query value on the request path or in your configuration:

```elixir
config :ueberauth, Ueberauth,
  providers: [
    slack: {Ueberauth.Strategy.Slack, [default_scope: "channels:read"]}
  ]
```

It is also possible to disable the sending of the `redirect_uri` to Slack. This is particularly useful when your production application sits
behind a proxy that handles SSL connections. In this case, the `redirect_uri` sent by `Ueberauth` will start with `http` instead of `https`,
and if you configured your Slack OAuth application's callback URL to use HTTPS, Slack will throw an `uri_mismatch` error.

To prevent `Ueberauth` from sending the `redirect_uri`, you should add the following to your configuration:

```elixir
config :ueberauth, Ueberauth,
  providers: [
    slack: {Ueberauth.Strategy.Slack, [send_redirect_uri: false]}
  ]
```
