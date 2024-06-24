defmodule Ueberauth.Strategy.Slack do
  use Ueberauth.Strategy,
    uid_field: :email,
    default_scope: "",
    oauth2_module: Ueberauth.Strategy.Slack.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  def handle_request!(conn) do
    opts =
      []
      |> with_scopes(conn)
      |> with_state_param(conn)
      |> with_redirect_uri(conn)

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  defp with_scopes(opts, conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)

    opts |> Keyword.put(:scope, scopes)
  end

  defp with_redirect_uri(opts, conn) do
    if option(conn, :send_redirect_uri) do
      opts |> Keyword.put(:redirect_uri, callback_url(conn))
    else
      opts
    end
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    token = apply(module, :get_token!, [[code: code]])

    if token.access_token == nil do
      set_errors!(conn, [
        error(token.other_params["error"], token.other_params["error_description"])
      ])
    else
      conn
      |> store_token(token)
      |> fetch_auth(token)
      |> fetch_identity(token)
      |> fetch_user(token)
      |> fetch_team(token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  defp store_token(conn, token) do
    put_private(conn, :slack_token, token)
  end

  defp fetch_auth(conn, token) do
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")
    case Ueberauth.Strategy.Slack.OAuth.get(token, "/auth.test") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: auth}} when status_code in 200..399 ->
        cond do
          auth["ok"] ->
            put_private(conn, :slack_auth, auth)

          auth["error"] == "invalid_auth" && Enum.member?(scopes, "identity.basic") ->
            conn

          true ->
            set_errors!(conn, [error(auth["error"], auth["error"])])
        end

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp fetch_identity(conn, token) do
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    case "identity.basic" in scopes do
      false ->
        conn

      true ->
        get_users_identity(conn, token)
    end
  end

  defp get_users_identity(conn, token) do
    case Ueberauth.Strategy.Slack.OAuth.get(token, "/users.identity") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: identity}} when status_code in 200..399 ->
        if identity["ok"] do
          put_private(conn, :slack_identity, identity)
        else
          set_errors!(conn, [error(identity["error"], identity["error"])])
        end

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp fetch_user(%Plug.Conn{assigns: %{ueberauth_failure: _fails}} = conn, _), do: conn

  defp fetch_user(conn, token) do
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    case "users:read" in scopes do
      false ->
        conn

      true ->
        get_users_info(conn, token)
    end
  end

  defp get_users_info(conn, token) do
    opts = %{user: conn.private.slack_auth["user_id"]}

    case Ueberauth.Strategy.Slack.OAuth.get(token, "/users.info", opts) do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: user}}
      when status_code in 200..399 ->
        if user["ok"] do
          put_private(conn, :slack_user, user["user"])
        else
          set_errors!(conn, [error(user["error"], user["error"])])
        end

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp fetch_team(%Plug.Conn{assigns: %{ueberauth_failure: _fails}} = conn, _), do: conn

  defp fetch_team(conn, token) do
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    case "team:read" in scopes do
      false ->
        conn

      true ->
        get_team_info(conn, token)
    end
  end

  defp get_team_info(conn, token) do
    case Ueberauth.Strategy.Slack.OAuth.get(token, "/team.info") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %OAuth2.Response{status_code: status_code, body: team}}
      when status_code in 200..399 ->
        if team["ok"] do
          put_private(conn, :slack_team, team["team"])
        else
          set_errors!(conn, [error(team["error"], team["error"])])
        end

      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp name_from_user(nil), do: nil

  defp name_from_user(user) do
    [
      user["profile"]["real_name_normalized"],
      user["profile"]["real_name"],
      user["real_name"],
      user["name"]
    ]
    |> Enum.reject(&(&1 == "" || &1 == nil))
    |> List.first()
  end

  def handle_cleanup!(conn) do
    conn
    |> put_private(:slack_user, nil)
    |> put_private(:slack_token, nil)
  end

  def uid(conn) do
    Map.get(info(conn), option(conn, :uid_field))
  end

  def credentials(conn) do
    token = conn.private.slack_token
    auth = conn.private[:slack_auth]
    identity = conn.private[:slack_identity]
    user = conn.private[:slack_user]
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes,
      other:
        Map.merge(
          %{
            user: get_in(auth, ["user"]),
            user_id: get_in(auth, ["user_id"]) || get_in(identity, ["user", "id"]),
            team: get_in(auth, ["team"]) || get_in(identity, ["team", "name"]),
            team_id: get_in(auth, ["team_id"]) || get_in(identity, ["team", "id"]),
            team_domain: get_in(identity, ["team", "domain"]),
            team_url: get_in(auth, ["url"])
          },
          user_credentials(user)
        )
    }
  end

  def info(conn) do
    user = conn.private[:slack_user]
    auth = conn.private[:slack_auth]
    identity = conn.private[:slack_identity]

    profile = get_in(user, ["profile"]) || get_in(identity, ["user"]) || %{}

    image_urls =
      profile
      |> Map.keys()
      |> Enum.filter(&(&1 =~ ~r/^image_/))
      |> Enum.into(%{}, &{&1, profile[&1]})

    team_image_urls =
      (identity || %{})
      |> Map.get("team", %{})
      |> Enum.filter(fn {key, _value} -> key =~ ~r/^image_/ end)
      |> Enum.into(%{}, fn {key, value} -> {"team_#{key}", value} end)

    %Info{
      name: name_from_user(user) || get_in(identity, ["user", "name"]),
      nickname: get_in(user, ["name"]),
      email: get_in(profile, ["email"]),
      image: get_in(profile, ["image_48"]),
      urls:
        image_urls
        |> Map.merge(team_image_urls)
        |> Map.merge(%{
          team_url: get_in(auth, ["url"])
        })
    }
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        auth: conn.private[:slack_auth],
        identity: conn.private[:slack_identity],
        token: conn.private[:slack_token],
        user: conn.private[:slack_user],
        team: conn.private[:slack_team]
      }
    }
  end

  defp user_credentials(nil), do: %{}

  defp user_credentials(user) do
    %{
      has_2fa: user["has_2fa"],
      is_admin: user["is_admin"],
      is_owner: user["is_owner"],
      is_primary_owner: user["is_primary_owner"],
      is_restricted: user["is_restricted"],
      is_ultra_restricted: user["is_ultra_restricted"]
    }
  end

  def uid(conn) do
    conn |> option(:uid_field) |> to_string()
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
