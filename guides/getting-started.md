# Getting Started

## Installation

Add `nova_auth` to your `rebar.config` dependencies:

```erlang
{deps, [
    {nova_auth, {git, "https://github.com/novaframework/nova_auth.git", {branch, "main"}}}
]}.
```

## Configuration Module

Create a module implementing the `nova_auth` behaviour. This defines your repo,
schemas, and authentication settings:

```erlang
-module(my_auth).
-behaviour(nova_auth).
-export([config/0]).

config() ->
    #{
        repo => my_repo,
        user_schema => my_user,
        token_schema => my_user_token
    }.
```

All other options have sensible defaults (see the [Configuration](configuration.md) guide).

## User Schema

Define a Kura schema for your users table:

```erlang
-module(my_user).
-behaviour(kura_schema).
-export([schema/0, changeset/2, registration_changeset/2]).

schema() ->
    #{
        source => <<"users">>,
        fields => #{
            id => #{type => integer, primary_key => true},
            email => #{type => string},
            hashed_password => #{type => string},
            confirmed_at => #{type => utc_datetime, default => undefined},
            inserted_at => #{type => utc_datetime},
            updated_at => #{type => utc_datetime}
        }
    }.

changeset(Data, Params) ->
    kura_changeset:cast(my_user, Data, Params, [email]).

registration_changeset(Data, Params) ->
    CS = kura_changeset:cast(my_user, Data, Params, [email, password]),
    case kura_changeset:get_change(CS, password) of
        undefined -> CS;
        Password ->
            Hashed = nova_auth_password:hash(Password),
            kura_changeset:put_change(CS, hashed_password, Hashed)
    end.
```

## Token Schema

Define a Kura schema for the user tokens table:

```erlang
-module(my_user_token).
-behaviour(kura_schema).
-export([schema/0]).

schema() ->
    #{
        source => <<"user_tokens">>,
        fields => #{
            id => #{type => integer, primary_key => true},
            user_id => #{type => integer},
            token => #{type => string},
            context => #{type => string},
            inserted_at => #{type => utc_datetime}
        }
    }.
```

## Route Protection

Use `nova_auth_security:require_authenticated/1` in your Nova route groups to
protect endpoints:

```erlang
%% In your Nova router
#{prefix => "/api",
  security => nova_auth_security:require_authenticated(my_auth),
  routes => [
      {"/profile", {my_profile_controller, handle}, #{methods => [get]}}
  ]}
```

The security function checks the session for a valid token. If the user is
authenticated, the user map is passed as the security state. If not, a 401
JSON response is returned automatically.

## Registration

Register a user with a changeset function:

```erlang
handle_register(Req) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    Params = json:decode(Body),
    case nova_auth_accounts:register(my_auth, fun my_user:registration_changeset/2, Params) of
        {ok, User} ->
            {json, 201, #{}, #{<<"id">> => maps:get(id, User)}};
        {error, Changeset} ->
            {json, 422, #{}, #{<<"errors">> => kura_changeset:errors(Changeset)}}
    end.
```

## Login

Authenticate and create a session:

```erlang
handle_login(Req) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    #{<<"email">> := Email, <<"password">> := Password} = json:decode(Body),
    case nova_auth_accounts:authenticate(my_auth, Email, Password) of
        {ok, User} ->
            {ok, Token} = nova_auth_session:generate_session_token(my_auth, User),
            Req2 = nova_session:set(Req1, <<"session_token">>, Token),
            {json, 200, #{}, #{<<"user_id">> => maps:get(id, User)}};
        {error, invalid_credentials} ->
            {json, 401, #{}, #{<<"error">> => <<"invalid credentials">>}}
    end.
```

## Logout

Delete the session token:

```erlang
handle_logout(Req) ->
    case nova_session:get(Req, <<"session_token">>) of
        {ok, Token} ->
            nova_auth_session:delete_session_token(my_auth, Token),
            {json, 200, #{}, #{<<"ok">> => true}};
        _ ->
            {json, 200, #{}, #{<<"ok">> => true}}
    end.
```
