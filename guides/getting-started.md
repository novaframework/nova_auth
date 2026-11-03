# Getting Started

## Installation

Add `nova_auth` to your `rebar.config` dependencies:

```erlang
{deps, [
    {nova_auth, "~> 0.2"}
]}.
```

For password auth also add Kura and its Postgres backend:

```erlang
{deps, [
    {nova_auth, "~> 0.2"},
    {kura, "~> 2.0"},
    {kura_postgres, "~> 1.1"}
]}.
```

## Choose Your Strategy

nova_auth supports two usage patterns:

1. **Core only** -- actor sessions, claims mapping, policies, security callbacks. No database required.
2. **Password auth** -- adds registration, login, session tokens, confirmation, reset. Requires [Kura](https://github.com/Taure/kura).

For OIDC/OAuth2, see [nova_auth_oidc](https://github.com/novaframework/nova_auth_oidc) which builds on nova_auth's actor session.

## Core Only (No Database)

### Protect routes

Use `nova_auth_security:require_authenticated/0` to protect route groups:

```erlang
#{prefix => ~"/dashboard",
  security => nova_auth_security:require_authenticated(),
  routes => [
      {~"/profile", fun my_controller:profile/1, #{methods => [get]}}
  ]}
```

Any request without an actor in the session gets a 401 JSON response automatically.

### Access the actor in controllers

The actor is passed as `auth_data` in the request map:

```erlang
profile(#{auth_data := Actor} = _Req) ->
    #{id := Id, email := Email} = Actor,
    {json, #{id => Id, email => Email}}.
```

### Store an actor manually

If you have your own authentication logic, store the actor directly. Renew
the session first, so a session id that was planted or observed before
sign-in stops working (session fixation), and return the renewed request so
the new cookie reaches the client:

```erlang
{ok, Req1} = nova_auth_actor:renew(Req),
ok = nova_auth_actor:store(Req1, #{
    id => ~"user-123",
    provider => my_custom_auth,
    email => ~"user@example.com",
    roles => [admin]
}),
{redirect, ~"/dashboard", Req1}.
```

## Password Auth (Requires Kura)

### Configuration module

Create a module implementing the `nova_auth` behaviour:

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

### User schema

Define a Kura schema for your users table:

```erlang
-module(my_user).
-behaviour(kura_schema).
-export([schema/0, changeset/2, registration_changeset/2]).

schema() ->
    #{
        source => ~"users",
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

### Token schema

Define a Kura schema for the user tokens table:

```erlang
-module(my_user_token).
-behaviour(kura_schema).
-export([schema/0]).

schema() ->
    #{
        source => ~"user_tokens",
        fields => #{
            id => #{type => integer, primary_key => true},
            user_id => #{type => integer},
            token => #{type => string},
            context => #{type => string},
            inserted_at => #{type => utc_datetime}
        }
    }.
```

### Registration

```erlang
handle_register(Req) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    Params = json:decode(Body),
    case nova_auth_accounts:register(my_auth, fun my_user:registration_changeset/2, Params) of
        {ok, User} ->
            {ok, Req2} = nova_auth_actor:renew(Req1),
            ok = nova_auth_actor:store(Req2, #{
                id => maps:get(id, User),
                provider => password,
                email => maps:get(email, User)
            }),
            {json, 201, #{}, Req2, #{~"id" => maps:get(id, User)}};
        {error, Changeset} ->
            {json, 422, #{}, #{~"errors" => kura_changeset:errors(Changeset)}}
    end.
```

### Login

```erlang
handle_login(Req) ->
    {ok, Body, Req1} = cowboy_req:read_body(Req),
    #{~"email" := Email, ~"password" := Password} = json:decode(Body),
    case nova_auth_accounts:authenticate(my_auth, Email, Password) of
        {ok, User} ->
            {ok, Req2} = nova_auth_actor:renew(Req1),
            ok = nova_auth_actor:store(Req2, #{
                id => maps:get(id, User),
                provider => password,
                email => maps:get(email, User)
            }),
            {json, 200, #{}, Req2, #{~"user_id" => maps:get(id, User)}};
        {error, invalid_credentials} ->
            {json, 401, #{}, #{~"error" => ~"invalid credentials"}}
    end.
```

### Logout

```erlang
handle_logout(Req) ->
    {ok, Req1} = nova_auth_actor:renew(Req),
    {json, 200, #{}, Req1, #{~"ok" => true}}.
```

`renew/1` drops the whole session, actor included, and moves the client to a
new session id.

### Tokens in links

Session, confirmation and reset tokens are URL-safe base64 without padding,
so they can be put in a link as they are:

```erlang
{ok, Token} = nova_auth_reset:generate_reset_token(my_auth, User),
Link = <<"https://example.com/password/reset?token=", Token/binary>>.
```

Tokens issued by nova_auth 0.2.0 and earlier used standard base64 and are
still accepted; URL-encode those (`uri_string:compose_query/1`) if you put
them in a link.
