# Actor Session

The actor session is the central concept in nova_auth. Regardless of how a user
authenticates (password, OIDC, JWT, custom), the result is an **actor map** stored
in the Nova session. All downstream code -- security callbacks, policies,
controllers -- works with this unified actor.

## How It Works

```
Password login ──┐
                  │
OIDC callback  ───┼──▶ nova_auth_actor:store(Req, Actor) ──▶ Nova ETS Session
                  │
Custom auth    ───┘
                                     │
                                     ▼
                        nova_auth_actor:fetch(Req) ──▶ {ok, Actor}
                                     │
                                     ▼
                    nova_auth_security:require_authenticated()
                    nova_auth_policy:allow_role(admin)
                    Controller: #{auth_data := Actor}
```

## Actor Shape

An actor is a map with two required keys and any additional fields:

```erlang
#{
    id => ~"user-123",          %% required: unique identifier
    provider => authentik,      %% required: auth strategy
    email => ~"user@example.com",
    roles => [admin, editor],
    display_name => ~"Jane Doe"
}
```

The `provider` field identifies how the user authenticated. Common values:
`password`, `authentik`, `google`, `github`, `keycloak`.

## API

### Renew and store (sign-in)

```erlang
{ok, Req1} = nova_auth_actor:renew(Req),
ok = nova_auth_actor:store(Req1, #{
    id => ~"abc123",
    provider => password,
    email => ~"user@example.com"
}),
{redirect, ~"/", Req1}.
```

`renew/1` deletes the current session's data and moves the client to a new
session id. Call it at every privilege change (sign-in, sign-out, password
change) so a session id planted or observed before that point stops working
(session fixation). Store the actor with the returned request, and return it
from the controller so the new cookie is sent.

On Nova releases that provide `nova_session:renew/1`, `renew/1` calls it. On
older releases it deletes the session with `nova_session:delete/1` and sets a
new `session_id` cookie itself: a 256-bit `crypto:strong_rand_bytes/1` id,
`Path=/`, `HttpOnly`, `SameSite=Lax`, and `Secure` on HTTPS requests. The
`nova` application's `session_cookie_opts` map, when set, is merged over
those defaults (set `secure => true` behind a TLS-terminating proxy).

### Fetch

```erlang
case nova_auth_actor:fetch(Req) of
    {ok, Actor} -> Actor;
    {error, not_found} -> not_logged_in
end.
```

### Fetch and stored data

`fetch/1` decodes the stored actor with `binary_to_term(Bin, [safe])`, so it
never creates atoms, and only returns a map with an `id` (binary or integer)
and a `provider` atom. Anything else is `{error, not_found}`. With a session
backend that survives node restarts, an actor whose atoms (for example
`provider` or role atoms) are not loaded yet is treated as signed out.

### Delete (logout)

```erlang
{ok, Req1} = nova_auth_actor:renew(Req).
```

`renew/1` is the safest sign-out: it drops the whole session and its id.
`nova_auth_actor:delete/1` only removes the actor key and keeps the session id.

### The actor is a session copy

The actor is a copy taken at sign-in. `nova_auth_accounts:change_password/4`,
`change_identity/4` and `nova_auth_reset:reset_password/3` delete the user's
database tokens, but they cannot reach actors stored in other sessions, so
those sessions stay signed in as far as `nova_auth_security` is concerned.
If other sessions must end when the password changes, also store the session
token from `nova_auth_session:generate_session_token/2` in the session and
check it with `nova_auth_session:get_user_by_session_token/2` on each request
(or in your own security function), dropping the actor when it fails.

### Session Key

The actor is stored under the key `<<"nova_auth_actor">>`. You can retrieve it
with `nova_auth_actor:session_key()` if you need to reference it directly.

## Security Callbacks

`nova_auth_security:require_authenticated/0` returns a closure that checks
for an actor in the session:

```erlang
#{prefix => ~"/api",
  security => nova_auth_security:require_authenticated(),
  routes => [...]}
```

If authenticated, the actor is passed to the controller as `auth_data`:

```erlang
my_handler(#{auth_data := #{id := Id, roles := Roles}} = _Req) ->
    {json, #{id => Id, roles => Roles}}.
```

If not authenticated, a 401 JSON response is returned automatically.

## Mixed Auth Strategies

When using both password auth and OIDC, both strategies store actors in the
same session key. The security callback doesn't need to know which strategy
was used:

```erlang
%% Password login renews the session and stores the actor
{ok, Req1} = nova_auth_actor:renew(Req),
ok = nova_auth_actor:store(Req1, #{id => UserId, provider => password, ...}).

%% OIDC callback stores actor (done by nova_auth_oidc_controller)
ok = nova_auth_actor:store(Req, #{id => Sub, provider => authentik, ...}).

%% Same security callback protects both
security => nova_auth_security:require_authenticated()
```
