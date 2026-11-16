# Actor Session

The actor session is the central concept in nova_auth. Regardless of how a user
authenticates (password, OIDC, JWT, custom), the result is an **actor map** stored
in the Nova session. All downstream code -- security callbacks, policies,
controllers -- works with this unified actor.

## How It Works

```
Password login ──┐
                  │
OIDC callback  ───┼──▶ nova_auth_actor:sign_in(Req, Actor) ──▶ Nova ETS Session
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

### Sign in

```erlang
{ok, SignedIn} = nova_auth_actor:sign_in(Req, #{
    id => ~"abc123",
    provider => password,
    email => ~"user@example.com"
}).
```

`sign_in/2` stores the actor and returns the request to go on with. On a Nova
whose `nova_session` module has `sign_in` the client is moved to a new session
id and what the session held before is deleted, so use `SignedIn` for every session
call that follows. A `nova_csrf_plugin` token made for the old id is refused
from then on, so answer a form sign-in with a redirect. On an earlier Nova
the actor is stored in the session the request has and the same request comes
back.

`store/2` is deprecated. It still stores the actor and returns `ok`, and it
leaves the session id as it was.

### Fetch

```erlang
case nova_auth_actor:fetch(Req) of
    {ok, Actor} -> Actor;
    {error, not_found} -> not_logged_in
end.
```

### Delete (logout)

```erlang
{ok, _Req} = nova_auth_actor:delete(Req).
```

This deletes the whole session of the request, not only the actor.

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
%% Password login signs the actor in
{ok, _SignedIn} = nova_auth_actor:sign_in(Req, #{id => UserId, provider => password, ...}).

%% OIDC callback signs the actor in (done by nova_auth_oidc_controller)
{ok, _SignedIn} = nova_auth_actor:sign_in(Req, #{id => Sub, provider => authentik, ...}).

%% Same security callback protects both
security => nova_auth_security:require_authenticated()
```
