# Nova Auth

Authentication library for the [Nova](https://github.com/novaframework/nova) ecosystem.

Provides a unified actor session, claims mapping, authorization policies, and optional password-based authentication. Works standalone or as the foundation for [nova_auth_oidc](https://github.com/novaframework/nova_auth_oidc).

## Features

- **Unified actor session** -- Strategy-agnostic session storage. Password auth, OIDC, JWT -- all produce the same actor map in the session.
- **Claims mapping** -- Transform provider-specific claims to actor maps with static maps or callback functions.
- **Security callbacks** -- Drop-in Nova security function for protecting route groups.
- **Policy helpers** -- Composable authorization policies (role-based, claim-based, ownership, authenticated).
- **Rate limiting** -- Nova plugin with configurable sliding-window rate limiting via Seki.
- **Password auth** (optional, requires [Kura](https://github.com/Taure/kura)) -- PBKDF2-SHA256 hashing, URL-safe session tokens, email confirmation, password reset.
- **Timing-safe** -- Dummy verification on failed lookups to prevent user enumeration.

## Quick Start

Add `nova_auth` to your deps (it is on [Hex](https://hex.pm/packages/nova_auth)):

```erlang
{deps, [
    {nova_auth, "~> 0.2"}
]}.
```

Password auth also needs Kura and its Postgres backend in your own deps:

```erlang
{deps, [
    {nova_auth, "~> 0.2"},
    {kura, "~> 2.0"},
    {kura_postgres, "~> 1.1"}
]}.
```

### OIDC-only (no database)

If you only need actor sessions and policies (e.g., with [nova_auth_oidc](https://github.com/novaframework/nova_auth_oidc)):

```erlang
%% Protect routes -- works with any auth strategy that stores an actor
#{prefix => ~"/dashboard",
  security => nova_auth_security:require_authenticated(),
  routes => [
      {~"/profile", fun my_controller:profile/1, #{methods => [get]}}
  ]}

%% Access actor in controller
profile(#{auth_data := Actor} = _Req) ->
    Email = maps:get(email, Actor, ~"unknown"),
    {json, #{email => Email}}.
```

### Password auth (requires Kura)

Create a config module implementing the `nova_auth` behaviour:

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

Register and authenticate:

```erlang
%% Register
{ok, User} = nova_auth_accounts:register(
    my_auth, fun my_user:registration_changeset/2, Params
).

%% Authenticate, renew the session (prevents session fixation), store the actor
{ok, User} = nova_auth_accounts:authenticate(my_auth, ~"user@example.com", ~"password123456").
{ok, Req1} = nova_auth_actor:renew(Req).
ok = nova_auth_actor:store(Req1, #{id => maps:get(id, User), provider => password, email => maps:get(email, User)}).

%% Session token (database-backed)
{ok, Token} = nova_auth_session:generate_session_token(my_auth, User).
```

## Modules

### Core (no dependencies beyond Nova)

| Module | Description |
|--------|-------------|
| `nova_auth_actor` | Store/fetch actor maps from Nova session |
| `nova_auth_claims` | Transform provider claims to actor maps |
| `nova_auth_security` | Route-level security callbacks |
| `nova_auth_policy` | Authorization policies for nova_resource |
| `nova_auth_rate_limit` | Rate limiting Nova plugin |

### Password auth (requires Kura)

| Module | Description |
|--------|-------------|
| `nova_auth_accounts` | Registration, authentication, password/identity changes |
| `nova_auth_session` | Database-backed session token management |
| `nova_auth_password` | PBKDF2-SHA256 password hashing |
| `nova_auth_token` | Token generation and validation |
| `nova_auth_confirm` | Email confirmation flow |
| `nova_auth_reset` | Password reset flow |

## Configuration

Password auth options (all optional with defaults):

| Option | Default | Description |
|--------|---------|-------------|
| `repo` | -- | Kura repo module (required for password auth) |
| `user_schema` | -- | Kura user schema module |
| `token_schema` | -- | Kura token schema module |
| `user_identity_field` | `email` | Field used for login lookup |
| `user_password_field` | `hashed_password` | Field storing the password hash |
| `session_validity_days` | `14` | Days before session tokens expire |
| `confirm_validity_days` | `3` | Days before confirmation tokens expire |
| `reset_validity_hours` | `1` | Hours before reset tokens expire |
| `hash_algorithm` | `pbkdf2_sha256` | Password hashing algorithm; `pbkdf2_sha256` is the only one implemented, other values raise |
| `token_bytes` | `32` | Random bytes for token generation |
| `require_confirmed` | `false` | Refuse sign-in for users without `confirmed_at` (`{error, unconfirmed}`) |

## Guides

- [Getting Started](guides/getting-started.md) -- Installation and first setup
- [Configuration](guides/configuration.md) -- Full configuration reference
- [Actor Session](guides/actor-session.md) -- How the unified actor session works
- [Claims Mapping](guides/claims-mapping.md) -- Transforming provider claims
- [Policies](guides/policies.md) -- Authorization with nova_resource
- [Rate Limiting](guides/rate-limiting.md) -- Protecting routes from abuse

## Related Libraries

- [nova_auth_oidc](https://github.com/novaframework/nova_auth_oidc) -- OIDC login, JWT bearer validation, token introspection, client credentials
- [Nova](https://github.com/novaframework/nova) -- Web framework
- [Kura](https://github.com/Taure/kura) -- Database layer (optional)
- [Seki](https://github.com/Taure/seki) -- Rate limiting

## Requirements

- Erlang/OTP 28+
- Nova 0.19+ (`nova_auth_actor:renew/1` delegates to `nova_session:renew/1`)
- PostgreSQL via Kura and `kura_postgres` (only for password auth)

## Upgrading from 0.2

These changes can break an existing app:

- **`hash_algorithm`:** `bcrypt` or `argon2` (or any value other than
  `pbkdf2_sha256`) now raises `{unsupported_hash_algorithm, Value}` from
  `nova_auth:config/1`. Set `hash_algorithm => pbkdf2_sha256` or remove it;
  stored hashes are already PBKDF2 because bcrypt/argon2 silently fell back to it.
- **`pbkdf2_iterations`:** a value that is not a positive integer now raises
  `{invalid_pbkdf2_iterations, Value}`.
- **`nova_auth_password:hash/2`:** the spec is `hash(binary(), atom())` and
  only `pbkdf2_sha256` is accepted; other algorithms raise.
- **Rate-limit options now take effect:** a route that passed only some
  options used to crash the plugin (badmatch) on every request; missing
  options now fall back to the defaults and the given ones apply, so those
  routes start limiting (and replying 429) instead of failing.
- **`key_fun` is replaced by `key`:** `nova_auth_rate_limit` takes
  `key => {Module, Function}` and rejects `key_fun` with
  `error({removed_option, key_fun})`.
- **Token length:** new tokens are URL-safe base64 without padding, 43
  characters for the default 32 bytes instead of 44. Tokens issued by 0.2
  still verify. Widen any column or validation that expects 44 characters.
- **Nova floor:** nova_auth now needs Nova 0.19 or later.

## License

Apache-2.0
