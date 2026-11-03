# Configuration

All configuration is provided through the `config/0` callback in your module
implementing `-behaviour(nova_auth)`. The returned map is merged with defaults
and cached in `persistent_term` for fast access.

## Password Auth Keys

These keys are only required when using password authentication modules
(`nova_auth_accounts`, `nova_auth_session`, etc.). OIDC-only applications
can omit them entirely.

### Required (for password auth)

| Key | Type | Description |
|-----|------|-------------|
| `repo` | `module()` | Your Kura repo module |
| `user_schema` | `module()` | Kura schema for the users table |
| `token_schema` | `module()` | Kura schema for the user tokens table |

### Optional

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `user_identity_field` | `atom()` | `email` | Field used for user lookup during authentication |
| `user_password_field` | `atom()` | `hashed_password` | Field storing the password hash on the user record |
| `session_validity_days` | `pos_integer()` | `14` | How long session tokens remain valid (days) |
| `confirm_validity_days` | `pos_integer()` | `3` | How long email confirmation tokens remain valid (days) |
| `reset_validity_hours` | `pos_integer()` | `1` | How long password reset tokens remain valid (hours) |
| `access_token_validity_minutes` | `pos_integer()` | `60` | How long `nova_auth_refresh` access tokens remain valid (minutes) |
| `refresh_token_validity_days` | `pos_integer()` | `30` | How long `nova_auth_refresh` refresh tokens remain valid (days) |
| `hash_algorithm` | `pbkdf2_sha256` | `pbkdf2_sha256` | Password hashing algorithm. PBKDF2-SHA256 is the only one implemented; any other value (`bcrypt`, `argon2`, ...) makes `nova_auth:config/1` raise `{unsupported_hash_algorithm, Value}`. The config is read lazily, so the error shows up on the first `nova_auth:config/1` call (usually the first sign-in or registration), not at boot |
| `token_bytes` | `pos_integer()` | `32` | Number of random bytes for token generation |
| `require_confirmed` | `boolean()` | `false` | When `true`, `nova_auth_accounts:authenticate/3` returns `{error, unconfirmed}` for a correct password if the user's `confirmed_at` is not set |

## Full Example

```erlang
-module(my_auth).
-behaviour(nova_auth).
-export([config/0]).

config() ->
    #{
        repo => my_repo,
        user_schema => my_user,
        token_schema => my_user_token,
        user_identity_field => email,
        user_password_field => hashed_password,
        session_validity_days => 30,
        confirm_validity_days => 7,
        reset_validity_hours => 2,
        hash_algorithm => pbkdf2_sha256,
        token_bytes => 64
    }.
```

## Actor Type

All authentication strategies produce an actor map stored in the Nova session.
The actor type is defined as:

```erlang
-type actor() :: #{
    id := binary() | integer(),
    provider := atom(),
    atom() => term()
}.
```

The `id` and `provider` fields are required. Additional fields (email, roles, etc.)
depend on your authentication strategy and claims mapping.

## Password Hashing

`pbkdf2_iterations` in the `nova_auth` application env must be a positive
integer; any other value raises `{invalid_pbkdf2_iterations, Value}` on the
first hash or verify.

The default algorithm is PBKDF2-SHA256 with these parameters:

- **Iterations:** 600,000
- **Key length:** 32 bytes
- **Salt:** 16 bytes (generated via `crypto:strong_rand_bytes/1`)

Hashes are stored in PHC string format:

```
$pbkdf2-sha256$600000$<base64-salt>$<base64-hash>
```

Verification uses `crypto:hash_equals/2` for constant-time comparison to prevent
timing attacks. Failed lookups call `nova_auth_password:dummy_verify/0` to
prevent user enumeration.

## Token Generation

Tokens are random bytes (`crypto:strong_rand_bytes/1`) encoded as URL-safe
base64 without padding, so they can go into links and cookies without
escaping. Only the SHA-256 hash of the token is stored in the database. The
raw token is returned to the caller once and never stored.

Tokens issued by nova_auth 0.2.0 and earlier used standard base64 (`+`, `/`,
`=`). They are still accepted, and their stored hashes are unchanged.

## Requiring Confirmed Accounts

By default `nova_auth_accounts:authenticate/3` signs in users whether or not
they have confirmed their email. Set `require_confirmed => true` to refuse
unconfirmed users:

```erlang
case nova_auth_accounts:authenticate(my_auth, Email, Password) of
    {ok, User} -> sign_in(User);
    {error, unconfirmed} -> ask_to_confirm(Email);
    {error, invalid_credentials} -> refuse()
end.
```

The password is always verified first, so an unconfirmed account takes as
long to answer as any other attempt. `{error, unconfirmed}` is only
returned for the correct password; a wrong password is still
`{error, invalid_credentials}`. The check reads the `confirmed_at` field
that `nova_auth_confirm:confirm_user/2` sets.

`nova_auth_accounts:change_identity/4` leaves `confirmed_at` to your
schema's `email_changeset/2`. Apps usually require a new address to be
confirmed again, by clearing it when the email changes:

```erlang
email_changeset(User, Params) ->
    CS = kura_changeset:validate_required(kura_changeset:cast(?MODULE, User, Params, [email]), [email]),
    case kura_changeset:get_change(CS, email) of
        undefined -> CS;
        _ -> kura_changeset:put_change(CS, confirmed_at, undefined)
    end.
```

## Purging Expired Tokens

`nova_auth_session:purge_expired_tokens/1` deletes the tokens that are past their
validity setting above. See the Getting Started guide for running it on a
schedule.

## Cache Invalidation

Configuration is cached in `persistent_term`. If you change your config at
runtime, call `nova_auth:invalidate_cache(MyAuthMod)` to force a refresh.
