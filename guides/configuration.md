# Configuration

All configuration is provided through the `config/0` callback in your module
implementing `-behaviour(nova_auth)`. The returned map is merged with defaults
and cached in `persistent_term` for fast access.

## Required Keys

| Key | Type | Description |
|-----|------|-------------|
| `repo` | `module()` | Your Kura repo module |
| `user_schema` | `module()` | Kura schema for the users table |
| `token_schema` | `module()` | Kura schema for the user tokens table |

## Optional Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `user_identity_field` | `atom()` | `email` | Field used for user lookup during authentication |
| `user_password_field` | `atom()` | `hashed_password` | Field storing the password hash on the user record |
| `session_validity_days` | `pos_integer()` | `14` | How long session tokens remain valid (days) |
| `confirm_validity_days` | `pos_integer()` | `3` | How long email confirmation tokens remain valid (days) |
| `reset_validity_hours` | `pos_integer()` | `1` | How long password reset tokens remain valid (hours) |
| `hash_algorithm` | `atom()` | `pbkdf2_sha256` | Password hashing algorithm |
| `token_bytes` | `pos_integer()` | `32` | Number of random bytes for token generation |

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

## Password Hashing

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

Tokens are generated as base64-encoded random bytes (`crypto:strong_rand_bytes/1`).
Only the SHA-256 hash of the token is stored in the database. The raw token is
returned to the caller once and never stored.

## Cache Invalidation

Configuration is cached in `persistent_term`. If you change your config at
runtime, call `nova_auth:invalidate_cache(MyAuthMod)` to force a refresh.
