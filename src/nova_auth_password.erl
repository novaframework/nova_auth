-module(nova_auth_password).
-moduledoc ~"""
Password hashing and verification using PBKDF2-SHA256. Includes constant-time
comparison and dummy verification to prevent user enumeration via timing attacks.

## Configuration

Set iterations via application environment:

```erlang
{nova_auth, [{pbkdf2_iterations, 600000}]}.
```

OWASP recommends 600,000 for PBKDF2-SHA256 (default). Lower values trade
security margin for speed — 100,000+ is reasonable for game backends.
""".

-export([hash/1, hash/2, verify/2, dummy_verify/0]).

-define(DEFAULT_ITERATIONS, 600000).
-define(PBKDF2_LENGTH, 32).

-doc "Hash a password using the default algorithm (PBKDF2-SHA256).".
-spec hash(binary()) -> binary().
hash(Password) ->
    hash(Password, pbkdf2_sha256).

-doc """
Hash a password using the specified algorithm.

Only `pbkdf2_sha256` is implemented. Any other algorithm, including
`bcrypt` and `argon2`, raises `error({unsupported_hash_algorithm, Algorithm})`
rather than silently hashing with a different algorithm.
""".
-spec hash(binary(), atom()) -> binary().
hash(Password, pbkdf2_sha256) ->
    Iterations = iterations(),
    Salt = crypto:strong_rand_bytes(16),
    DK = crypto:pbkdf2_hmac(sha256, Password, Salt, Iterations, ?PBKDF2_LENGTH),
    IterBin = integer_to_binary(Iterations),
    <<"$pbkdf2-sha256$", IterBin/binary, "$", (base64:encode(Salt))/binary, "$",
        (base64:encode(DK))/binary>>;
hash(_Password, Algorithm) ->
    error({unsupported_hash_algorithm, Algorithm}).

-doc "Verify a password against a stored hash using constant-time comparison.".
-spec verify(binary(), binary()) -> boolean().
verify(Password, <<"$pbkdf2-sha256$", Rest/binary>>) ->
    case binary:split(Rest, <<"$">>, [global]) of
        [IterBin, SaltB64, HashB64] ->
            Iterations = binary_to_integer(IterBin),
            Salt = base64:decode(SaltB64),
            ExpectedDK = base64:decode(HashB64),
            ActualDK = crypto:pbkdf2_hmac(
                sha256, Password, Salt, Iterations, byte_size(ExpectedDK)
            ),
            crypto:hash_equals(ActualDK, ExpectedDK);
        _ ->
            false
    end;
verify(_Password, _Hash) ->
    false.

-doc "Simulate password verification timing to prevent user enumeration.".
-spec dummy_verify() -> false.
dummy_verify() ->
    Iterations = iterations(),
    Salt = crypto:strong_rand_bytes(16),
    _ = crypto:pbkdf2_hmac(sha256, <<"dummy">>, Salt, Iterations, ?PBKDF2_LENGTH),
    false.

%% --- Internal ---

-spec iterations() -> pos_integer().
iterations() ->
    case application:get_env(nova_auth, pbkdf2_iterations, ?DEFAULT_ITERATIONS) of
        Iterations when is_integer(Iterations), Iterations > 0 -> Iterations;
        Other -> error({invalid_pbkdf2_iterations, Other})
    end.
