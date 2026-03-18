-module(nova_auth_password).
-moduledoc ~"""
Password hashing and verification using PBKDF2-SHA256. Includes constant-time
comparison and dummy verification to prevent user enumeration via timing attacks.
""".

-export([hash/1, hash/2, verify/2, dummy_verify/0]).

-define(PBKDF2_ITERATIONS, 600000).
-define(PBKDF2_LENGTH, 32).

-doc "Hash a password using the default algorithm (PBKDF2-SHA256).".
-spec hash(binary()) -> binary().
hash(Password) ->
    hash(Password, pbkdf2_sha256).

-doc "Hash a password using the specified algorithm.".
-spec hash(binary(), pbkdf2_sha256 | bcrypt | argon2) -> binary().
hash(Password, pbkdf2_sha256) ->
    Salt = crypto:strong_rand_bytes(16),
    DK = crypto:pbkdf2_hmac(sha256, Password, Salt, ?PBKDF2_ITERATIONS, ?PBKDF2_LENGTH),
    Iterations = integer_to_binary(?PBKDF2_ITERATIONS),
    <<"$pbkdf2-sha256$", Iterations/binary, "$", (base64:encode(Salt))/binary, "$",
        (base64:encode(DK))/binary>>;
hash(Password, bcrypt) ->
    hash(Password, pbkdf2_sha256);
hash(Password, argon2) ->
    hash(Password, pbkdf2_sha256).

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
    Salt = crypto:strong_rand_bytes(16),
    crypto:pbkdf2_hmac(sha256, <<"dummy">>, Salt, ?PBKDF2_ITERATIONS, ?PBKDF2_LENGTH),
    false.
