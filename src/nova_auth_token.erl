-module(nova_auth_token).
-moduledoc ~"""
Cryptographic token generation, hashing, and time-based validation.
Tokens are base64-encoded random bytes, hashed with SHA-256 for storage.
""".

-include("../include/nova_auth.hrl").

-export([generate/0, generate/1, hash/1, valid/1, valid/2]).

-doc "Generate a random token using the default byte size.".
-spec generate() -> binary().
generate() ->
    generate(?NOVA_AUTH_DEFAULT_TOKEN_BYTES).

-doc "Generate a random token with the specified number of random bytes.".
-spec generate(pos_integer()) -> binary().
generate(Bytes) ->
    base64:encode(crypto:strong_rand_bytes(Bytes)).

-doc "SHA-256 hash a raw token for safe database storage.".
-spec hash(binary()) -> binary().
hash(RawToken) ->
    Raw = base64:decode(RawToken),
    base64:encode(crypto:hash(sha256, Raw)).

-doc "Check if a token is still valid using the default session validity period.".
-spec valid(calendar:datetime()) -> boolean().
valid(InsertedAt) ->
    valid(InsertedAt, ?NOVA_AUTH_DEFAULT_SESSION_VALIDITY_DAYS).

-doc "Check if a token inserted at `InsertedAt` is within `ValidityDays` of now.".
-spec valid(calendar:datetime(), pos_integer()) -> boolean().
valid(InsertedAt, ValidityDays) ->
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    TokenTime = calendar:datetime_to_gregorian_seconds(InsertedAt),
    (Now - TokenTime) < (ValidityDays * 24 * 60 * 60).
