-module(nova_auth_token).
-moduledoc ~"""
Cryptographic token generation, hashing, and time-based validation.

Tokens are random bytes encoded as URL-safe base64 without padding
(RFC 4648 section 5), so they can go into URLs, query strings and cookies
without escaping. They are hashed with SHA-256 for storage.

Tokens issued by earlier releases used standard base64 (`+`, `/`, `=`).
`hash/1` accepts both alphabets, so those tokens keep working.
""".

-include("../include/nova_auth.hrl").

-export([generate/0, generate/1, hash/1, lookup_hash/1, valid/1, valid/2]).

-doc "Generate a random token using the default byte size.".
-spec generate() -> binary().
generate() ->
    generate(?NOVA_AUTH_DEFAULT_TOKEN_BYTES).

-doc "Generate a random token with the specified number of random bytes.".
-spec generate(pos_integer()) -> binary().
generate(Bytes) ->
    base64:encode(crypto:strong_rand_bytes(Bytes), #{mode => urlsafe, padding => false}).

-doc """
SHA-256 hash a raw token for safe database storage.

Accepts URL-safe and standard base64, with or without padding. A token and
its other-alphabet spelling hash to the same value.
""".
-spec hash(binary()) -> binary().
hash(RawToken) ->
    Raw = base64:decode(to_standard_alphabet(RawToken), #{padding => false}),
    base64:encode(crypto:hash(sha256, Raw)).

-doc """
Hash a token presented by a client for a lookup.

Like `hash/1`, but a value that is not base64 (a junk bearer token, a
truncated link) gives `{error, invalid_token}` instead of raising.
""".
-spec lookup_hash(term()) -> {ok, binary()} | {error, invalid_token}.
lookup_hash(RawToken) when is_binary(RawToken) ->
    try
        {ok, hash(RawToken)}
    catch
        error:_ -> {error, invalid_token}
    end;
lookup_hash(_RawToken) ->
    {error, invalid_token}.

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

to_standard_alphabet(Token) ->
    binary:replace(binary:replace(Token, ~"-", ~"+", [global]), ~"_", ~"/", [global]).
