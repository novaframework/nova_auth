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

-export([generate/0, generate/1, hash/1, valid/1, valid/2, purge_expired/1]).

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

-doc """
Delete every expired token of the auth module `AuthMod` from its token table.

Covers session, confirm, reset, access and refresh tokens, each against its
own validity setting (`session_validity_days`, `confirm_validity_days`,
`reset_validity_hours`, `access_token_validity_minutes`,
`refresh_token_validity_days`), in one parameterised `DELETE`. Returns the
number of rows deleted. Tokens of any other context are left alone.

Expired tokens already fail validation; purging only keeps the table small.
Run it periodically, for example from a scheduled job.
""".
-spec purge_expired(module()) -> {ok, non_neg_integer()} | {error, term()}.
purge_expired(AuthMod) ->
    #{repo := Repo, token_schema := TokenSchema} = Cfg = nova_auth:config(AuthMod),
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    Expired = [
        {'and', [{context, Context}, {inserted_at, '<', cutoff(Now, Seconds)}]}
     || {Context, Seconds} <- validity_seconds(Cfg)
    ],
    Q = kura_query:where(kura_query:from(TokenSchema), {'or', Expired}),
    kura_repo_worker:delete_all(Repo, Q).

validity_seconds(Cfg) ->
    #{
        session_validity_days := SessionDays,
        confirm_validity_days := ConfirmDays,
        reset_validity_hours := ResetHours,
        access_token_validity_minutes := AccessMinutes,
        refresh_token_validity_days := RefreshDays
    } = Cfg,
    [
        {~"session", SessionDays * 86400},
        {~"confirm", ConfirmDays * 86400},
        {~"reset", ResetHours * 3600},
        {~"access", AccessMinutes * 60},
        {~"refresh", RefreshDays * 86400}
    ].

cutoff(Now, Seconds) ->
    calendar:gregorian_seconds_to_datetime(Now - Seconds).
