-module(nova_auth_token_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0]).
-export([
    generate_returns_url_safe_base64/1,
    generate_custom_bytes/1,
    hash_matches_standard_base64_spelling/1,
    hash_matches_legacy_storage_format/1,
    hash_rejects_invalid_token/1,
    lookup_hash_never_raises/1,
    generate_unique_tokens/1,
    hash_is_deterministic/1,
    hash_differs_from_raw/1,
    valid_fresh_token/1,
    valid_expired_token/1
]).

all() ->
    [{group, token_tests}].

groups() ->
    [
        {token_tests, [parallel], [
            generate_returns_url_safe_base64,
            generate_custom_bytes,
            hash_matches_standard_base64_spelling,
            hash_matches_legacy_storage_format,
            hash_rejects_invalid_token,
            lookup_hash_never_raises,
            generate_unique_tokens,
            hash_is_deterministic,
            hash_differs_from_raw,
            valid_fresh_token,
            valid_expired_token
        ]}
    ].

generate_returns_url_safe_base64(_Config) ->
    [
        begin
            Token = nova_auth_token:generate(),
            ?assertEqual(nomatch, binary:match(Token, [~"+", ~"/", ~"="])),
            ?assertEqual(Token, uri_string:quote(Token)),
            Decoded = base64:decode(Token, #{mode => urlsafe, padding => false}),
            ?assertEqual(32, byte_size(Decoded))
        end
     || _ <- lists:seq(1, 50)
    ].

generate_custom_bytes(_Config) ->
    Token = nova_auth_token:generate(64),
    Decoded = base64:decode(Token, #{mode => urlsafe, padding => false}),
    ?assertEqual(64, byte_size(Decoded)).

hash_matches_standard_base64_spelling(_Config) ->
    Raw = <<251, 255, 191, 0, 1, 2, 3>>,
    UrlSafe = base64:encode(Raw, #{mode => urlsafe, padding => false}),
    Standard = base64:encode(Raw),
    ?assertNotEqual(UrlSafe, Standard),
    ?assertEqual(nova_auth_token:hash(Standard), nova_auth_token:hash(UrlSafe)).

hash_matches_legacy_storage_format(_Config) ->
    Raw = crypto:strong_rand_bytes(32),
    LegacyToken = base64:encode(Raw),
    LegacyHash = base64:encode(crypto:hash(sha256, base64:decode(LegacyToken))),
    ?assertEqual(LegacyHash, nova_auth_token:hash(LegacyToken)).

lookup_hash_never_raises(_Config) ->
    Token = nova_auth_token:generate(),
    ?assertEqual({ok, nova_auth_token:hash(Token)}, nova_auth_token:lookup_hash(Token)),
    [
        ?assertEqual({error, invalid_token}, nova_auth_token:lookup_hash(Junk))
     || Junk <- [~"not a token!", ~"%%%", ~"a", 42, undefined]
    ].

hash_rejects_invalid_token(_Config) ->
    ?assertError(_, nova_auth_token:hash(~"not a token!")).

generate_unique_tokens(_Config) ->
    T1 = nova_auth_token:generate(),
    T2 = nova_auth_token:generate(),
    ?assertNotEqual(T1, T2).

hash_is_deterministic(_Config) ->
    Token = nova_auth_token:generate(),
    H1 = nova_auth_token:hash(Token),
    H2 = nova_auth_token:hash(Token),
    ?assertEqual(H1, H2).

hash_differs_from_raw(_Config) ->
    Token = nova_auth_token:generate(),
    Hashed = nova_auth_token:hash(Token),
    ?assertNotEqual(Token, Hashed).

valid_fresh_token(_Config) ->
    Now = calendar:universal_time(),
    ?assert(nova_auth_token:valid(Now)),
    ?assert(nova_auth_token:valid(Now, 14)).

valid_expired_token(_Config) ->
    %% Create a datetime 15 days in the past
    NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    PastSecs = NowSecs - (15 * 24 * 60 * 60),
    Past = calendar:gregorian_seconds_to_datetime(PastSecs),
    ?assertNot(nova_auth_token:valid(Past, 14)).
