-module(nova_auth_token_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0]).
-export([
    generate_returns_base64/1,
    generate_custom_bytes/1,
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
            generate_returns_base64,
            generate_custom_bytes,
            generate_unique_tokens,
            hash_is_deterministic,
            hash_differs_from_raw,
            valid_fresh_token,
            valid_expired_token
        ]}
    ].

generate_returns_base64(_Config) ->
    Token = nova_auth_token:generate(),
    ?assert(is_binary(Token)),
    Decoded = base64:decode(Token),
    ?assertEqual(32, byte_size(Decoded)).

generate_custom_bytes(_Config) ->
    Token = nova_auth_token:generate(64),
    Decoded = base64:decode(Token),
    ?assertEqual(64, byte_size(Decoded)).

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
