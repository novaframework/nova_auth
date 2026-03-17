-module(nova_auth_password_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0]).
-export([
    hash_returns_binary/1,
    verify_correct_password/1,
    verify_wrong_password/1,
    dummy_verify_returns_false/1,
    hash_produces_unique_salts/1,
    hash_format_is_pbkdf2/1
]).

all() ->
    [{group, password_tests}].

groups() ->
    [
        {password_tests, [parallel], [
            hash_returns_binary,
            verify_correct_password,
            verify_wrong_password,
            dummy_verify_returns_false,
            hash_produces_unique_salts,
            hash_format_is_pbkdf2
        ]}
    ].

hash_returns_binary(_Config) ->
    Hashed = nova_auth_password:hash(<<"password123456">>),
    ?assert(is_binary(Hashed)),
    ?assert(byte_size(Hashed) > 0).

verify_correct_password(_Config) ->
    Password = <<"my_secure_password">>,
    Hashed = nova_auth_password:hash(Password),
    ?assert(nova_auth_password:verify(Password, Hashed)).

verify_wrong_password(_Config) ->
    Password = <<"my_secure_password">>,
    Hashed = nova_auth_password:hash(Password),
    ?assertNot(nova_auth_password:verify(<<"wrong_password">>, Hashed)).

dummy_verify_returns_false(_Config) ->
    ?assertNot(nova_auth_password:dummy_verify()),
    ?assertNot(nova_auth_password:dummy_verify(pbkdf2_sha256)).

hash_produces_unique_salts(_Config) ->
    Password = <<"same_password">>,
    Hash1 = nova_auth_password:hash(Password),
    Hash2 = nova_auth_password:hash(Password),
    ?assertNotEqual(Hash1, Hash2).

hash_format_is_pbkdf2(_Config) ->
    Hashed = nova_auth_password:hash(<<"test">>),
    ?assertMatch(<<"$pbkdf2-sha256$", _/binary>>, Hashed).
