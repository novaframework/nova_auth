-module(nova_auth_claims_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0]).
-export([
    static_map_renames_keys/1,
    static_map_skips_missing_claims/1,
    static_map_empty/1,
    callback_mapping/1,
    map3_merges_with_base/1,
    map3_overwrites_base/1
]).

%% Callback used by callback_mapping test

all() ->
    [{group, claims_tests}].

groups() ->
    [
        {claims_tests, [parallel], [
            static_map_renames_keys,
            static_map_skips_missing_claims,
            static_map_empty,
            callback_mapping,
            map3_merges_with_base,
            map3_overwrites_base
        ]}
    ].

static_map_renames_keys(_Config) ->
    Mapping = #{~"sub" => id, ~"email" => email, ~"groups" => roles},
    Claims = #{~"sub" => ~"abc123", ~"email" => ~"user@example.com", ~"groups" => [~"admins"]},
    Result = nova_auth_claims:map(Mapping, Claims),
    ?assertEqual(~"abc123", maps:get(id, Result)),
    ?assertEqual(~"user@example.com", maps:get(email, Result)),
    ?assertEqual([~"admins"], maps:get(roles, Result)).

static_map_skips_missing_claims(_Config) ->
    Mapping = #{~"sub" => id, ~"email" => email, ~"name" => display_name},
    Claims = #{~"sub" => ~"abc123"},
    Result = nova_auth_claims:map(Mapping, Claims),
    ?assertEqual(~"abc123", maps:get(id, Result)),
    ?assertNot(maps:is_key(email, Result)),
    ?assertNot(maps:is_key(display_name, Result)).

static_map_empty(_Config) ->
    ?assertEqual(#{}, nova_auth_claims:map(#{}, #{~"sub" => ~"abc"})).

callback_mapping(_Config) ->
    Result = nova_auth_claims:map({test_claims_mapping, to_actor}, #{
        ~"sub" => ~"42", ~"role" => ~"admin"
    }),
    ?assertEqual(#{id => ~"42", role => admin}, Result).

map3_merges_with_base(_Config) ->
    Mapping = #{~"email" => email},
    Claims = #{~"email" => ~"user@example.com"},
    Base = #{id => ~"123", provider => authentik},
    Result = nova_auth_claims:map(Mapping, Claims, Base),
    ?assertEqual(~"123", maps:get(id, Result)),
    ?assertEqual(authentik, maps:get(provider, Result)),
    ?assertEqual(~"user@example.com", maps:get(email, Result)).

map3_overwrites_base(_Config) ->
    Mapping = #{~"email" => email},
    Claims = #{~"email" => ~"new@example.com"},
    Base = #{email => ~"old@example.com"},
    Result = nova_auth_claims:map(Mapping, Claims, Base),
    ?assertEqual(~"new@example.com", maps:get(email, Result)).
