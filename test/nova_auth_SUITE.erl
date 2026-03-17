-module(nova_auth_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([
    config_returns_defaults/1,
    config_caches_in_persistent_term/1,
    config_key_lookup/1,
    invalidate_cache_clears/1
]).

all() ->
    [{group, config_tests}].

groups() ->
    [
        {config_tests, [], [
            config_returns_defaults,
            config_caches_in_persistent_term,
            config_key_lookup,
            invalidate_cache_clears
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    catch persistent_term:erase({nova_auth, test_auth_config}),
    ok.

config_returns_defaults(_Config) ->
    catch persistent_term:erase({nova_auth, test_auth_config}),
    Cfg = nova_auth:config(test_auth_config),
    ?assertEqual(email, maps:get(user_identity_field, Cfg)),
    ?assertEqual(hashed_password, maps:get(user_password_field, Cfg)),
    ?assertEqual(14, maps:get(session_validity_days, Cfg)),
    ?assertEqual(pbkdf2_sha256, maps:get(hash_algorithm, Cfg)),
    ?assertEqual(32, maps:get(token_bytes, Cfg)),
    ?assertEqual(test_repo, maps:get(repo, Cfg)),
    ?assertEqual(test_user, maps:get(user_schema, Cfg)),
    ?assertEqual(test_token, maps:get(token_schema, Cfg)).

config_caches_in_persistent_term(_Config) ->
    catch persistent_term:erase({nova_auth, test_auth_config}),
    Cfg1 = nova_auth:config(test_auth_config),
    Cfg2 = nova_auth:config(test_auth_config),
    ?assertEqual(Cfg1, Cfg2),
    ?assertNotEqual(undefined, persistent_term:get({nova_auth, test_auth_config}, undefined)).

config_key_lookup(_Config) ->
    catch persistent_term:erase({nova_auth, test_auth_config}),
    ?assertEqual(test_repo, nova_auth:config(test_auth_config, repo)).

invalidate_cache_clears(_Config) ->
    catch persistent_term:erase({nova_auth, test_auth_config}),
    _Cfg = nova_auth:config(test_auth_config),
    nova_auth:invalidate_cache(test_auth_config),
    ?assertEqual(undefined, persistent_term:get({nova_auth, test_auth_config}, undefined)).
