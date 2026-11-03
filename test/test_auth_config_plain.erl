-module(test_auth_config_plain).
-behaviour(nova_auth).

-export([config/0]).

config() ->
    #{
        repo => test_auth_repo,
        user_schema => test_auth_user_plain,
        token_schema => test_auth_token
    }.
