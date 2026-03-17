-module(test_auth_config).
-behaviour(nova_auth).

-export([config/0]).

config() ->
    #{
        repo => test_repo,
        user_schema => test_user,
        token_schema => test_token
    }.
