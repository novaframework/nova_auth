-module(test_auth_config_confirmed).
-behaviour(nova_auth).

-export([config/0]).

config() ->
    #{
        repo => test_auth_repo,
        user_schema => test_auth_user,
        token_schema => test_auth_token,
        require_confirmed => true
    }.
