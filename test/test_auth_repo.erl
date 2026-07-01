-module(test_auth_repo).
-behaviour(kura_repo).

-export([otp_app/0, start/0]).

otp_app() -> nova_auth.

start() ->
    application:set_env(nova_auth, test_auth_repo, #{
        %% kura 2.x: select the backend driver (Postgres) explicitly.
        backend => kura_backend_postgres,
        pool => test_auth_repo,
        database => <<"nova_auth_test">>,
        hostname => <<"localhost">>,
        port => 5555,
        username => <<"postgres">>,
        password => <<"root">>,
        pool_size => 5
    }),
    kura_repo_worker:start(?MODULE).
