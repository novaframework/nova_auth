-module(test_auth_repo).
-behaviour(kura_repo).

-export([otp_app/0, start/0]).

otp_app() -> nova_auth.

start() ->
    %% kura 2.x resolves backend -> pool/driver only for the `kura` app's
    %% `repos` map; for this per-app config we wire them explicitly. Keys
    %% match kura_pool_pgo (host/user, not hostname/username).
    Backend = kura_backend_postgres,
    application:set_env(nova_auth, test_auth_repo, #{
        backend => Backend,
        pool_module => Backend:pool_module(),
        driver_module => Backend:driver_module(),
        dialect => Backend:dialect(),
        host => "localhost",
        port => 5555,
        database => "nova_auth_test",
        user => "postgres",
        password => "root",
        pool_size => 5
    }),
    kura_repo_worker:start(?MODULE).
