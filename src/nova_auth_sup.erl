-module(nova_auth_sup).
-moduledoc ~"""
Top-level supervisor for nova_auth. Supervises the rate limit ETS owner process.
""".
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-doc "Start the nova_auth supervisor.".
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc false.
init([]) ->
    Children = [
        #{
            id => nova_auth_rate_limit_server,
            start => {nova_auth_rate_limit_server, start_link, []},
            type => worker
        }
    ],
    {ok, {#{strategy => one_for_one, intensity => 5, period => 10}, Children}}.
