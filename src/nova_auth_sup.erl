-module(nova_auth_sup).
-moduledoc ~"""
Top-level supervisor for nova_auth.
""".
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-doc "Start the nova_auth supervisor.".
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc false.
init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 5, period => 10}, []}}.
