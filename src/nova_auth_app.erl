-module(nova_auth_app).
-moduledoc ~"""
OTP application callback for nova_auth. Starts the top-level supervisor.
""".
-behaviour(application).

-export([start/2, stop/1]).

-doc "Start the nova_auth application and its supervision tree.".
start(_StartType, _StartArgs) ->
    nova_auth_sup:start_link().

-doc "Stop the nova_auth application.".
stop(_State) ->
    ok.
