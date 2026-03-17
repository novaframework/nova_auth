-module(nova_auth_rate_limit_server).
-moduledoc ~"""
ETS table owner for the rate limiter. Owns the `nova_auth_rate_limit` bag
table and periodically cleans up expired entries.
""".
-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(TABLE, nova_auth_rate_limit).
-define(CLEANUP_INTERVAL, 60000).

-doc "Start the rate limit server and create the ETS table.".
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc false.
init([]) ->
    ets:new(?TABLE, [named_table, public, bag, {write_concurrency, true}, {read_concurrency, true}]),
    erlang:send_after(?CLEANUP_INTERVAL, self(), cleanup),
    {ok, #{}}.

-doc false.
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-doc false.
handle_cast(_Msg, State) ->
    {noreply, State}.

-doc false.
handle_info(cleanup, State) ->
    Now = erlang:system_time(second),
    ets:select_delete(?TABLE, [
        {{'_', '_', '$1'}, [{'<', '$1', Now}], [true]}
    ]),
    erlang:send_after(?CLEANUP_INTERVAL, self(), cleanup),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.
