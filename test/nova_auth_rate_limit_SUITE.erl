-module(nova_auth_rate_limit_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).
-export([
    init_returns_defaults/1,
    check_rate_allows_under_limit/1,
    check_rate_blocks_over_limit/1,
    cleanup_removes_expired/1
]).

all() ->
    [{group, rate_limit_tests}].

groups() ->
    [
        {rate_limit_tests, [], [
            init_returns_defaults,
            check_rate_allows_under_limit,
            check_rate_blocks_over_limit,
            cleanup_removes_expired
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    {ok, Pid} = nova_auth_rate_limit_server:start_link(),
    [{rate_limit_pid, Pid} | Config].

end_per_testcase(_TestCase, Config) ->
    Pid = proplists:get_value(rate_limit_pid, Config),
    unlink(Pid),
    exit(Pid, kill),
    ok.

init_returns_defaults(_Config) ->
    {ok, State} = nova_auth_rate_limit:init(),
    ?assertEqual(10, maps:get(max_requests, State)),
    ?assertEqual(60, maps:get(window_seconds, State)).

check_rate_allows_under_limit(_Config) ->
    Table = nova_auth_rate_limit,
    Key = {127, 0, 0, 1},
    Now = erlang:system_time(second),
    %% Insert fewer than default limit (10)
    lists:foreach(
        fun(I) ->
            ets:insert(Table, {Key, {ref, I}, Now + 60})
        end,
        lists:seq(1, 5)
    ),
    Count = length(ets:select(Table, [{{Key, '$1', '$2'}, [{'>=', '$2', Now - 60}], ['$1']}])),
    ?assert(Count < 10).

check_rate_blocks_over_limit(_Config) ->
    Table = nova_auth_rate_limit,
    Key = {127, 0, 0, 2},
    Now = erlang:system_time(second),
    lists:foreach(
        fun(I) ->
            ets:insert(Table, {Key, {ref, I}, Now + 60})
        end,
        lists:seq(1, 10)
    ),
    Count = length(ets:select(Table, [{{Key, '$1', '$2'}, [{'>=', '$2', Now - 60}], ['$1']}])),
    ?assert(Count >= 10).

cleanup_removes_expired(_Config) ->
    Table = nova_auth_rate_limit,
    Key = {127, 0, 0, 3},
    Now = erlang:system_time(second),
    %% Insert expired entry
    ets:insert(Table, {Key, {ref, expired}, Now - 10}),
    %% Trigger cleanup
    nova_auth_rate_limit_server ! cleanup,
    timer:sleep(50),
    Entries = ets:lookup(Table, Key),
    ?assertEqual([], Entries).
