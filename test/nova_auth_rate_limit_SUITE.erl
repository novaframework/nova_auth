-module(nova_auth_rate_limit_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1
]).
-export([
    init_returns_defaults/1,
    seki_limiter_created/1
]).

all() ->
    [{group, rate_limit_tests}].

groups() ->
    [
        {rate_limit_tests, [], [
            init_returns_defaults,
            seki_limiter_created
        ]}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(seki),
    Config.

end_per_suite(_Config) ->
    ok.

init_returns_defaults(_Config) ->
    {ok, State} = nova_auth_rate_limit:init(),
    ?assertEqual(10, maps:get(limit, State)),
    ?assertEqual(60000, maps:get(window, State)),
    ?assertEqual(sliding_window, maps:get(algorithm, State)).

seki_limiter_created(_Config) ->
    %% Verify seki:check works after the limiter is created
    LimiterName = test_auth_limiter,
    ok = seki:new_limiter(LimiterName, #{
        algorithm => sliding_window,
        limit => 3,
        window => 60000
    }),
    {allow, #{remaining := 2}} = seki:check(LimiterName, {127, 0, 0, 1}),
    {allow, #{remaining := 1}} = seki:check(LimiterName, {127, 0, 0, 1}),
    {allow, #{remaining := 0}} = seki:check(LimiterName, {127, 0, 0, 1}),
    {deny, #{retry_after := _}} = seki:check(LimiterName, {127, 0, 0, 1}),
    seki:delete_limiter(LimiterName).
