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
    seki_limiter_created/1,
    pre_security_counts_the_request/1,
    pre_security_answers_429_over_the_limit/1,
    pre_request_does_not_count_after_pre_security/1,
    pre_request_counts_without_pre_security/1,
    pre_request_answers_429_over_the_limit/1
]).

all() ->
    [{group, rate_limit_tests}].

groups() ->
    [
        {rate_limit_tests, [], [
            init_returns_defaults,
            seki_limiter_created,
            pre_security_counts_the_request,
            pre_security_answers_429_over_the_limit,
            pre_request_does_not_count_after_pre_security,
            pre_request_counts_without_pre_security,
            pre_request_answers_429_over_the_limit
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

pre_security_counts_the_request(_Config) ->
    Options = options(pre_security_counts, 2),
    {ok, First, plugin_state} =
        nova_auth_rate_limit:pre_security(request(), #{}, Options, plugin_state),
    ?assertEqual(~"1", cowboy_req:resp_header(~"x-ratelimit-remaining", First)),
    {ok, Second, plugin_state} =
        nova_auth_rate_limit:pre_security(request(), #{}, Options, plugin_state),
    ?assertEqual(~"0", cowboy_req:resp_header(~"x-ratelimit-remaining", Second)).

pre_security_answers_429_over_the_limit(_Config) ->
    Options = options(pre_security_denies, 1),
    {ok, _Allowed, plugin_state} =
        nova_auth_rate_limit:pre_security(request(), #{}, Options, plugin_state),
    ?assertMatch(
        {stop, #{has_sent_resp := true}, plugin_state},
        nova_auth_rate_limit:pre_security(request(), #{}, Options, plugin_state)
    ),
    ?assertEqual(429, sent_status()).

pre_request_does_not_count_after_pre_security(_Config) ->
    Options = options(counted_once, 2),
    {ok, Checked, plugin_state} =
        nova_auth_rate_limit:pre_security(request(), #{}, Options, plugin_state),
    ?assertEqual(
        {ok, Checked, plugin_state},
        nova_auth_rate_limit:pre_request(Checked, #{}, Options, plugin_state)
    ),
    {ok, Next, plugin_state} =
        nova_auth_rate_limit:pre_security(request(), #{}, Options, plugin_state),
    ?assertEqual(~"0", cowboy_req:resp_header(~"x-ratelimit-remaining", Next)).

pre_request_counts_without_pre_security(_Config) ->
    Options = options(pre_request_counts, 2),
    {ok, First, plugin_state} =
        nova_auth_rate_limit:pre_request(request(), #{}, Options, plugin_state),
    ?assertEqual(~"1", cowboy_req:resp_header(~"x-ratelimit-remaining", First)),
    {ok, Second, plugin_state} =
        nova_auth_rate_limit:pre_request(request(), #{}, Options, plugin_state),
    ?assertEqual(~"0", cowboy_req:resp_header(~"x-ratelimit-remaining", Second)).

pre_request_answers_429_over_the_limit(_Config) ->
    Options = options(pre_request_denies, 1),
    {ok, _Allowed, plugin_state} =
        nova_auth_rate_limit:pre_request(request(), #{}, Options, plugin_state),
    ?assertMatch(
        {stop, #{has_sent_resp := true}, plugin_state},
        nova_auth_rate_limit:pre_request(request(), #{}, Options, plugin_state)
    ),
    ?assertEqual(429, sent_status()).

options(Limiter, Limit) ->
    #{
        limiter => Limiter,
        limit => Limit,
        window => 60000,
        algorithm => sliding_window,
        key_fun => fun cowboy_req:peer/1
    }.

request() ->
    #{
        pid => self(),
        streamid => 1,
        method => ~"POST",
        headers => #{},
        peer => {{127, 0, 0, 1}, 50000}
    }.

sent_status() ->
    receive
        {{Pid, 1}, {response, Status, _Headers, _Body}} when Pid =:= self() -> Status
    after 1000 -> no_response
    end.
