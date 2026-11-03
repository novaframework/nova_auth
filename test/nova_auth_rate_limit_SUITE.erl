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
    empty_options_use_defaults/1,
    partial_options_merge_defaults/1,
    deny_returns_three_tuple_stop/1
]).

all() ->
    [{group, rate_limit_tests}].

groups() ->
    [
        {rate_limit_tests, [], [
            init_returns_defaults,
            seki_limiter_created,
            empty_options_use_defaults,
            partial_options_merge_defaults,
            deny_returns_three_tuple_stop
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

empty_options_use_defaults(_Config) ->
    Req = req({10, 0, 0, 1}),
    {ok, Req1, plugin_state} = nova_auth_rate_limit:pre_request(Req, #{}, #{}, plugin_state),
    ?assertEqual(~"9", cowboy_req:resp_header(~"x-ratelimit-remaining", Req1)).

partial_options_merge_defaults(_Config) ->
    Options = #{limiter => rl_partial_options, limit => 2},
    Req = req({10, 0, 0, 2}),
    {ok, Req1, _} = nova_auth_rate_limit:pre_request(Req, #{}, Options, plugin_state),
    ?assertEqual(~"1", cowboy_req:resp_header(~"x-ratelimit-remaining", Req1)).

deny_returns_three_tuple_stop(_Config) ->
    Options = #{limiter => rl_deny, limit => 1, key_fun => fun(_) -> same_key end},
    Req = req({10, 0, 0, 3}),
    {ok, _, plugin_state} = nova_auth_rate_limit:pre_request(Req, #{}, Options, plugin_state),
    Result = nova_auth_rate_limit:pre_request(Req, #{}, Options, plugin_state),
    ?assertMatch({stop, #{}, plugin_state}, Result),
    receive
        {{_, 1}, {response, 429, Headers, Body}} ->
            ?assertMatch(#{~"retry-after" := _, ~"x-ratelimit-remaining" := ~"0"}, Headers),
            ?assertEqual(#{~"error" => ~"too many requests"}, json:decode(iolist_to_binary(Body)))
    after 1000 ->
        ct:fail(no_reply_sent)
    end.

req(IP) ->
    #{
        pid => self(),
        streamid => 1,
        peer => {IP, 40000},
        method => ~"POST",
        version => 'HTTP/1.1',
        headers => #{},
        has_body => false
    }.
