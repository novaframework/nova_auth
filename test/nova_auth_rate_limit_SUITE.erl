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
    deny_returns_reply_stop/1,
    key_module_function/1,
    key_fun_is_rejected/1,
    invalid_key_is_rejected/1,
    mismatched_settings_warn_once/1
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
            deny_returns_reply_stop,
            key_module_function,
            key_fun_is_rejected,
            invalid_key_is_rejected,
            mismatched_settings_warn_once
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

deny_returns_reply_stop(_Config) ->
    Options = #{limiter => rl_deny, limit => 1},
    Req = req({10, 0, 0, 3}),
    {ok, _, plugin_state} = nova_auth_rate_limit:pre_request(Req, #{}, Options, plugin_state),
    {stop, {reply, 429, Headers, Body}, Req, plugin_state} =
        nova_auth_rate_limit:pre_request(Req, #{}, Options, plugin_state),
    ?assertMatch(
        #{
            ~"content-type" := ~"application/json",
            ~"retry-after" := _,
            ~"x-ratelimit-remaining" := ~"0"
        },
        Headers
    ),
    ?assertEqual(#{~"error" => ~"too many requests"}, json:decode(Body)).

key_module_function(_Config) ->
    Options = #{limiter => rl_key_mf, limit => 1, key => {test_rate_limit_key, same_key}},
    {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 0, 4}), #{}, Options, s),
    ?assertMatch(
        {stop, {reply, 429, _, _}, _, s},
        nova_auth_rate_limit:pre_request(req({10, 0, 0, 5}), #{}, Options, s)
    ).

key_fun_is_rejected(_Config) ->
    Options = #{limiter => rl_key_fun, key_fun => fun test_rate_limit_key:same_key/1},
    ?assertError(
        {removed_option, key_fun},
        nova_auth_rate_limit:pre_request(req({10, 0, 0, 6}), #{}, Options, s)
    ).

invalid_key_is_rejected(_Config) ->
    Options = #{limiter => rl_bad_key, key => not_a_key_spec},
    ?assertError(
        {invalid_option, key, not_a_key_spec},
        nova_auth_rate_limit:pre_request(req({10, 0, 0, 7}), #{}, Options, s)
    ).

mismatched_settings_warn_once(_Config) ->
    First = #{limiter => rl_shared, limit => 5},
    Other = #{limiter => rl_shared, limit => 50},
    {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 0, 8}), #{}, First, s),
    ok = test_log_capture:start(),
    try
        {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 0, 8}), #{}, Other, s),
        {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 0, 8}), #{}, Other, s),
        {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 0, 8}), #{}, First, s),
        Warnings = [
            Report
         || #{level := warning, msg := {report, #{limiter := rl_shared} = Report}} <-
                test_log_capture:events()
        ],
        ?assertMatch(
            [#{settings := #{limit := 5}, ignored := #{limit := 50}}], Warnings
        )
    after
        test_log_capture:stop()
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
