-module(nova_auth_rate_limit_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    end_per_testcase/2
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
    named_limiter_settings_conflict_raises/1,
    unnamed_groups_with_different_settings_are_independent/1,
    unnamed_groups_with_same_settings_share_counters/1,
    derived_limiter_name_is_readable/1,
    retry_after_rounds_up/1,
    client_ip_direct_peer/1,
    client_ip_untrusted_peer_ignores_header/1,
    client_ip_trusted_single_hop/1,
    client_ip_multi_hop_spoofed_leftmost/1,
    client_ip_all_hops_trusted/1,
    client_ip_cidr/1,
    client_ip_ipv6/1,
    client_ip_ipv4_mapped_peer/1,
    client_ip_malformed_header/1,
    client_ip_invalid_trusted_entry/1,
    client_ip_as_key/1,
    concurrent_first_requests_do_not_crash/1,
    preregistered_named_limiter_is_used/1
]).

all() ->
    [{group, rate_limit_tests}, {group, client_ip_tests}].

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
            named_limiter_settings_conflict_raises,
            unnamed_groups_with_different_settings_are_independent,
            unnamed_groups_with_same_settings_share_counters,
            derived_limiter_name_is_readable,
            retry_after_rounds_up,
            concurrent_first_requests_do_not_crash,
            preregistered_named_limiter_is_used
        ]},
        {client_ip_tests, [], [
            client_ip_direct_peer,
            client_ip_untrusted_peer_ignores_header,
            client_ip_trusted_single_hop,
            client_ip_multi_hop_spoofed_leftmost,
            client_ip_all_hops_trusted,
            client_ip_cidr,
            client_ip_ipv6,
            client_ip_ipv4_mapped_peer,
            client_ip_malformed_header,
            client_ip_invalid_trusted_entry,
            client_ip_as_key
        ]}
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(seki),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(seki).

end_per_testcase(_Case, _Config) ->
    ok = application:unset_env(nova_auth, trusted_proxies),
    [
        begin
            case Key of
                {nova_auth_rate_limit, Name} when is_atom(Name) -> ok = seki:delete_limiter(Name);
                _ -> ok
            end,
            persistent_term:erase(Key)
        end
     || {Key, _} <- persistent_term:get(),
        is_tuple(Key),
        element(1, Key) =:= nova_auth_rate_limit
    ],
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

named_limiter_settings_conflict_raises(_Config) ->
    First = #{limiter => rl_shared, limit => 5},
    Other = #{limiter => rl_shared, limit => 50},
    {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 0, 8}), #{}, First, s),
    ?assertError(
        {limiter_settings_conflict, rl_shared, #{limit := 5}, #{limit := 50}},
        nova_auth_rate_limit:pre_request(req({10, 0, 0, 8}), #{}, Other, s)
    ),
    ?assertMatch({ok, _, _}, nova_auth_rate_limit:pre_request(req({10, 0, 0, 8}), #{}, First, s)).

unnamed_groups_with_different_settings_are_independent(_Config) ->
    Lax = #{limit => 1000},
    Strict = #{limit => 3, window => 900000},
    {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 1, 1}), #{}, Lax, s),
    Outcomes = [
        element(1, nova_auth_rate_limit:pre_request(req({10, 0, 1, 2}), #{}, Strict, s))
     || _ <- lists:seq(1, 5)
    ],
    ?assertEqual([ok, ok, ok, stop, stop], Outcomes),
    {ok, Req1, _} = nova_auth_rate_limit:pre_request(req({10, 0, 1, 2}), #{}, Lax, s),
    ?assertEqual(~"999", cowboy_req:resp_header(~"x-ratelimit-remaining", Req1)).

unnamed_groups_with_same_settings_share_counters(_Config) ->
    Options = #{limit => 7, window => 120000},
    {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 2, 1}), #{}, Options, s),
    {ok, Req1, _} = nova_auth_rate_limit:pre_request(
        req({10, 0, 2, 1}), #{}, maps:merge(#{algorithm => sliding_window}, Options), s
    ),
    ?assertEqual(~"5", cowboy_req:resp_header(~"x-ratelimit-remaining", Req1)).

derived_limiter_name_is_readable(_Config) ->
    Options = #{limit => 4, window => 30000},
    {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 3, 1}), #{}, Options, s),
    ?assertEqual(
        #{algorithm => sliding_window, limit => 4, window => 30000},
        persistent_term:get({nova_auth_rate_limit, nova_auth_rate_limit_sliding_window_4_30000})
    ),
    ?assertMatch(
        {allow, #{remaining := 2}},
        seki:check(nova_auth_rate_limit_sliding_window_4_30000, {10, 0, 3, 1})
    ).

retry_after_rounds_up(_Config) ->
    Options = #{limit => 1, window => 1500},
    {ok, _, _} = nova_auth_rate_limit:pre_request(req({10, 0, 4, 1}), #{}, Options, s),
    {stop, {reply, 429, Headers, _}, _, s} =
        nova_auth_rate_limit:pre_request(req({10, 0, 4, 1}), #{}, Options, s),
    ?assertMatch(#{~"retry-after" := ~"2"}, Headers).

client_ip_direct_peer(_Config) ->
    ok = application:unset_env(nova_auth, trusted_proxies),
    Req = req({203, 0, 113, 7}, #{~"x-forwarded-for" => ~"198.51.100.1"}),
    ?assertEqual({203, 0, 113, 7}, nova_auth_rate_limit:client_ip(Req)).

client_ip_untrusted_peer_ignores_header(_Config) ->
    trust([{10, 0, 0, 1}]),
    Req = req({203, 0, 113, 7}, #{~"x-forwarded-for" => ~"198.51.100.1"}),
    ?assertEqual({203, 0, 113, 7}, nova_auth_rate_limit:client_ip(Req)).

client_ip_trusted_single_hop(_Config) ->
    trust([{10, 0, 0, 1}]),
    Req = req({10, 0, 0, 1}, #{~"x-forwarded-for" => ~"198.51.100.1"}),
    ?assertEqual({198, 51, 100, 1}, nova_auth_rate_limit:client_ip(Req)).

client_ip_multi_hop_spoofed_leftmost(_Config) ->
    trust([{10, 0, 0, 1}, {10, 0, 0, 2}]),
    Req = req({10, 0, 0, 1}, #{
        ~"x-forwarded-for" => ~"1.2.3.4, 198.51.100.9, 10.0.0.2"
    }),
    ?assertEqual({198, 51, 100, 9}, nova_auth_rate_limit:client_ip(Req)).

client_ip_all_hops_trusted(_Config) ->
    trust([{10, 0, 0, 1}, {10, 0, 0, 2}]),
    Req = req({10, 0, 0, 1}, #{~"x-forwarded-for" => ~"10.0.0.2"}),
    ?assertEqual({10, 0, 0, 2}, nova_auth_rate_limit:client_ip(Req)),
    ?assertEqual({10, 0, 0, 1}, nova_auth_rate_limit:client_ip(req({10, 0, 0, 1}))).

client_ip_cidr(_Config) ->
    trust([{{10, 0, 0, 0}, 8}, {{172, 16, 0, 0}, 12}]),
    Req = req({10, 20, 30, 40}, #{
        ~"x-forwarded-for" => ~"6.6.6.6, 198.51.100.3, 172.31.255.255, 10.1.1.1"
    }),
    ?assertEqual({198, 51, 100, 3}, nova_auth_rate_limit:client_ip(Req)),
    Outside = req({10, 0, 0, 1}, #{~"x-forwarded-for" => ~"172.32.0.1"}),
    ?assertEqual({172, 32, 0, 1}, nova_auth_rate_limit:client_ip(Outside)).

client_ip_ipv6(_Config) ->
    trust([{{16#fd00, 0, 0, 0, 0, 0, 0, 0}, 8}, {0, 0, 0, 0, 0, 0, 0, 1}]),
    Req = req({0, 0, 0, 0, 0, 0, 0, 1}, #{
        ~"x-forwarded-for" => ~"2001:db8::dead, 2001:db8::1, fd12::5"
    }),
    ?assertEqual({16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, nova_auth_rate_limit:client_ip(Req)).

client_ip_ipv4_mapped_peer(_Config) ->
    trust([{{10, 0, 0, 0}, 8}]),
    Req = req({0, 0, 0, 0, 0, 16#FFFF, 16#0A00, 16#0001}, #{
        ~"x-forwarded-for" => ~"198.51.100.4"
    }),
    ?assertEqual({198, 51, 100, 4}, nova_auth_rate_limit:client_ip(Req)).

client_ip_malformed_header(_Config) ->
    trust([{10, 0, 0, 1}, {10, 0, 0, 2}]),
    Garbage = req({10, 0, 0, 1}, #{~"x-forwarded-for" => ~"198.51.100.5, not-an-ip, 10.0.0.2"}),
    ?assertEqual({10, 0, 0, 2}, nova_auth_rate_limit:client_ip(Garbage)),
    WithPort = req({10, 0, 0, 1}, #{~"x-forwarded-for" => ~"198.51.100.5:4711"}),
    ?assertEqual({10, 0, 0, 1}, nova_auth_rate_limit:client_ip(WithPort)),
    Empty = req({10, 0, 0, 1}, #{~"x-forwarded-for" => ~""}),
    ?assertEqual({10, 0, 0, 1}, nova_auth_rate_limit:client_ip(Empty)).

client_ip_invalid_trusted_entry(_Config) ->
    trust(["10.0.0.1"]),
    ?assertError(
        {invalid_option, trusted_proxies, "10.0.0.1"},
        nova_auth_rate_limit:client_ip(req({10, 0, 0, 1}))
    ),
    trust([{{10, 0, 0, 0}, 33}]),
    ?assertError(
        {invalid_option, trusted_proxies, {{10, 0, 0, 0}, 33}},
        nova_auth_rate_limit:client_ip(req({10, 0, 0, 1}))
    ).

client_ip_as_key(_Config) ->
    trust([{10, 0, 0, 1}]),
    Options = #{limiter => rl_client_ip, limit => 1, key => {nova_auth_rate_limit, client_ip}},
    Proxied = fun(Client) -> req({10, 0, 0, 1}, #{~"x-forwarded-for" => Client}) end,
    {ok, _, _} = nova_auth_rate_limit:pre_request(Proxied(~"198.51.100.6"), #{}, Options, s),
    ?assertMatch(
        {ok, _, _},
        nova_auth_rate_limit:pre_request(Proxied(~"198.51.100.7"), #{}, Options, s)
    ),
    ?assertMatch(
        {stop, {reply, 429, _, _}, _, s},
        nova_auth_rate_limit:pre_request(Proxied(~"198.51.100.6"), #{}, Options, s)
    ).

concurrent_first_requests_do_not_crash(_Config) ->
    Options = #{limit => 150, window => 61234},
    Self = self(),
    Go = make_ref(),
    Pids = [
        spawn_link(fun() ->
            receive
                Go -> ok
            end,
            Result =
                try nova_auth_rate_limit:pre_request(req({10, 9, 0, 1}), #{}, Options, s) of
                    {ok, #{resp_headers := #{~"x-ratelimit-remaining" := Remaining}}, s} when
                        is_binary(Remaining)
                    ->
                        {allow, binary_to_integer(Remaining)};
                    {stop, {reply, 429, _, _}, _, s} ->
                        deny
                catch
                    Class:Reason -> {Class, Reason}
                end,
            Self ! {self(), Result}
        end)
     || _ <- lists:seq(1, 200)
    ],
    _ = [Pid ! Go || Pid <- Pids],
    Results = [
        receive
            {Pid, Result} -> Result
        after 10000 -> error(timeout)
        end
     || Pid <- Pids
    ],
    ?assertEqual(
        [],
        [R || R <- Results, R =/= deny, not (is_tuple(R) andalso element(1, R) =:= allow)]
    ),
    ?assertEqual([], [N || {allow, N} <- Results, N < 0 orelse N >= 150]),
    ?assertNotEqual([], [N || {allow, N} <- Results]).

preregistered_named_limiter_is_used(_Config) ->
    ok = seki:new_limiter(nova_auth_test_prereg, #{
        algorithm => sliding_window, limit => 2, window => 60000
    }),
    Options = #{limiter => nova_auth_test_prereg, limit => 2, window => 60000},
    Check = fun() -> nova_auth_rate_limit:pre_request(req({10, 9, 0, 2}), #{}, Options, s) end,
    ?assertMatch({ok, _, s}, Check()),
    ?assertMatch({ok, _, s}, Check()),
    ?assertMatch({stop, {reply, 429, _, _}, _, s}, Check()).

trust(Proxies) ->
    ok = application:set_env(nova_auth, trusted_proxies, Proxies).

req(IP, Headers) ->
    (req(IP))#{headers => Headers}.

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
