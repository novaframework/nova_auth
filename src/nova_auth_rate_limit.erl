-module(nova_auth_rate_limit).
-moduledoc ~"""
Nova plugin for IP-based rate limiting. Tracks requests in an ETS bag table
and returns 429 when the limit is exceeded within the configured time window.
""".
-behaviour(nova_plugin).

-export([init/0, stop/1, pre_request/4, post_request/4, plugin_info/0]).

-define(TABLE, nova_auth_rate_limit).
-define(DEFAULT_MAX_REQUESTS, 10).
-define(DEFAULT_WINDOW_SECONDS, 60).

-doc "Initialize the plugin with default rate limit settings.".
init() ->
    {ok, #{
        max_requests => ?DEFAULT_MAX_REQUESTS,
        window_seconds => ?DEFAULT_WINDOW_SECONDS,
        key_fun => fun default_key/1
    }}.

-doc false.
stop(_State) ->
    ok.

-doc "Check the request against the rate limit before processing.".
pre_request(Req, _State, PluginState, _) ->
    #{
        max_requests := MaxRequests,
        window_seconds := WindowSeconds,
        key_fun := KeyFun
    } = PluginState,
    Key = KeyFun(Req),
    Now = erlang:system_time(second),
    WindowStart = Now - WindowSeconds,
    case check_rate(Key, Now, WindowStart, MaxRequests) of
        ok ->
            {ok, Req, PluginState};
        rate_limited ->
            Body = iolist_to_binary(json:encode(#{<<"error">> => <<"too many requests">>})),
            Req1 = cowboy_req:set_resp_headers(
                #{
                    <<"content-type">> => <<"application/json">>,
                    <<"retry-after">> => integer_to_binary(WindowSeconds)
                },
                Req
            ),
            Req2 = cowboy_req:set_resp_body(Body, Req1),
            Req3 = cowboy_req:reply(429, Req2),
            {stop, Req3}
    end.

-doc false.
post_request(Req, _State, PluginState, _) ->
    {ok, Req, PluginState}.

-doc "Return plugin metadata.".
plugin_info() ->
    #{
        name => <<"nova_auth_rate_limit">>,
        version => <<"0.1.0">>,
        description => <<"Rate limiting plugin for Nova">>
    }.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

check_rate(Key, Now, WindowStart, MaxRequests) ->
    Entries =
        try
            ets:select(?TABLE, [
                {{Key, '$1', '$2'}, [{'>=', '$2', WindowStart}], ['$1']}
            ])
        catch
            error:badarg -> []
        end,
    case length(Entries) >= MaxRequests of
        true ->
            rate_limited;
        false ->
            Ref = make_ref(),
            Expiry = Now + 60,
            try
                ets:insert(?TABLE, {Key, Ref, Expiry}),
                ok
            catch
                error:badarg -> ok
            end
    end.

default_key(Req) ->
    {IP, _Port} = cowboy_req:peer(Req),
    IP.
