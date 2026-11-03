-module(nova_auth_rate_limit).
-moduledoc ~"""
Rate limiting Nova plugin backed by Seki.

Uses Seki's sliding window algorithm by default. The limiter is created
automatically on first use if it doesn't exist.

## Usage

```erlang
#{prefix => <<"/api/auth">>,
  plugins => [
      {pre_request, nova_auth_rate_limit, #{
          limiter => auth_rate_limit,
          limit => 10,
          window => 60000,
          algorithm => sliding_window
      }}
  ],
  routes => [...]}
```

## Options

Every option is optional; `#{}` gives the defaults.

- `limiter`: limiter name atom (default: `nova_auth_rate_limit`)
- `limit`: max requests per window (default: 10)
- `window`: window in milliseconds (default: 60000)
- `algorithm`: Seki algorithm (default: `sliding_window`)
- `key_fun`: `fun(Req) -> Key` for custom rate limit keys (default: peer IP)

The limiter is created with the `limit`, `window` and `algorithm` of the
first request that uses its name, and route groups that share a name share
its counters. Give each distinct policy its own `limiter` name.

A denied request gets a 429 JSON reply and the plugin returns
`{stop, Req, State}`, so no later plugin or controller runs.
""".
-behaviour(nova_plugin).

-export([init/0, stop/1, pre_request/4, post_request/4, plugin_info/0]).

-define(DEFAULT_LIMITER, nova_auth_rate_limit).
-define(DEFAULT_LIMIT, 10).
-define(DEFAULT_WINDOW, 60000).

-doc false.
-spec init() -> {ok, map()}.
init() ->
    {ok, defaults()}.

-doc false.
-spec stop(map()) -> ok.
stop(_State) ->
    ok.

-doc false.
-spec pre_request(cowboy_req:req(), term(), map(), term()) ->
    {ok, cowboy_req:req(), term()} | {stop, cowboy_req:req(), term()}.
pre_request(Req, _Env, Options, PluginState) ->
    #{
        limiter := LimiterName,
        limit := Limit,
        window := Window,
        algorithm := Algorithm,
        key_fun := KeyFun
    } = maps:merge(defaults(), Options),
    ensure_limiter(LimiterName, Limit, Window, Algorithm),
    Key = KeyFun(Req),
    case seki:check(LimiterName, Key) of
        {allow, #{remaining := Remaining}} ->
            Req1 = cowboy_req:set_resp_header(
                <<"x-ratelimit-remaining">>, integer_to_binary(Remaining), Req
            ),
            {ok, Req1, PluginState};
        {deny, #{retry_after := RetryAfterMs}} ->
            RetryAfter = integer_to_binary(max(1, RetryAfterMs div 1000)),
            Body = iolist_to_binary(json:encode(#{<<"error">> => <<"too many requests">>})),
            Req1 = cowboy_req:set_resp_headers(
                #{
                    <<"content-type">> => <<"application/json">>,
                    <<"retry-after">> => RetryAfter,
                    <<"x-ratelimit-remaining">> => <<"0">>
                },
                Req
            ),
            Req2 = cowboy_req:set_resp_body(Body, Req1),
            Req3 = cowboy_req:reply(429, Req2),
            {stop, Req3, PluginState}
    end.

-doc false.
-spec post_request(cowboy_req:req(), term(), map(), term()) -> {ok, cowboy_req:req(), term()}.
post_request(Req, _Env, _Options, PluginState) ->
    {ok, Req, PluginState}.

-doc false.
-spec plugin_info() -> map().
plugin_info() ->
    #{
        title => <<"nova_auth_rate_limit">>,
        version => <<"0.2.0">>,
        description => <<"Rate limiting plugin for Nova (powered by Seki)">>,
        authors => [<<"Nova Framework">>],
        url => <<"https://github.com/novaframework/nova_auth">>
    }.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

defaults() ->
    #{
        limiter => ?DEFAULT_LIMITER,
        limit => ?DEFAULT_LIMIT,
        window => ?DEFAULT_WINDOW,
        algorithm => sliding_window,
        key_fun => fun default_key/1
    }.

ensure_limiter(Name, Limit, Window, Algorithm) ->
    case persistent_term:get({?MODULE, Name}, false) of
        true ->
            ok;
        false ->
            case
                seki:new_limiter(Name, #{
                    algorithm => Algorithm,
                    limit => Limit,
                    window => Window
                })
            of
                ok ->
                    persistent_term:put({?MODULE, Name}, true);
                {error, already_exists} ->
                    persistent_term:put({?MODULE, Name}, true)
            end
    end.

default_key(Req) ->
    {IP, _Port} = cowboy_req:peer(Req),
    IP.
