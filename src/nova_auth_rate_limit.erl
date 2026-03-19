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

- `limiter` — Limiter name atom (default: `nova_auth_rate_limit`)
- `limit` — Max requests per window (default: 10)
- `window` — Window in milliseconds (default: 60000)
- `algorithm` — Seki algorithm (default: `sliding_window`)
- `key_fun` — `fun(Req) -> Key` for custom rate limit keys (default: peer IP)
""".
-behaviour(nova_plugin).

-export([init/0, stop/1, pre_request/4, post_request/4, plugin_info/0]).

-define(DEFAULT_LIMITER, nova_auth_rate_limit).
-define(DEFAULT_LIMIT, 10).
-define(DEFAULT_WINDOW, 60000).

-doc false.
-spec init() -> {ok, map()}.
init() ->
    {ok, #{
        limiter => ?DEFAULT_LIMITER,
        limit => ?DEFAULT_LIMIT,
        window => ?DEFAULT_WINDOW,
        algorithm => sliding_window,
        key_fun => fun default_key/1
    }}.

-doc false.
-spec stop(map()) -> ok.
stop(_State) ->
    ok.

-doc false.
-spec pre_request(cowboy_req:req(), term(), map(), term()) ->
    {ok, cowboy_req:req(), map()} | {stop, cowboy_req:req()}.
pre_request(Req, _State, PluginState, _) ->
    #{
        limiter := LimiterName,
        limit := Limit,
        window := Window,
        algorithm := Algorithm,
        key_fun := KeyFun
    } = PluginState,
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
            {stop, Req3}
    end.

-doc false.
-spec post_request(cowboy_req:req(), term(), map(), term()) -> {ok, cowboy_req:req(), map()}.
post_request(Req, _State, PluginState, _) ->
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
