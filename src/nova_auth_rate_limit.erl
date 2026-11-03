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
- `key`: `{Module, Function}`; `Module:Function(Req)` returns the rate
  limit key (default: the peer IP address)

The limiter is created with the `limit`, `window` and `algorithm` of the
first request that uses its name, and route groups that share a name share
its counters and keep those first settings. A request whose settings differ
from the existing limiter's logs a warning (once per distinct setting).
Give each distinct policy its own `limiter` name.

A denied request returns `{stop, {reply, 429, Headers, Body}, Req, State}`:
Nova sends the 429 JSON reply and no later plugin or controller runs.

The `key_fun` option of earlier releases is rejected with
`error({removed_option, key_fun})`; use `key`.
""".
-behaviour(nova_plugin).

-include_lib("kernel/include/logger.hrl").

-export([init/0, stop/1, pre_request/4, post_request/4, plugin_info/0]).

-type reply() :: {reply, 429, #{binary() => binary()}, binary()}.

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
    {ok, cowboy_req:req(), term()} | {stop, reply(), cowboy_req:req(), term()}.
pre_request(_Req, _Env, #{key_fun := _}, _PluginState) ->
    error({removed_option, key_fun});
pre_request(Req, _Env, Options, PluginState) ->
    #{
        limiter := LimiterName,
        limit := Limit,
        window := Window,
        algorithm := Algorithm,
        key := KeySpec
    } = maps:merge(defaults(), Options),
    ensure_limiter(LimiterName, #{algorithm => Algorithm, limit => Limit, window => Window}),
    case seki:check(LimiterName, rate_limit_key(KeySpec, Req)) of
        {allow, #{remaining := Remaining}} ->
            Req1 = cowboy_req:set_resp_header(
                <<"x-ratelimit-remaining">>, integer_to_binary(Remaining), Req
            ),
            {ok, Req1, PluginState};
        {deny, #{retry_after := RetryAfterMs}} ->
            Headers = #{
                <<"content-type">> => <<"application/json">>,
                <<"retry-after">> => integer_to_binary(retry_after_seconds(RetryAfterMs)),
                <<"x-ratelimit-remaining">> => <<"0">>
            },
            Body = iolist_to_binary(json:encode(#{<<"error">> => <<"too many requests">>})),
            {stop, {reply, 429, Headers, Body}, Req, PluginState}
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
        key => peer
    }.

ensure_limiter(Name, Settings) ->
    case persistent_term:get({?MODULE, Name}, undefined) of
        Settings ->
            ok;
        undefined ->
            case seki:new_limiter(Name, Settings) of
                ok -> ok;
                {error, already_exists} -> ok
            end,
            persistent_term:put({?MODULE, Name}, Settings);
        Existing ->
            warn_settings_mismatch(Name, Existing, Settings)
    end.

warn_settings_mismatch(Name, Existing, Requested) ->
    WarnedKey = {?MODULE, warned, Name, Requested},
    case persistent_term:get(WarnedKey, false) of
        true ->
            ok;
        false ->
            ?LOG_WARNING(#{
                msg => ~"nova_auth_rate_limit limiter keeps its first settings",
                limiter => Name,
                settings => Existing,
                ignored => Requested
            }),
            persistent_term:put(WarnedKey, true)
    end.

rate_limit_key(peer, Req) ->
    {IP, _Port} = cowboy_req:peer(Req),
    IP;
rate_limit_key({Mod, Fun}, Req) when is_atom(Mod), is_atom(Fun) ->
    Mod:Fun(Req);
rate_limit_key(Other, _Req) ->
    error({invalid_option, key, Other}).

retry_after_seconds(Ms) when is_integer(Ms), Ms >= 1000 ->
    Ms div 1000;
retry_after_seconds(_) ->
    1.
