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

- `limiter`: limiter name atom (default: a name derived from the settings)
- `limit`: max requests per window (default: 10)
- `window`: window in milliseconds (default: 60000)
- `algorithm`: Seki algorithm (default: `sliding_window`)
- `key`: `{Module, Function}`; `Module:Function(Req)` returns the rate
  limit key (default: the peer IP address). Behind a reverse proxy use
  `{nova_auth_rate_limit, client_ip}`, see `client_ip/1`.

Without `limiter`, the name is derived from `algorithm`, `limit` and
`window` (for example `nova_auth_rate_limit_sliding_window_10_60000`): route groups with the same settings share counters and groups
with different settings are independent. Route groups that give the same
`limiter` name share its counters and must use the same settings; a request
whose settings differ from the ones the limiter was created with raises
`error({limiter_settings_conflict, Name, Existing, Requested})`.

A denied request returns `{stop, {reply, 429, Headers, Body}, Req, State}`:
Nova sends the 429 JSON reply and no later plugin or controller runs.

`key_fun` (`fun(Req) -> Key`) still works but is deprecated: it puts a fun
in route configuration. It takes precedence over `key`, and each route
configuration that uses it logs one warning. Use `key => {Module, Function}`.
""".
-behaviour(nova_plugin).

-export([init/0, stop/1, pre_request/4, post_request/4, plugin_info/0]).
-export([client_ip/1]).

-include_lib("kernel/include/logger.hrl").

-type reply() :: {reply, 429, #{binary() => binary()}, binary()}.

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
pre_request(Req, _Env, Options, PluginState) ->
    #{
        limit := Limit,
        window := Window,
        algorithm := Algorithm,
        key := KeySpec
    } = maps:merge(defaults(), Options),
    Settings = #{algorithm => Algorithm, limit => Limit, window => Window},
    LimiterName = limiter_name(Options, Settings),
    ok = ensure_limiter(LimiterName, Settings),
    case seki:check(LimiterName, request_key(Options, KeySpec, Req)) of
        {allow, #{remaining := Remaining}} ->
            Req1 = cowboy_req:set_resp_header(
                ~"x-ratelimit-remaining", integer_to_binary(Remaining), Req
            ),
            {ok, Req1, PluginState};
        {deny, #{retry_after := RetryAfterMs}} ->
            Headers = #{
                ~"content-type" => ~"application/json",
                ~"retry-after" => integer_to_binary(retry_after_seconds(RetryAfterMs)),
                ~"x-ratelimit-remaining" => ~"0"
            },
            Body = iolist_to_binary(json:encode(#{~"error" => ~"too many requests"})),
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

-doc """
Rate-limit key for clients behind trusted reverse proxies.

Use it as `key => {nova_auth_rate_limit, client_ip}`. Returns the peer
address unless the peer is listed in the `nova_auth` application env
`trusted_proxies`. For a trusted peer it walks `X-Forwarded-For` from the
right, skips addresses that are trusted proxies, and returns the first
address that is not. The leftmost entry is never trusted for being leftmost:
a client can put anything there. If an entry does not parse as a bare IP
address, the last trusted hop is returned.

`trusted_proxies` is a list of exact addresses (`{10, 0, 0, 1}`) and CIDR
ranges (`{{10, 0, 0, 0}, 8}`), IPv4 or IPv6. It defaults to `[]`, which
makes `client_ip/1` the peer address. Any other entry raises
`error({invalid_option, trusted_proxies, Entry})`.

```erlang
{nova_auth, [{trusted_proxies, [{{10, 0, 0, 0}, 8}, {0, 0, 0, 0, 0, 0, 0, 1}]}]}
```
""".
-spec client_ip(cowboy_req:req()) -> inet:ip_address().
client_ip(Req) ->
    {Peer, _Port} = cowboy_req:peer(Req),
    Trusted = application:get_env(nova_auth, trusted_proxies, []),
    PeerIP = unmap_ipv4(Peer),
    case is_trusted(PeerIP, Trusted) of
        true -> forwarded_client(forwarded_for(Req), PeerIP, Trusted);
        false -> PeerIP
    end.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

defaults() ->
    #{
        limit => ?DEFAULT_LIMIT,
        window => ?DEFAULT_WINDOW,
        algorithm => sliding_window,
        key => peer
    }.

limiter_name(#{limiter := Name}, _Settings) ->
    Name;
limiter_name(_Options, Settings) ->
    case persistent_term:get({?MODULE, name, Settings}, undefined) of
        undefined ->
            Name = derived_name(Settings),
            persistent_term:put({?MODULE, name, Settings}, Name),
            Name;
        Name ->
            Name
    end.

derived_name(#{algorithm := Algorithm, limit := Limit, window := Window}) ->
    Name = iolist_to_binary(
        io_lib:format("nova_auth_rate_limit_~w_~w_~w", [Algorithm, Limit, Window])
    ),
    %% Settings come from route configuration, never from a request, so the
    %% atoms made here are bounded by the configured route groups.
    %% elp:ignore W0023 - bounded by route configuration
    binary_to_atom(Name).

ensure_limiter(Name, Settings) ->
    case persistent_term:get({?MODULE, Name}, undefined) of
        Settings ->
            ok;
        undefined ->
            case seki:new_limiter(Name, Settings) of
                ok -> ok;
                {error, already_registered} -> ok
            end,
            persistent_term:put({?MODULE, Name}, Settings);
        Existing ->
            error({limiter_settings_conflict, Name, Existing, Settings})
    end.

forwarded_for(Req) ->
    case cowboy_req:header(~"x-forwarded-for", Req) of
        undefined -> [];
        Value -> lists:reverse(binary:split(Value, ~",", [global]))
    end.

forwarded_client([], LastTrusted, _Trusted) ->
    LastTrusted;
forwarded_client([Hop | Hops], LastTrusted, Trusted) ->
    case hop_address(Hop) of
        {ok, Addr} ->
            IP = unmap_ipv4(Addr),
            case is_trusted(IP, Trusted) of
                true -> forwarded_client(Hops, IP, Trusted);
                false -> IP
            end;
        {error, _} ->
            LastTrusted
    end.

hop_address(Hop) ->
    case string:trim(Hop) of
        Trimmed when is_binary(Trimmed) -> inet:parse_strict_address(binary_to_list(Trimmed));
        _ -> {error, einval}
    end.

is_trusted(IP, Trusted) ->
    lists:any(fun(Entry) -> trusted_entry(IP, Entry) end, Trusted).

trusted_entry(IP, {Net, Len} = Entry) when is_tuple(Net), is_integer(Len) ->
    case ip_bits(Net) of
        {NetInt, Bits} when Len >= 0, Len =< Bits ->
            case ip_bits(IP) of
                {IPInt, Bits} -> IPInt bsr (Bits - Len) =:= NetInt bsr (Bits - Len);
                _ -> false
            end;
        _ ->
            error({invalid_option, trusted_proxies, Entry})
    end;
trusted_entry(IP, Entry) when is_tuple(Entry) ->
    case ip_bits(Entry) of
        {_, _} -> unmap_ipv4(Entry) =:= IP;
        error -> error({invalid_option, trusted_proxies, Entry})
    end;
trusted_entry(_IP, Entry) ->
    error({invalid_option, trusted_proxies, Entry}).

ip_bits({A, B, C, D} = IP) ->
    case inet:is_ip_address(IP) of
        true ->
            <<N:32>> = <<A, B, C, D>>,
            {N, 32};
        false ->
            error
    end;
ip_bits({A, B, C, D, E, F, G, H} = IP) ->
    case inet:is_ip_address(IP) of
        true ->
            <<N:128>> = <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>,
            {N, 128};
        false ->
            error
    end;
ip_bits(_) ->
    error.

unmap_ipv4({0, 0, 0, 0, 0, 16#FFFF, AB, CD}) ->
    {AB bsr 8, AB band 255, CD bsr 8, CD band 255};
unmap_ipv4(IP) ->
    IP.

request_key(#{key_fun := KeyFun} = Options, _KeySpec, Req) when is_function(KeyFun, 1) ->
    warn_key_fun_once(Options),
    KeyFun(Req);
request_key(#{key_fun := Other}, _KeySpec, _Req) ->
    error({invalid_option, key_fun, Other});
request_key(_Options, KeySpec, Req) ->
    rate_limit_key(KeySpec, Req).

warn_key_fun_once(Options) ->
    case persistent_term:get({?MODULE, key_fun_warned, Options}, false) of
        true ->
            ok;
        false ->
            persistent_term:put({?MODULE, key_fun_warned, Options}, true),
            ?LOG_WARNING(#{
                msg => ~"nova_auth_rate_limit key_fun is deprecated",
                replacement => ~"key => {Module, Function}"
            })
    end.

rate_limit_key(peer, Req) ->
    {IP, _Port} = cowboy_req:peer(Req),
    IP;
rate_limit_key({Mod, Fun}, Req) when is_atom(Mod), is_atom(Fun) ->
    Mod:Fun(Req);
rate_limit_key(Other, _Req) ->
    error({invalid_option, key, Other}).

retry_after_seconds(Ms) when is_integer(Ms), Ms > 0 ->
    (Ms + 999) div 1000;
retry_after_seconds(_) ->
    1.
