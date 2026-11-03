# Rate Limiting

Nova Auth includes a rate limiting plugin powered by [Seki](https://github.com/Taure/seki), providing production-grade rate limiting with multiple algorithms.

## Basic Usage

Add the plugin to any route group:

```erlang
#{prefix => <<"/api/auth">>,
  plugins => [
      {pre_request, nova_auth_rate_limit, #{}}
  ],
  routes => [
      {<<"/login">>, fun my_session_controller:create/1, #{methods => [post]}},
      {<<"/register">>, fun my_registration_controller:create/1, #{methods => [post]}}
  ]}
```

By default, this allows 10 requests per 60 seconds per IP address using a sliding window algorithm. Every option below is optional and falls back to its default.

## Configuration

Pass options in the plugin config map:

```erlang
{pre_request, nova_auth_rate_limit, #{
    limiter => auth_rate_limit,      % Limiter name (default: derived from the settings)
    limit => 5,                       % Max requests per window (default: 10)
    window => 900000,                 % Window in ms, 15 minutes (default: 60000)
    algorithm => token_bucket,        % Seki algorithm (default: sliding_window)
    key => {my_rate_limit, key}       % Module:Function(Req) -> Key (default: peer IP)
}}
```

Without `limiter`, the limiter name is derived from `limit`, `window` and
`algorithm`. Route groups with the same settings share counters, and groups
with different settings are independent, so a strict group can never be
loosened by a lax one that happened to serve the first request.

Route groups that give the same `limiter` name share its counters and must
use the same settings. A limiter is created by the first request that uses
its name; a later request under that name with other settings raises
`error({limiter_settings_conflict, Name, Existing, Requested})`, so the
mismatch shows up as a 500 in testing instead of a silently weaker limit.

## Algorithms

Seki supports four rate limiting algorithms:

| Algorithm | Best For | Burst Control |
|-----------|----------|---------------|
| `sliding_window` | General purpose (default) | Prevents boundary bursts |
| `token_bucket` | APIs with controlled bursts | Allows bursts up to bucket size |
| `gcra` | High-performance, minimal state | Configurable tolerance |
| `leaky_bucket` | Traffic shaping | No bursts |

## Custom Rate Limit Keys

By default, rate limiting is per client IP (`cowboy_req:peer/1`). Behind a
reverse proxy that is the proxy's address, so derive the key from a header
the proxy sets and clients cannot forge.

Nova runs `pre_request` plugins before the route's security function, so
`auth_data` is not in the request yet. Read the actor from the session
instead:

```erlang
%% Rate limit by signed-in user, falling back to the client IP
{pre_request, nova_auth_rate_limit, #{key => {my_rate_limit, key}}}
```

```erlang
-module(my_rate_limit).
-export([key/1]).

key(Req) ->
    case nova_auth_actor:fetch(Req) of
        {ok, #{id := UserId}} -> {user, UserId};
        {error, not_found} -> {ip, element(1, cowboy_req:peer(Req))}
    end.
```

`key` takes a `{Module, Function}` pair rather than a fun, so route
configuration stays plain data. The `key_fun` option of earlier releases is
rejected with `error({removed_option, key_fun})`.

## Response Headers

On allowed requests:
- `x-ratelimit-remaining`: remaining requests in the current window

On denied requests (429 Too Many Requests, JSON body `{"error": "too many requests"}`):
- `retry-after`: seconds until the client can retry
- `x-ratelimit-remaining`: `0`

A denied request returns `{stop, {reply, 429, Headers, Body}, Req, State}`:
Nova sends the reply and the controller does not run.

## Multiple Limiters

You can apply different rate limits to different route groups:

```erlang
%% Strict limit for auth endpoints
#{prefix => <<"/api/auth">>,
  plugins => [{pre_request, nova_auth_rate_limit, #{
      limiter => auth_limit,
      limit => 5,
      window => 900000
  }}]}

%% More permissive for general API
#{prefix => <<"/api">>,
  plugins => [{pre_request, nova_auth_rate_limit, #{
      limiter => api_limit,
      limit => 100,
      window => 60000
  }}]}
```

## Telemetry

Seki emits telemetry events that you can observe:

- `[seki, rate_limit, allow]`: request allowed
- `[seki, rate_limit, deny]`: request denied
