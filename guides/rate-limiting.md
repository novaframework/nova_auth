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
    limiter => auth_rate_limit,      % Limiter name (default: nova_auth_rate_limit)
    limit => 5,                       % Max requests per window (default: 10)
    window => 900000,                 % Window in ms, 15 minutes (default: 60000)
    algorithm => token_bucket,        % Seki algorithm (default: sliding_window)
    key_fun => fun my_key/1           % Custom key function (default: peer IP)
}}
```

A limiter is created by the first request that uses its name, with that
request's `limit`, `window` and `algorithm`. Route groups that use the same
`limiter` name (including the default) share its counters and its settings,
so give each distinct policy its own name.

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
{pre_request, nova_auth_rate_limit, #{
    key_fun => fun(Req) ->
        case nova_auth_actor:fetch(Req) of
            {ok, #{id := UserId}} -> {user, UserId};
            {error, not_found} -> {ip, element(1, cowboy_req:peer(Req))}
        end
    end
}}
```

## Response Headers

On allowed requests:
- `x-ratelimit-remaining`: remaining requests in the current window

On denied requests (429 Too Many Requests, JSON body `{"error": "too many requests"}`):
- `retry-after`: seconds until the client can retry
- `x-ratelimit-remaining`: `0`

A denied request stops the plugin chain (`{stop, Req, State}`), so the
controller does not run.

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
