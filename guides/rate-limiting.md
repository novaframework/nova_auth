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

By default, this allows 10 requests per 60 seconds per IP address using a sliding window algorithm.

## When the limit is checked

On a Nova that has the `pre_security/4` plugin callback, the limit is checked
there: ahead of the security callback of the route group, for every request,
so a request that the security callback refuses is counted as well. On an
earlier Nova the limit is checked in `pre_request/4`. A request is counted
once either way.

## Configuration

Pass options in the plugin config map:

```erlang
{pre_request, nova_auth_rate_limit, #{
    limiter => auth_rate_limit,      % Limiter name (default: nova_auth_rate_limit)
    limit => 5,                       % Max requests per window (default: 10)
    window => 900000,                 % Window in ms — 15 minutes (default: 60000)
    algorithm => token_bucket,        % Seki algorithm (default: sliding_window)
    key_fun => fun my_key/1           % Custom key function (default: peer IP)
}}
```

## Algorithms

Seki supports four rate limiting algorithms:

| Algorithm | Best For | Burst Control |
|-----------|----------|---------------|
| `sliding_window` | General purpose (default) | Prevents boundary bursts |
| `token_bucket` | APIs with controlled bursts | Allows bursts up to bucket size |
| `gcra` | High-performance, minimal state | Configurable tolerance |
| `leaky_bucket` | Traffic shaping | No bursts |

## Custom Rate Limit Keys

By default, rate limiting is per client IP. You can customize this:

```erlang
%% Rate limit by authenticated user
{pre_request, nova_auth_rate_limit, #{
    key_fun => fun(Req) ->
        case maps:get(auth_data, Req, undefined) of
            #{id := UserId} -> {user, UserId};
            _ -> {ip, element(1, cowboy_req:peer(Req))}
        end
    end
}}
```

On a Nova that checks the limit ahead of the security callback, `key_fun`
runs before `auth_data` is set, so the example above falls back to the client
IP there. Key on something the request carries itself, such as a header.

## Response Headers

On allowed requests:
- `x-ratelimit-remaining` — remaining requests in the current window

On denied requests (429 Too Many Requests):
- `retry-after` — seconds until the client can retry
- `x-ratelimit-remaining` — `0`

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

- `[seki, rate_limit, allow]` — request allowed
- `[seki, rate_limit, deny]` — request denied
