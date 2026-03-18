# Rate Limiting

`nova_auth_rate_limit` is a Nova plugin that provides IP-based rate limiting
using an ETS bag table. When a client exceeds the request limit within the
time window, a `429 Too Many Requests` response is returned with a `Retry-After`
header.

## Setup

Add `nova_auth_rate_limit` as a plugin in your Nova route configuration:

```erlang
#{prefix => "/api/auth",
  plugins => [
      {pre_request, nova_auth_rate_limit, #{
          max_requests => 5,
          window_seconds => 60
      }}
  ],
  routes => [
      {"/login", {auth_controller, login}, #{methods => [post]}},
      {"/register", {auth_controller, register}, #{methods => [post]}}
  ]}
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_requests` | `pos_integer()` | `10` | Maximum requests allowed within the window |
| `window_seconds` | `pos_integer()` | `60` | Time window in seconds |
| `key_fun` | `fun((cowboy_req:req()) -> term())` | IP-based | Function to extract the rate limit key from the request |

## Custom Key Function

By default, rate limiting is keyed by client IP address. You can provide a
custom key function to rate limit by other criteria:

```erlang
%% Rate limit by API key header
KeyFun = fun(Req) ->
    cowboy_req:header(<<"x-api-key">>, Req, <<"anonymous">>)
end,

#{plugins => [
    {pre_request, nova_auth_rate_limit, #{
        max_requests => 100,
        window_seconds => 3600,
        key_fun => KeyFun
    }}
]}
```

```erlang
%% Rate limit by IP + path combination
KeyFun = fun(Req) ->
    {IP, _Port} = cowboy_req:peer(Req),
    Path = cowboy_req:path(Req),
    {IP, Path}
end
```

## Response Format

When rate limited, the plugin stops request processing and returns:

- **Status:** `429 Too Many Requests`
- **Headers:** `Content-Type: application/json`, `Retry-After: <window_seconds>`
- **Body:** `{"error": "too many requests"}`
