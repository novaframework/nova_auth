-module(test_rate_limit_key).

-export([same_key/1]).

same_key(Req) when is_map(Req) ->
    same_key.
