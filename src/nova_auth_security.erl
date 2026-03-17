-module(nova_auth_security).
-moduledoc ~"""
Nova security callback for route-level authentication. Returns a closure
suitable for use in Nova route security configuration.
""".

-export([require_authenticated/1, require_authenticated/2]).

-doc "Return a security fun bound to the given auth module for use in route config.".
-spec require_authenticated(module()) -> fun((cowboy_req:req()) -> term()).
require_authenticated(AuthMod) ->
    fun(Req) -> require_authenticated(AuthMod, Req) end.

-doc "Check the session for a valid token and return the user or 401.".
-spec require_authenticated(module(), cowboy_req:req()) ->
    {true, map()} | {false, integer(), map(), binary()}.
require_authenticated(AuthMod, Req) ->
    case nova_session:get(Req, <<"session_token">>) of
        {ok, Token} ->
            case nova_auth_session:get_user_by_session_token(AuthMod, Token) of
                {ok, User} ->
                    {true, User};
                _ ->
                    unauthorized()
            end;
        _ ->
            unauthorized()
    end.

unauthorized() ->
    Body = iolist_to_binary(json:encode(#{<<"error">> => <<"unauthorized">>})),
    {false, 401, #{<<"content-type">> => <<"application/json">>}, Body}.
