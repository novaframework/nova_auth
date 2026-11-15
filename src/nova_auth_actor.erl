-module(nova_auth_actor).
-moduledoc ~"""
Generic session actor storage. Stores and retrieves actor maps from
Nova's ETS session. Both password auth and OIDC write here, providing
a unified downstream experience for security callbacks and policies.
""".

-export([sign_in/2, store/2, fetch/1, delete/1, session_key/0]).

-define(SESSION_KEY, ~"nova_auth_actor").

-doc """
Sign an actor in: store the actor map in the Nova session and return the
request to go on with.

On a Nova whose `nova_session` module has `sign_in` the client is moved to a
new session id, what the session held before is deleted, and the returned
request is the one that carries the new id. Use it for every session call that
follows. A `nova_csrf_plugin` token made for the old id is refused from then
on, so answer a form sign-in with a redirect. On an earlier Nova the actor is
stored in the session the request has and the request comes back unchanged.

```erlang
{ok, SignedIn} = nova_auth_actor:sign_in(Req, #{id => UserId, provider => password}),
{redirect, ~"/"}
```
""".
-spec sign_in(cowboy_req:req(), nova_auth:actor()) -> {ok, cowboy_req:req()} | {error, atom()}.
sign_in(Req, Actor) when is_map(Actor) ->
    sign_in(nova_session, Req, term_to_binary(Actor)).

-doc """
Store an actor map in the session the request has. The session id stays as
it was.
""".
-doc #{
    deprecated =>
        ~"Sign in with sign_in/2, which also moves the client to a new session id where Nova can"
}.
-spec store(cowboy_req:req(), nova_auth:actor()) -> ok | {error, atom()}.
store(Req, Actor) when is_map(Actor) ->
    nova_session:set(Req, ?SESSION_KEY, term_to_binary(Actor)).

-doc "Fetch the actor map from the Nova session.".
-spec fetch(cowboy_req:req()) -> {ok, nova_auth:actor()} | {error, not_found}.
fetch(Req) ->
    case nova_session:get(Req, ?SESSION_KEY) of
        {ok, Bin} when is_binary(Bin) ->
            %% eqwalizer:fixme - binary_to_term returns term()
            {ok, binary_to_term(Bin)};
        _ ->
            {error, not_found}
    end.

-doc "Sign the actor out: delete the whole Nova session of the request.".
-spec delete(cowboy_req:req()) -> {ok, cowboy_req:req()} | {error, atom()}.
delete(Req) ->
    nova_session:delete(Req).

-doc "Return the session key used for actor storage.".
-spec session_key() -> binary().
session_key() ->
    ?SESSION_KEY.

%% nova_session:sign_in/3 is not in every Nova this library builds against,
%% so it is called through a variable: a literal call is an undefined
%% function to xref and dialyzer there.
-spec sign_in(module(), cowboy_req:req(), binary()) -> {ok, cowboy_req:req()} | {error, atom()}.
sign_in(Session, Req, Value) ->
    _ = code:ensure_loaded(Session),
    case erlang:function_exported(Session, sign_in, 3) of
        true ->
            Session:sign_in(Req, ?SESSION_KEY, Value);
        false ->
            case nova_session:set(Req, ?SESSION_KEY, Value) of
                ok -> {ok, Req};
                {error, _Reason} = Error -> Error
            end
    end.
