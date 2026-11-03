-module(nova_auth_actor).
-moduledoc ~"""
Generic session actor storage. Stores and retrieves actor maps from
Nova's ETS session. Both password auth and OIDC write here, providing
a unified downstream experience for security callbacks and policies.

Call `renew/1` before `store/2` at sign-in, and at sign-out, so a session
id planted or observed before the privilege change stops working
(session fixation).
""".

-export([store/2, fetch/1, delete/1, renew/1, session_key/0]).

-define(SESSION_KEY, ~"nova_auth_actor").

-doc "Store an actor map in the Nova session.".
-spec store(cowboy_req:req(), nova_auth:actor()) -> ok | {error, atom()}.
store(Req, Actor) when is_map(Actor) ->
    nova_session:set(Req, ?SESSION_KEY, term_to_binary(Actor)).

-doc """
Fetch the actor map from the Nova session.

The stored value is decoded with `binary_to_term/2` and the `safe` option,
so it can never create atoms. A value that does not decode to an actor map
is reported as `{error, not_found}`.
""".
-spec fetch(cowboy_req:req()) -> {ok, nova_auth:actor()} | {error, not_found}.
fetch(Req) ->
    case nova_session:get(Req, ?SESSION_KEY) of
        {ok, Bin} when is_binary(Bin) ->
            decode(Bin);
        _ ->
            {error, not_found}
    end.

-doc "Clear the actor from the Nova session.".
-spec delete(cowboy_req:req()) -> {ok, cowboy_req:req()} | {error, atom()}.
delete(Req) ->
    nova_session:delete(Req, ?SESSION_KEY).

-doc """
Move the client to a new, empty session.

The data of the current session, including any stored actor, is deleted and
the response carries a new session id. Use the returned request for the
`store/2` call that follows: it carries the new id.

Delegates to `nova_session:renew/1`, which issues the new `session_id`
cookie with the response.
""".
-spec renew(cowboy_req:req()) -> {ok, cowboy_req:req()}.
renew(Req) ->
    nova_session:renew(Req).

-doc "Return the session key used for actor storage.".
-spec session_key() -> binary().
session_key() ->
    ?SESSION_KEY.

decode(Bin) ->
    try binary_to_term(Bin, [safe]) of
        #{id := Id, provider := Provider} = Actor when
            (is_binary(Id) orelse is_integer(Id)), is_atom(Provider)
        ->
            {ok, Actor};
        _ ->
            {error, not_found}
    catch
        error:badarg ->
            {error, not_found}
    end.
