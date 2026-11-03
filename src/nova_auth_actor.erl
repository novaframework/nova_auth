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
-define(SESSION_COOKIE, ~"session_id").
-define(SESSION_ID_BYTES, 32).

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
`store/2` call that follows, and return it from the controller (for example
`{redirect, Path, Req1}`) so the new cookie reaches the client.

Uses `nova_session:renew/1` when the running Nova provides it. Older Nova
releases have no renew function; there the session data is deleted with
`nova_session:delete/1` and a new `session_id` cookie is set with a
`crypto:strong_rand_bytes/1` id. That cookie gets `Path=/`, `HttpOnly`,
`SameSite=Lax`, and `Secure` on HTTPS requests; the `nova` application's
`session_cookie_opts` map, when set, is merged over these.
""".
-spec renew(cowboy_req:req()) -> {ok, cowboy_req:req()}.
renew(Req) ->
    case nova_has_renew() of
        true -> nova_session_renew(Req);
        false -> renew_fallback(Req)
    end.

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

nova_has_renew() ->
    _ = code:ensure_loaded(nova_session),
    erlang:function_exported(nova_session, renew, 1).

%% Called through a variable: older Nova releases have no renew/1, and a
%% literal remote call would fail xref there.
nova_session_renew(Req) ->
    Mod = nova_session,
    Mod:renew(Req).

renew_fallback(Req0) ->
    {ok, Req1} = nova_session:delete(Req0),
    SessionId = base64:encode(
        crypto:strong_rand_bytes(?SESSION_ID_BYTES), #{mode => urlsafe, padding => false}
    ),
    Req2 = cowboy_req:set_resp_cookie(?SESSION_COOKIE, SessionId, Req1, cookie_opts(Req1)),
    {ok, Req2#{nova_session_id => SessionId}}.

cookie_opts(Req) ->
    Defaults = #{
        path => ~"/",
        http_only => true,
        same_site => lax,
        secure => cowboy_req:scheme(Req) =:= ~"https"
    },
    case application:get_env(nova, session_cookie_opts) of
        {ok, Opts} when is_map(Opts) -> maps:merge(Defaults, Opts);
        _ -> Defaults
    end.
