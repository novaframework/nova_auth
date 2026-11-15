-module(nova_auth_actor_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_testcase/2, end_per_testcase/2]).
-export([
    sign_in_stores_the_actor/1,
    sign_in_moves_to_a_new_session/1,
    sign_in_keeps_the_session_without_nova_sign_in/1,
    store_returns_ok/1
]).

-define(SESSION_ID, ~"session-before-sign-in").
-define(ACTOR, #{id => 1, provider => password, email => ~"user@example.com"}).

all() ->
    [
        sign_in_stores_the_actor,
        sign_in_moves_to_a_new_session,
        sign_in_keeps_the_session_without_nova_sign_in,
        store_returns_ok
    ].

init_per_testcase(sign_in_moves_to_a_new_session, Config) ->
    case nova_has_sign_in() of
        true -> start_sessions(Config);
        false -> {skip, "this Nova has no nova_session:sign_in/3"}
    end;
init_per_testcase(sign_in_keeps_the_session_without_nova_sign_in, Config) ->
    case nova_has_sign_in() of
        true -> {skip, "this Nova has nova_session:sign_in/3"};
        false -> start_sessions(Config)
    end;
init_per_testcase(_TestCase, Config) ->
    start_sessions(Config).

end_per_testcase(_TestCase, _Config) ->
    case ets:whereis(test_auth_session_backend) of
        undefined -> ok;
        _Table -> test_auth_session_backend:stop()
    end.

sign_in_stores_the_actor(_Config) ->
    {ok, SignedIn} = nova_auth_actor:sign_in(request(), ?ACTOR),
    ?assertEqual({ok, ?ACTOR}, nova_auth_actor:fetch(SignedIn)).

sign_in_moves_to_a_new_session(_Config) ->
    ok = nova_session:set(request(), ~"before", ~"kept by nobody"),
    {ok, SignedIn} = nova_auth_actor:sign_in(request(), ?ACTOR),
    ?assertNotEqual(?SESSION_ID, maps:get(nova_session_id, SignedIn)),
    ?assertEqual({error, not_found}, nova_auth_actor:fetch(request())),
    ?assertEqual({error, not_found}, nova_session:get(request(), ~"before")),
    ?assertEqual({error, not_found}, nova_session:get(SignedIn, ~"before")).

sign_in_keeps_the_session_without_nova_sign_in(_Config) ->
    ?assertEqual({ok, request()}, nova_auth_actor:sign_in(request(), ?ACTOR)),
    ?assertEqual({ok, ?ACTOR}, nova_auth_actor:fetch(request())).

store_returns_ok(_Config) ->
    ?assertEqual(ok, nova_auth_actor:store(request(), ?ACTOR)),
    ?assertEqual({ok, ?ACTOR}, nova_auth_actor:fetch(request())).

start_sessions(Config) ->
    ok = test_auth_session_backend:start(),
    Config.

request() ->
    #{nova_session_id => ?SESSION_ID}.

nova_has_sign_in() ->
    _ = code:ensure_loaded(nova_session),
    erlang:function_exported(nova_session, sign_in, 3).
