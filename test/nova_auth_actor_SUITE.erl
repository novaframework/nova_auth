-module(nova_auth_actor_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([
    store_and_fetch_roundtrip/1,
    fetch_does_not_create_atoms/1,
    fetch_rejects_non_actor_terms/1,
    fetch_rejects_corrupt_binary/1,
    renew_moves_to_new_empty_session/1,
    sign_in_renews_then_stores/1
]).

all() ->
    [
        store_and_fetch_roundtrip,
        fetch_does_not_create_atoms,
        fetch_rejects_non_actor_terms,
        fetch_rejects_corrupt_binary,
        renew_moves_to_new_empty_session,
        sign_in_renews_then_stores
    ].

init_per_suite(Config) ->
    ok = test_session_backend:start(),
    ok = application:set_env(nova, session_manager, test_session_backend),
    Config.

end_per_suite(_Config) ->
    ok = application:unset_env(nova, session_manager),
    test_session_backend:stop().

store_and_fetch_roundtrip(_Config) ->
    Req = req(~"sid-roundtrip"),
    Actor = #{id => 42, provider => password, roles => [admin]},
    ok = nova_auth_actor:store(Req, Actor),
    ?assertEqual({ok, Actor}, nova_auth_actor:fetch(Req)).

fetch_does_not_create_atoms(_Config) ->
    Req = req(~"sid-atoms"),
    Name = ~"nova_auth_actor_SUITE_atom_that_does_not_exist",
    ok = nova_session:set(Req, nova_auth_actor:session_key(), small_atom_ext(Name)),
    ?assertEqual({error, not_found}, nova_auth_actor:fetch(Req)),
    ?assertError(badarg, binary_to_existing_atom(Name)).

fetch_rejects_non_actor_terms(_Config) ->
    Req = req(~"sid-shape"),
    Key = nova_auth_actor:session_key(),
    [
        begin
            ok = nova_session:set(Req, Key, term_to_binary(Term)),
            ?assertEqual({error, not_found}, nova_auth_actor:fetch(Req))
        end
     || Term <- [
            not_a_map,
            #{id => 1},
            #{provider => password},
            #{id => 1.5, provider => password},
            #{id => 1, provider => ~"password"}
        ]
    ].

fetch_rejects_corrupt_binary(_Config) ->
    Req = req(~"sid-corrupt"),
    ok = nova_session:set(Req, nova_auth_actor:session_key(), ~"not an external term"),
    ?assertEqual({error, not_found}, nova_auth_actor:fetch(Req)).

renew_moves_to_new_empty_session(_Config) ->
    OldId = ~"sid-renew",
    Req = req(OldId),
    ok = nova_auth_actor:store(Req, #{id => 1, provider => password}),
    ok = nova_session:set(Req, ~"other", ~"value"),
    {ok, Req1} = nova_auth_actor:renew(Req),
    #{nova_session_id := NewId} = Req1,
    ?assertNotEqual(OldId, NewId),
    ?assert(is_binary(NewId) andalso byte_size(NewId) >= 43),
    ?assertEqual([], test_session_backend:keys(OldId)),
    ?assertEqual({error, not_found}, nova_auth_actor:fetch(Req1)),
    ok = nova_auth_actor:store(Req1, #{id => 2, provider => password}),
    ?assertMatch({ok, #{id := 2}}, nova_auth_actor:fetch(Req1)),
    ?assertEqual({error, not_found}, nova_auth_actor:fetch(Req)).

sign_in_renews_then_stores(_Config) ->
    OldId = ~"sid-sign-in",
    Req = req(OldId),
    ok = nova_session:set(Req, ~"planted", ~"value"),
    Actor = #{id => 7, provider => password},
    {ok, Req1} = nova_auth_actor:sign_in(Req, Actor),
    #{nova_session_id := NewId} = Req1,
    ?assertNotEqual(OldId, NewId),
    ?assertEqual([], test_session_backend:keys(OldId)),
    ?assertEqual({ok, Actor}, nova_auth_actor:fetch(Req1)),
    ?assertEqual({error, not_found}, nova_auth_actor:fetch(Req)).

req(SessionId) ->
    #{
        nova_session_id => SessionId,
        headers => #{}
    }.

small_atom_ext(Name) ->
    <<131, 119, (byte_size(Name)), Name/binary>>.
