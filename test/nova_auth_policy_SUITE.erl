-module(nova_auth_policy_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0]).
-export([
    allow_authenticated_with_actor/1,
    allow_authenticated_without_actor/1,
    allow_role_single/1,
    allow_role_list/1,
    allow_role_wrong_role/1,
    allow_owner_read_returns_filter/1,
    allow_owner_write_matches/1,
    allow_owner_write_no_match/1,
    deny_all_always_false/1
]).

all() ->
    [{group, policy_tests}].

groups() ->
    [
        {policy_tests, [parallel], [
            allow_authenticated_with_actor,
            allow_authenticated_without_actor,
            allow_role_single,
            allow_role_list,
            allow_role_wrong_role,
            allow_owner_read_returns_filter,
            allow_owner_write_matches,
            allow_owner_write_no_match,
            deny_all_always_false
        ]}
    ].

allow_authenticated_with_actor(_Config) ->
    #{condition := Cond} = nova_auth_policy:allow_authenticated(),
    ?assert(Cond(#{id => 1}, #{})).

allow_authenticated_without_actor(_Config) ->
    #{condition := Cond} = nova_auth_policy:allow_authenticated(),
    ?assertNot(Cond(undefined, #{})).

allow_role_single(_Config) ->
    #{condition := Cond} = nova_auth_policy:allow_role(admin),
    ?assert(Cond(#{id => 1, role => admin}, #{})).

allow_role_list(_Config) ->
    #{condition := Cond} = nova_auth_policy:allow_role([admin, moderator]),
    ?assert(Cond(#{id => 1, role => moderator}, #{})).

allow_role_wrong_role(_Config) ->
    #{condition := Cond} = nova_auth_policy:allow_role(admin),
    ?assertNot(Cond(#{id => 1, role => user}, #{})).

allow_owner_read_returns_filter(_Config) ->
    #{condition := Cond} = nova_auth_policy:allow_owner(user_id),
    Result = Cond(#{id => 42}, #{type => read}),
    ?assert(is_function(Result, 1)).

allow_owner_write_matches(_Config) ->
    #{condition := Cond} = nova_auth_policy:allow_owner(user_id),
    ?assert(Cond(#{id => 42}, #{record => #{user_id => 42}})).

allow_owner_write_no_match(_Config) ->
    #{condition := Cond} = nova_auth_policy:allow_owner(user_id),
    ?assertNot(Cond(#{id => 42}, #{record => #{user_id => 99}})).

deny_all_always_false(_Config) ->
    #{condition := Cond} = nova_auth_policy:deny_all(),
    ?assertNot(Cond(#{id => 1, role => admin}, #{})).
