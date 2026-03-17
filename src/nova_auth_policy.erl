-module(nova_auth_policy).
-moduledoc ~"""
Policy helpers for nova_resource authorization. Returns policy maps with
condition functions that can be evaluated against an actor and context.
""".

-export([
    allow_authenticated/0,
    allow_role/1,
    allow_owner/1,
    deny_all/0
]).

-type policy() :: #{action := atom(), condition := fun()}.

-doc "Allow any authenticated (non-undefined) actor.".
-spec allow_authenticated() -> policy().
allow_authenticated() ->
    #{
        action => '_',
        condition => fun(Actor, _Extra) -> Actor =/= undefined end
    }.

-doc "Allow actors whose `role` field matches one of the given roles.".
-spec allow_role(atom() | [atom()]) -> policy().
allow_role(Role) when is_atom(Role) ->
    allow_role([Role]);
allow_role(Roles) when is_list(Roles) ->
    #{
        action => '_',
        condition => fun(Actor, _Extra) ->
            UserRole = maps:get(role, Actor, undefined),
            lists:member(UserRole, Roles)
        end
    }.

-doc "Allow actors who own the record (actor id matches the owner field).".
-spec allow_owner(atom()) -> policy().
allow_owner(OwnerField) ->
    #{
        action => '_',
        condition => fun
            (Actor, #{type := read}) ->
                UserId = maps:get(id, Actor),
                fun(Query) ->
                    kura_query:where(Query, {OwnerField, UserId})
                end;
            (Actor, Extra) ->
                Record = maps:get(record, Extra, #{}),
                maps:get(OwnerField, Record, undefined) =:= maps:get(id, Actor)
        end
    }.

-doc "Deny all actors unconditionally.".
-spec deny_all() -> policy().
deny_all() ->
    #{
        action => '_',
        condition => fun(_Actor, _Extra) -> false end
    }.
