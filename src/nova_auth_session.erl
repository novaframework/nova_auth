-module(nova_auth_session).
-moduledoc ~"""
Session token lifecycle management. Handles creating, validating, and
deleting session tokens backed by the configured Kura repo.
""".

-include_lib("kura/include/kura.hrl").

-export([
    generate_session_token/2,
    get_user_by_session_token/2,
    delete_session_token/2,
    delete_all_user_tokens/2,
    delete_all_user_tokens/3
]).

-doc "Create a new session token for a user and store the hash in the database.".
-spec generate_session_token(module(), map()) -> {ok, binary()} | {error, term()}.
generate_session_token(AuthMod, User) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, token_schema := TokenSchema} = Cfg,
    TokenBytes = maps:get(token_bytes, Cfg),
    RawToken = nova_auth_token:generate(TokenBytes),
    HashedToken = nova_auth_token:hash(RawToken),
    Now = calendar:universal_time(),
    CS = kura_changeset:cast(
        TokenSchema,
        #{},
        #{
            user_id => maps:get(id, User),
            token => HashedToken,
            context => <<"session">>,
            inserted_at => Now
        },
        [user_id, token, context, inserted_at]
    ),
    case kura_repo_worker:insert(Repo, CS) of
        {ok, _} -> {ok, RawToken};
        {error, _} = Err -> Err
    end.

-doc "Look up a user by their raw session token, checking validity.".
-spec get_user_by_session_token(module(), binary()) -> {ok, map()} | {error, term()}.
get_user_by_session_token(AuthMod, SessionToken) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, token_schema := TokenSchema, user_schema := UserSchema} = Cfg,
    ValidityDays = maps:get(session_validity_days, Cfg),
    try
        HashedToken = nova_auth_token:hash(SessionToken),
        Q = kura_query:where(
            kura_query:where(kura_query:from(TokenSchema), {token, HashedToken}),
            {context, <<"session">>}
        ),
        case kura_repo_worker:all(Repo, Q) of
            {ok, [Token]} ->
                case nova_auth_token:valid(maps:get(inserted_at, Token), ValidityDays) of
                    true ->
                        kura_repo_worker:get(Repo, UserSchema, maps:get(user_id, Token));
                    false ->
                        {error, token_expired}
                end;
            _ ->
                {error, not_found}
        end
    catch
        _:_ -> {error, invalid_token}
    end.

-doc "Delete a specific session token (logout).".
-spec delete_session_token(module(), binary()) -> ok.
delete_session_token(AuthMod, SessionToken) ->
    #{repo := Repo, token_schema := TokenSchema} = nova_auth:config(AuthMod),
    try
        HashedToken = nova_auth_token:hash(SessionToken),
        Q = kura_query:where(
            kura_query:where(kura_query:from(TokenSchema), {token, HashedToken}),
            {context, <<"session">>}
        ),
        kura_repo_worker:delete_all(Repo, Q),
        ok
    catch
        _:_ -> ok
    end.

-doc "Delete all tokens for a user across all contexts.".
-spec delete_all_user_tokens(module(), term()) -> ok.
delete_all_user_tokens(AuthMod, UserId) ->
    #{repo := Repo, token_schema := TokenSchema} = nova_auth:config(AuthMod),
    Q = kura_query:where(kura_query:from(TokenSchema), {user_id, UserId}),
    kura_repo_worker:delete_all(Repo, Q),
    ok.

-doc "Delete all tokens for a user within a specific context.".
-spec delete_all_user_tokens(module(), term(), binary()) -> ok.
delete_all_user_tokens(AuthMod, UserId, Context) ->
    #{repo := Repo, token_schema := TokenSchema} = nova_auth:config(AuthMod),
    Q = kura_query:where(
        kura_query:where(kura_query:from(TokenSchema), {user_id, UserId}),
        {context, Context}
    ),
    kura_repo_worker:delete_all(Repo, Q),
    ok.
