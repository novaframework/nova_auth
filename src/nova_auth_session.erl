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
    delete_all_user_tokens/3,
    purge_expired_tokens/1
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
    case nova_auth_token:lookup_hash(SessionToken) of
        {error, invalid_token} ->
            {error, not_found};
        {ok, HashedToken} ->
            try
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
            end
    end.

-doc "Delete a specific session token (logout).".
-spec delete_session_token(module(), binary()) -> ok.
delete_session_token(AuthMod, SessionToken) ->
    #{repo := Repo, token_schema := TokenSchema} = nova_auth:config(AuthMod),
    case nova_auth_token:lookup_hash(SessionToken) of
        {error, invalid_token} ->
            ok;
        {ok, HashedToken} ->
            try
                Q = kura_query:where(
                    kura_query:where(kura_query:from(TokenSchema), {token, HashedToken}),
                    {context, <<"session">>}
                ),
                _ = kura_repo_worker:delete_all(Repo, Q),
                ok
            catch
                _:_ -> ok
            end
    end.

-doc "Delete all tokens for a user across all contexts.".
-spec delete_all_user_tokens(module(), term()) -> ok.
delete_all_user_tokens(AuthMod, UserId) ->
    #{repo := Repo, token_schema := TokenSchema} = nova_auth:config(AuthMod),
    Q = kura_query:where(kura_query:from(TokenSchema), {user_id, UserId}),
    nova_auth_refresh:delete_user_tokens(Repo, UserId, Q).

-doc "Delete all tokens for a user within a specific context.".
-spec delete_all_user_tokens(module(), term(), binary()) -> ok.
delete_all_user_tokens(AuthMod, UserId, Context) ->
    #{repo := Repo, token_schema := TokenSchema} = nova_auth:config(AuthMod),
    Q = kura_query:where(
        kura_query:where(kura_query:from(TokenSchema), {user_id, UserId}),
        {context, Context}
    ),
    _ = kura_repo_worker:delete_all(Repo, Q),
    ok.

-doc """
Delete every expired token of the auth module `AuthMod` from its token table.

Covers session, confirm, reset, access and refresh tokens, each against its
own validity setting (`session_validity_days`, `confirm_validity_days`,
`reset_validity_hours`, `access_token_validity_minutes`,
`refresh_token_validity_days`), in one parameterised `DELETE`. Returns the
number of rows deleted. Tokens of any other context are left alone.

Expired tokens already fail validation; purging only keeps the table small.
Run it periodically, for example from a scheduled job.
""".
-spec purge_expired_tokens(module()) -> {ok, non_neg_integer()} | {error, term()}.
purge_expired_tokens(AuthMod) ->
    #{repo := Repo, token_schema := TokenSchema} = Cfg = nova_auth:config(AuthMod),
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    Expired = [
        {'and', [{context, Context}, {inserted_at, '<', cutoff(Now, Seconds)}]}
     || {Context, Seconds} <- validity_seconds(Cfg)
    ],
    Q = kura_query:where(kura_query:from(TokenSchema), {'or', Expired}),
    kura_repo_worker:delete_all(Repo, Q).

validity_seconds(Cfg) ->
    #{
        session_validity_days := SessionDays,
        confirm_validity_days := ConfirmDays,
        reset_validity_hours := ResetHours,
        access_token_validity_minutes := AccessMinutes,
        refresh_token_validity_days := RefreshDays
    } = Cfg,
    [
        {~"session", SessionDays * 86400},
        {~"confirm", ConfirmDays * 86400},
        {~"reset", ResetHours * 3600},
        {~"access", AccessMinutes * 60},
        {~"refresh", RefreshDays * 86400}
    ].

cutoff(Now, Seconds) ->
    calendar:gregorian_seconds_to_datetime(Now - Seconds).
