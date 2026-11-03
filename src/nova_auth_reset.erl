-module(nova_auth_reset).
-moduledoc ~"""
Password reset token management. Generates time-limited reset tokens and
handles the reset flow, invalidating all existing tokens on success.
""".

-include_lib("kura/include/kura.hrl").

-export([
    generate_reset_token/2,
    reset_password/3
]).

-doc "Generate and store a password reset token for a user. Returns the raw token.".
-spec generate_reset_token(module(), map()) -> {ok, binary()} | {error, term()}.
generate_reset_token(AuthMod, User) ->
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
            context => <<"reset">>,
            inserted_at => Now
        },
        [user_id, token, context, inserted_at]
    ),
    case kura_repo_worker:insert(Repo, CS) of
        {ok, _} -> {ok, RawToken};
        {error, _} = Err -> Err
    end.

-doc """
Reset a user's password using a raw reset token. Invalidates all tokens on success.

The reset token is single-use: it is claimed (deleted) in the same
transaction as the password update, so of several concurrent resets with one
token exactly one succeeds and the others get `{error, not_found}`. If the
password update fails (for example a changeset error), the transaction rolls
back and the token stays valid. Password keys are removed from an error
changeset as in `nova_auth_accounts:register/2`.

Actors already stored in other sessions with `nova_auth_actor` are not
removed; see the Actor Session guide for ending those sessions too.
""".
-spec reset_password(module(), binary(), map()) -> {ok, map()} | {error, term()}.
reset_password(AuthMod, Token, NewParams) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, token_schema := TokenSchema} = Cfg,
    ResetHours = maps:get(reset_validity_hours, Cfg),
    case nova_auth_token:lookup_hash(Token) of
        {error, invalid_token} ->
            {error, not_found};
        {ok, HashedToken} ->
            try
                Q = kura_query:where(
                    kura_query:where(kura_query:from(TokenSchema), {token, HashedToken}),
                    {context, <<"reset">>}
                ),
                case kura_repo_worker:all(Repo, Q) of
                    {ok, [TokenRecord]} ->
                        case token_valid_hours(maps:get(inserted_at, TokenRecord), ResetHours) of
                            true -> redeem(AuthMod, Cfg, TokenRecord, NewParams);
                            false -> {error, token_expired}
                        end;
                    _ ->
                        {error, not_found}
                end
            catch
                _:_ -> {error, invalid_token}
            end
    end.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

redeem(AuthMod, Cfg, TokenRecord, NewParams) ->
    #{repo := Repo, token_schema := TokenSchema, user_schema := UserSchema} = Cfg,
    UserId = maps:get(user_id, TokenRecord),
    Claim = kura_query:where(kura_query:from(TokenSchema), {id, maps:get(id, TokenRecord)}),
    Update = fun() ->
        case kura_repo_worker:delete_all(Repo, Claim) of
            {ok, 1} -> update_password(Repo, UserSchema, UserId, NewParams);
            {ok, _} -> throw({?MODULE, rollback, not_found});
            {error, Reason} -> throw({?MODULE, rollback, Reason})
        end
    end,
    try kura_repo_worker:transaction(Repo, Update) of
        {ok, UpdatedUser} ->
            nova_auth_session:delete_all_user_tokens(AuthMod, UserId),
            {ok, UpdatedUser};
        {error, _} = Err ->
            Err
    catch
        throw:{?MODULE, rollback, #kura_changeset{} = CS} ->
            {error, nova_auth_accounts:scrub_passwords(CS)};
        throw:{?MODULE, rollback, Reason} ->
            {error, Reason}
    end.

update_password(Repo, UserSchema, UserId, NewParams) ->
    case kura_repo_worker:get(Repo, UserSchema, UserId) of
        {ok, User} ->
            CS = apply_password_changeset(UserSchema, User, NewParams),
            case kura_repo_worker:update(Repo, CS) of
                {ok, UpdatedUser} -> {ok, UpdatedUser};
                {error, Reason} -> throw({?MODULE, rollback, Reason})
            end;
        {error, Reason} ->
            throw({?MODULE, rollback, Reason})
    end.

apply_password_changeset(UserSchema, User, Params) ->
    case erlang:function_exported(UserSchema, password_changeset, 2) of
        true -> UserSchema:password_changeset(User, Params);
        false -> kura_changeset:cast(UserSchema, User, Params, [password, password_confirmation])
    end.

token_valid_hours(InsertedAt, ValidityHours) ->
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    TokenTime = calendar:datetime_to_gregorian_seconds(InsertedAt),
    (Now - TokenTime) < (ValidityHours * 60 * 60).
