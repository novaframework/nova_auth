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

-doc "Reset a user's password using a raw reset token. Invalidates all tokens on success.".
-spec reset_password(module(), binary(), map()) -> {ok, map()} | {error, term()}.
reset_password(AuthMod, Token, NewParams) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, token_schema := TokenSchema, user_schema := UserSchema} = Cfg,
    ResetHours = maps:get(reset_validity_hours, Cfg),
    ValidityDays = ResetHours / 24,
    try
        HashedToken = nova_auth_token:hash(Token),
        Q = kura_query:where(
            kura_query:where(kura_query:from(TokenSchema), {token, HashedToken}),
            {context, <<"reset">>}
        ),
        case kura_repo_worker:all(Repo, Q) of
            {ok, [TokenRecord]} ->
                case nova_auth_token:valid(maps:get(inserted_at, TokenRecord), ValidityDays) of
                    true ->
                        UserId = maps:get(user_id, TokenRecord),
                        case kura_repo_worker:get(Repo, UserSchema, UserId) of
                            {ok, User} ->
                                CS = apply_password_changeset(UserSchema, User, NewParams),
                                case kura_repo_worker:update(Repo, CS) of
                                    {ok, UpdatedUser} ->
                                        nova_auth_session:delete_all_user_tokens(
                                            AuthMod, UserId
                                        ),
                                        {ok, UpdatedUser};
                                    {error, _} = Err ->
                                        Err
                                end;
                            {error, _} = Err ->
                                Err
                        end;
                    false ->
                        {error, token_expired}
                end;
            _ ->
                {error, not_found}
        end
    catch
        _:_ -> {error, invalid_token}
    end.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

apply_password_changeset(UserSchema, User, Params) ->
    case erlang:function_exported(UserSchema, password_changeset, 2) of
        true -> UserSchema:password_changeset(User, Params);
        false -> kura_changeset:cast(UserSchema, User, Params, [password, password_confirmation])
    end.
