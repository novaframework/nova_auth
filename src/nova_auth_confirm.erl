-module(nova_auth_confirm).
-moduledoc ~"""
Email confirmation token management. Generates confirmation tokens and
handles the confirmation flow by setting `confirmed_at` on the user record.
""".

-include_lib("kura/include/kura.hrl").

-export([
    generate_confirm_token/2,
    confirm_user/2
]).

-doc "Generate and store a confirmation token for a user. Returns the raw token.".
-spec generate_confirm_token(module(), map()) -> {ok, binary()} | {error, term()}.
generate_confirm_token(AuthMod, User) ->
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
            context => <<"confirm">>,
            inserted_at => Now
        },
        [user_id, token, context, inserted_at]
    ),
    case kura_repo_worker:insert(Repo, CS) of
        {ok, _} -> {ok, RawToken};
        {error, _} = Err -> Err
    end.

-doc "Confirm a user's email using a raw confirmation token.".
-spec confirm_user(module(), binary()) -> {ok, map()} | {error, term()}.
confirm_user(AuthMod, Token) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, token_schema := TokenSchema, user_schema := UserSchema} = Cfg,
    ValidityDays = maps:get(confirm_validity_days, Cfg),
    try
        HashedToken = nova_auth_token:hash(Token),
        Q = kura_query:where(
            kura_query:where(kura_query:from(TokenSchema), {token, HashedToken}),
            {context, <<"confirm">>}
        ),
        case kura_repo_worker:all(Repo, Q) of
            {ok, [TokenRecord]} ->
                case nova_auth_token:valid(maps:get(inserted_at, TokenRecord), ValidityDays) of
                    true ->
                        UserId = maps:get(user_id, TokenRecord),
                        case kura_repo_worker:get(Repo, UserSchema, UserId) of
                            {ok, User} ->
                                Now = calendar:universal_time(),
                                CS = kura_changeset:cast(
                                    UserSchema,
                                    User,
                                    #{
                                        confirmed_at => Now
                                    },
                                    [confirmed_at]
                                ),
                                case kura_repo_worker:update(Repo, CS) of
                                    {ok, UpdatedUser} ->
                                        nova_auth_session:delete_all_user_tokens(
                                            AuthMod, UserId, <<"confirm">>
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
