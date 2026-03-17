-module(nova_auth_accounts).
-moduledoc ~"""
User account operations: authentication, registration, password changes,
and identity changes. Uses dummy verification on failed lookups to prevent
timing-based user enumeration.
""".

-include_lib("kura/include/kura.hrl").

-export([
    authenticate/3,
    register/3,
    change_password/4,
    change_identity/4,
    get_user_by_id/2
]).

-doc "Authenticate a user by identity and password.".
-spec authenticate(module(), binary(), binary()) -> {ok, map()} | {error, invalid_credentials}.
authenticate(AuthMod, Identity, Password) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, user_schema := UserSchema} = Cfg,
    IdentityField = maps:get(user_identity_field, Cfg),
    PasswordField = maps:get(user_password_field, Cfg),
    Algorithm = maps:get(hash_algorithm, Cfg),
    Q = kura_query:where(kura_query:from(UserSchema), {IdentityField, Identity}),
    case kura_repo_worker:all(Repo, Q) of
        {ok, [User]} ->
            HashedPassword = maps:get(PasswordField, User),
            case nova_auth_password:verify(Password, HashedPassword) of
                true -> {ok, User};
                false -> {error, invalid_credentials}
            end;
        _ ->
            nova_auth_password:dummy_verify(Algorithm),
            {error, invalid_credentials}
    end.

-doc "Register a new user using the provided changeset function and params.".
-spec register(module(), fun((map(), map()) -> #kura_changeset{}), map()) ->
    {ok, map()} | {error, #kura_changeset{}}.
register(AuthMod, ChangesetFun, Params) ->
    #{repo := Repo} = nova_auth:config(AuthMod),
    CS = ChangesetFun(#{}, Params),
    kura_repo_worker:insert(Repo, CS).

-doc "Change a user's password after verifying the current password. Invalidates all tokens.".
-spec change_password(module(), map(), binary(), map()) ->
    {ok, map()} | {error, invalid_password} | {error, #kura_changeset{}}.
change_password(AuthMod, User, CurrentPassword, NewParams) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, user_schema := UserSchema} = Cfg,
    PasswordField = maps:get(user_password_field, Cfg),
    HashedPassword = maps:get(PasswordField, User),
    case nova_auth_password:verify(CurrentPassword, HashedPassword) of
        true ->
            CS = apply_password_changeset(UserSchema, User, NewParams),
            case kura_repo_worker:update(Repo, CS) of
                {ok, UpdatedUser} ->
                    nova_auth_session:delete_all_user_tokens(AuthMod, maps:get(id, User)),
                    {ok, UpdatedUser};
                {error, _} = Err ->
                    Err
            end;
        false ->
            {error, invalid_password}
    end.

-doc "Change a user's identity (e.g. email) after verifying the current password. Invalidates all tokens.".
-spec change_identity(module(), map(), binary(), map()) ->
    {ok, map()} | {error, invalid_password} | {error, #kura_changeset{}}.
change_identity(AuthMod, User, CurrentPassword, NewParams) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, user_schema := UserSchema} = Cfg,
    PasswordField = maps:get(user_password_field, Cfg),
    HashedPassword = maps:get(PasswordField, User),
    case nova_auth_password:verify(CurrentPassword, HashedPassword) of
        true ->
            CS = apply_identity_changeset(UserSchema, User, NewParams),
            case kura_repo_worker:update(Repo, CS) of
                {ok, UpdatedUser} ->
                    nova_auth_session:delete_all_user_tokens(AuthMod, maps:get(id, User)),
                    {ok, UpdatedUser};
                {error, _} = Err ->
                    Err
            end;
        false ->
            {error, invalid_password}
    end.

-doc "Fetch a user by their primary key.".
-spec get_user_by_id(module(), term()) -> {ok, map()} | {error, not_found} | {error, term()}.
get_user_by_id(AuthMod, UserId) ->
    #{repo := Repo, user_schema := UserSchema} = nova_auth:config(AuthMod),
    kura_repo_worker:get(Repo, UserSchema, UserId).

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

apply_password_changeset(UserSchema, User, Params) ->
    case erlang:function_exported(UserSchema, password_changeset, 2) of
        true -> UserSchema:password_changeset(User, Params);
        false -> kura_changeset:cast(UserSchema, User, Params, [password, password_confirmation])
    end.

apply_identity_changeset(UserSchema, User, Params) ->
    case erlang:function_exported(UserSchema, email_changeset, 2) of
        true -> UserSchema:email_changeset(User, Params);
        false -> kura_changeset:cast(UserSchema, User, Params, [email])
    end.
