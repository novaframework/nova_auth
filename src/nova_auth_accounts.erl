-module(nova_auth_accounts).
-moduledoc ~"""
User account operations: authentication, registration, password changes,
and identity changes. Uses dummy verification on failed lookups to prevent
timing-based user enumeration.
""".

-include_lib("kura/include/kura.hrl").

-define(PASSWORD_KEYS, [password, password_confirmation, ~"password", ~"password_confirmation"]).

-export([
    authenticate/3,
    register/2,
    register/3,
    change_password/4,
    change_identity/4,
    get_user_by_id/2,
    scrub_passwords/1
]).

-doc """
Authenticate a user by identity and password.

With `require_confirmed => true` in the auth config, a user whose
`confirmed_at` is not set gets `{error, unconfirmed}` instead of
`{ok, User}`. The password is verified first either way, so the check adds
no timing difference, and `{error, unconfirmed}` is only returned for a
correct password.
""".
-spec authenticate(module(), binary(), binary()) ->
    {ok, map()} | {error, invalid_credentials | unconfirmed}.
authenticate(AuthMod, Identity, Password) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, user_schema := UserSchema} = Cfg,
    IdentityField = maps:get(user_identity_field, Cfg),
    PasswordField = maps:get(user_password_field, Cfg),
    Q = kura_query:where(kura_query:from(UserSchema), {IdentityField, Identity}),
    case kura_repo_worker:all(Repo, Q) of
        {ok, [User]} ->
            HashedPassword = maps:get(PasswordField, User),
            case nova_auth_password:verify(Password, HashedPassword) of
                true -> check_confirmed(Cfg, User);
                false -> {error, invalid_credentials}
            end;
        _ ->
            nova_auth_password:dummy_verify(),
            {error, invalid_credentials}
    end.

-doc """
Register a new user with the configured user schema's
`registration_changeset/2`.

On `{error, Changeset}` the `password` and `password_confirmation` keys
(atom and binary) are removed from the changeset's `changes` and `params`,
so the plaintext password is not carried into error replies or logs.
""".
-spec register(module(), map()) -> {ok, map()} | {error, #kura_changeset{}}.
register(AuthMod, Params) ->
    #{repo := Repo, user_schema := UserSchema} = nova_auth:config(AuthMod),
    scrub_error(kura_repo_worker:insert(Repo, UserSchema:registration_changeset(#{}, Params))).

-doc """
Register a new user using the provided changeset function and params.

Password keys are removed from an error changeset as in `register/2`.
""".
-spec register(module(), fun((map(), map()) -> #kura_changeset{}), map()) ->
    {ok, map()} | {error, #kura_changeset{}}.
register(AuthMod, ChangesetFun, Params) ->
    #{repo := Repo} = nova_auth:config(AuthMod),
    CS = ChangesetFun(#{}, Params),
    scrub_error(kura_repo_worker:insert(Repo, CS)).

-doc """
Change a user's password after verifying the current password. Invalidates all tokens.

Password keys are removed from an error changeset as in `register/2`.

Actors already stored in other sessions with `nova_auth_actor` are not
removed; see the Actor Session guide for ending those sessions too.
""".
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
                    scrub_error(Err)
            end;
        false ->
            {error, invalid_password}
    end.

-doc """
Change a user's identity (e.g. email) after verifying the current password. Invalidates all tokens.

Uses the user schema's `email_changeset/2` when it exports one, otherwise
casts only the configured `user_identity_field` and requires it. When the
identity actually changes and the schema has a `confirmed_at` field,
`confirmed_at` is cleared, so the new address has to be confirmed again.

Actors already stored in other sessions with `nova_auth_actor` are not
removed; see the Actor Session guide for ending those sessions too.
""".
-spec change_identity(module(), map(), binary(), map()) ->
    {ok, map()} | {error, invalid_password} | {error, #kura_changeset{}}.
change_identity(AuthMod, User, CurrentPassword, NewParams) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, user_schema := UserSchema} = Cfg,
    PasswordField = maps:get(user_password_field, Cfg),
    IdentityField = maps:get(user_identity_field, Cfg),
    HashedPassword = maps:get(PasswordField, User),
    case nova_auth_password:verify(CurrentPassword, HashedPassword) of
        true ->
            CS0 = apply_identity_changeset(UserSchema, User, NewParams, IdentityField),
            CS = maybe_unconfirm(UserSchema, User, IdentityField, CS0),
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

-doc false.
-spec scrub_passwords(#kura_changeset{}) -> #kura_changeset{}.
scrub_passwords(#kura_changeset{changes = Changes, params = Params} = CS) ->
    CS#kura_changeset{
        changes = maps:without(?PASSWORD_KEYS, Changes),
        params = maps:without(?PASSWORD_KEYS, Params)
    }.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

-spec scrub_error({ok, map()} | {error, #kura_changeset{}}) ->
    {ok, map()} | {error, #kura_changeset{}}.
scrub_error({error, CS}) ->
    {error, scrub_passwords(CS)};
scrub_error({ok, _} = Ok) ->
    Ok.

check_confirmed(#{require_confirmed := true}, User) ->
    case maps:get(confirmed_at, User, undefined) of
        Unset when Unset =:= undefined; Unset =:= nil; Unset =:= null -> {error, unconfirmed};
        _ -> {ok, User}
    end;
check_confirmed(_Cfg, User) ->
    {ok, User}.

apply_password_changeset(UserSchema, User, Params) ->
    case erlang:function_exported(UserSchema, password_changeset, 2) of
        true -> UserSchema:password_changeset(User, Params);
        false -> kura_changeset:cast(UserSchema, User, Params, [password, password_confirmation])
    end.

apply_identity_changeset(UserSchema, User, Params, IdentityField) ->
    case erlang:function_exported(UserSchema, email_changeset, 2) of
        true ->
            UserSchema:email_changeset(User, Params);
        false ->
            CS = kura_changeset:cast(UserSchema, User, Params, [IdentityField]),
            kura_changeset:validate_required(CS, [IdentityField])
    end.

maybe_unconfirm(UserSchema, User, IdentityField, CS) ->
    New = kura_changeset:get_change(CS, IdentityField),
    Changed = New =/= undefined andalso New =/= maps:get(IdentityField, User, undefined),
    case Changed andalso has_field(UserSchema, confirmed_at) of
        true -> kura_changeset:put_change(CS, confirmed_at, undefined);
        false -> CS
    end.

has_field(UserSchema, Name) ->
    lists:any(fun(#kura_field{name = N}) -> N =:= Name end, UserSchema:fields()).
