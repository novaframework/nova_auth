-module(nova_auth_refresh).
-moduledoc ~"""
Short-lived access tokens paired with rotating refresh tokens.

`generate_pair/2` issues an access token (validated for
`access_token_validity_minutes`) and a refresh token (valid for
`refresh_token_validity_days`). The refresh token is single-use: `refresh/2`
rotates it, marking the old one used and issuing a fresh access+refresh pair
in the same `family_id`. Presenting an already-used refresh token is treated
as theft: the whole family is revoked (`reuse_detected`). The token is claimed
with a conditional update, so of several concurrent refreshes of one token
exactly one gets a new pair and the others get `reuse_detected`.

Requires the configured `token_schema` to have `family_id` (string) and
`used_at` (utc_datetime) fields in addition to the session-token fields,
and the table needs an index on `family_id`: `revoke_family/2` and reuse
detection delete by it, which is a full table scan without one.
Tokens are stored hashed via `nova_auth_token`.
""".

-include_lib("kura/include/kura.hrl").

-export([
    generate_pair/2,
    get_user_by_access_token/2,
    refresh/2,
    revoke_family/2,
    revoke_all/2,
    delete_access_token/2
]).

-define(ACCESS, <<"access">>).
-define(REFRESH, <<"refresh">>).

-type tokens() :: #{access_token := binary(), refresh_token := binary()}.

-doc "Issue a fresh access + refresh token pair for a user.".
-spec generate_pair(module(), map()) -> {ok, tokens()} | {error, term()}.
generate_pair(AuthMod, User) ->
    Cfg = nova_auth:config(AuthMod),
    UserId = maps:get(id, User),
    Family = nova_auth_token:generate(16),
    mint_pair(Cfg, UserId, Family).

-doc "Resolve the user for a raw access token, honoring the access TTL.".
-spec get_user_by_access_token(module(), binary()) -> {ok, map()} | {error, term()}.
get_user_by_access_token(AuthMod, Access) when is_binary(Access) ->
    #{
        repo := Repo,
        token_schema := Schema,
        user_schema := UserSchema,
        access_token_validity_minutes := Mins
    } = nova_auth:config(AuthMod),
    try
        case one_by_token(Repo, Schema, Access, ?ACCESS) of
            {ok, Row} ->
                case within(maps:get(inserted_at, Row), Mins * 60) of
                    true -> kura_repo_worker:get(Repo, UserSchema, maps:get(user_id, Row));
                    false -> {error, token_expired}
                end;
            none ->
                {error, not_found}
        end
    catch
        _:_ -> {error, invalid_token}
    end;
get_user_by_access_token(_AuthMod, _Access) ->
    {error, invalid_token}.

-doc """
Rotate a refresh token: on success returns a new access+refresh pair and marks
the presented one used. A reused (already-rotated) token revokes the family.
""".
-spec refresh(module(), binary()) -> {ok, tokens()} | {error, term()}.
refresh(AuthMod, RawRefresh) when is_binary(RawRefresh) ->
    Cfg = nova_auth:config(AuthMod),
    #{repo := Repo, token_schema := Schema, refresh_token_validity_days := Days} = Cfg,
    try
        case one_by_token(Repo, Schema, RawRefresh, ?REFRESH) of
            {ok, Row} -> handle_row(Cfg, Row, Days);
            none -> {error, invalid_refresh}
        end
    catch
        _:_ -> {error, invalid_refresh}
    end;
refresh(_AuthMod, _RawRefresh) ->
    {error, invalid_refresh}.

-doc "Revoke the refresh-token family that a raw refresh token belongs to.".
-spec revoke_family(module(), binary()) -> ok.
revoke_family(AuthMod, RawRefresh) when is_binary(RawRefresh) ->
    #{repo := Repo, token_schema := Schema} = Cfg = nova_auth:config(AuthMod),
    case one_by_token(Repo, Schema, RawRefresh, ?REFRESH) of
        {ok, Row} -> revoke_family_id(Cfg, maps:get(family_id, Row, undefined));
        none -> ok
    end;
revoke_family(_AuthMod, _RawRefresh) ->
    ok.

-doc "Revoke ALL tokens for a user (e.g. on ban or global logout).".
-spec revoke_all(module(), term()) -> ok.
revoke_all(AuthMod, UserId) ->
    #{repo := Repo, token_schema := Schema} = nova_auth:config(AuthMod),
    Q = kura_query:where(kura_query:from(Schema), {user_id, UserId}),
    _ = kura_repo_worker:delete_all(Repo, Q),
    ok.

-doc "Delete a single access token (logout of one device).".
-spec delete_access_token(module(), binary()) -> ok.
delete_access_token(AuthMod, Access) when is_binary(Access) ->
    #{repo := Repo, token_schema := Schema} = nova_auth:config(AuthMod),
    case nova_auth_token:lookup_hash(Access) of
        {ok, Hash} ->
            _ = kura_repo_worker:delete_all(Repo, q_by_token(Schema, Hash, ?ACCESS)),
            ok;
        {error, invalid_token} ->
            ok
    end;
delete_access_token(_AuthMod, _Access) ->
    ok.

%% --- Internal ---

-spec handle_row(map(), map(), pos_integer()) -> {ok, tokens()} | {error, term()}.
handle_row(Cfg, Row, Days) ->
    case is_used(maps:get(used_at, Row, undefined)) of
        true ->
            reuse_detected(Cfg, Row);
        false ->
            case within(maps:get(inserted_at, Row), Days * 86400) of
                false ->
                    _ = delete_by_token(Cfg, maps:get(token, Row)),
                    {error, refresh_expired};
                true ->
                    rotate(Cfg, Row)
            end
    end.

%% The conditional update is the single-use check: of concurrent refreshes
%% of one token only the one that flips used_at from NULL wins.
-spec rotate(map(), map()) -> {ok, tokens()} | {error, term()}.
rotate(#{repo := Repo, token_schema := Schema} = Cfg, Row) ->
    Claim = kura_query:where(
        kura_query:where(kura_query:from(Schema), {id, maps:get(id, Row)}),
        {used_at, is_nil}
    ),
    case kura_repo_worker:update_all(Repo, Claim, #{used_at => calendar:universal_time()}) of
        {ok, 1} ->
            mint_pair(Cfg, maps:get(user_id, Row), maps:get(family_id, Row, undefined));
        {ok, 0} ->
            reuse_detected(Cfg, Row);
        {error, _} ->
            {error, invalid_refresh}
    end.

-spec reuse_detected(map(), map()) -> {error, reuse_detected}.
reuse_detected(Cfg, Row) ->
    ok = revoke_family_id(Cfg, maps:get(family_id, Row, undefined)),
    {error, reuse_detected}.

-spec mint_pair(map(), term(), binary() | undefined) -> {ok, tokens()} | {error, term()}.
mint_pair(Cfg, UserId, Family) ->
    case insert_token(Cfg, UserId, ?ACCESS, undefined) of
        {ok, Access} ->
            case insert_token(Cfg, UserId, ?REFRESH, Family) of
                {ok, Refresh} -> {ok, #{access_token => Access, refresh_token => Refresh}};
                {error, _} = E -> E
            end;
        {error, _} = E ->
            E
    end.

-spec insert_token(map(), term(), binary(), binary() | undefined) ->
    {ok, binary()} | {error, term()}.
insert_token(
    #{repo := Repo, token_schema := Schema, token_bytes := Bytes}, UserId, Context, Family
) ->
    Raw = nova_auth_token:generate(Bytes),
    Base = #{
        user_id => UserId,
        token => nova_auth_token:hash(Raw),
        context => Context,
        inserted_at => calendar:universal_time()
    },
    Params =
        case Family of
            undefined -> Base;
            _ -> Base#{family_id => Family}
        end,
    CS = kura_changeset:cast(Schema, #{}, Params, [
        user_id, token, context, family_id, inserted_at
    ]),
    case kura_repo_worker:insert(Repo, CS) of
        {ok, _} -> {ok, Raw};
        {error, _} = E -> E
    end.

-spec one_by_token(module(), module(), binary(), binary()) -> {ok, map()} | none.
one_by_token(Repo, Schema, RawToken, Context) ->
    case nova_auth_token:lookup_hash(RawToken) of
        {ok, Hash} ->
            case kura_repo_worker:all(Repo, q_by_token(Schema, Hash, Context)) of
                {ok, [Row | _]} -> {ok, Row};
                _ -> none
            end;
        {error, invalid_token} ->
            none
    end.

-spec q_by_token(module(), binary(), binary()) -> #kura_query{}.
q_by_token(Schema, Hash, Context) ->
    kura_query:where(
        kura_query:where(kura_query:from(Schema), {token, Hash}),
        {context, Context}
    ).

-spec revoke_family_id(map(), binary() | undefined) -> ok.
revoke_family_id(_Cfg, undefined) ->
    ok;
revoke_family_id(#{repo := Repo, token_schema := Schema}, Family) ->
    Q = kura_query:where(kura_query:from(Schema), {family_id, Family}),
    _ = kura_repo_worker:delete_all(Repo, Q),
    ok.

-spec delete_by_token(map(), binary()) -> ok.
delete_by_token(#{repo := Repo, token_schema := Schema}, Token) ->
    Q = kura_query:where(kura_query:from(Schema), {token, Token}),
    _ = kura_repo_worker:delete_all(Repo, Q),
    ok.

-spec is_used(term()) -> boolean().
is_used(undefined) -> false;
is_used(nil) -> false;
is_used(null) -> false;
is_used(_) -> true.

-spec within(calendar:datetime(), non_neg_integer()) -> boolean().
within(InsertedAt, MaxSeconds) ->
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    T = calendar:datetime_to_gregorian_seconds(InsertedAt),
    (Now - T) < MaxSeconds.
