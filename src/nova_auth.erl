-module(nova_auth).
-moduledoc ~"""
Behaviour for nova_auth configuration. Implementing modules define
authentication settings (repo, schemas, token lifetimes). Configuration
is cached in persistent_term for fast repeated access.

Password-related keys (`repo`, `user_schema`, `token_schema`) are only
required when using password authentication modules (nova_auth_accounts,
nova_auth_session, etc.). OIDC-only applications can omit them entirely.
""".

-include("../include/nova_auth.hrl").

%% Config defaults used only here (kept local rather than in the shared header).
-define(NOVA_AUTH_DEFAULT_ACCESS_VALIDITY_MINUTES, 60).
-define(NOVA_AUTH_DEFAULT_REFRESH_VALIDITY_DAYS, 30).

-export([config/1, config/2, invalidate_cache/1]).

-export_type([actor/0]).

-type actor() :: #{
    id := binary() | integer(),
    provider := atom(),
    atom() => term()
}.

-callback config() ->
    #{
        repo => module(),
        user_schema => module(),
        token_schema => module(),
        user_identity_field => atom(),
        user_password_field => atom(),
        session_validity_days => pos_integer(),
        confirm_validity_days => pos_integer(),
        reset_validity_hours => pos_integer(),
        hash_algorithm => pbkdf2_sha256 | bcrypt | argon2,
        token_bytes => pos_integer()
    }.

-doc "Return the merged auth configuration for `Mod`, caching in persistent_term.".
-spec config(module()) -> map().
config(Mod) ->
    case persistent_term:get({nova_auth, Mod}, undefined) of
        undefined ->
            Cfg = Mod:config(),
            Defaults = #{
                user_identity_field => email,
                user_password_field => hashed_password,
                session_validity_days => ?NOVA_AUTH_DEFAULT_SESSION_VALIDITY_DAYS,
                access_token_validity_minutes => ?NOVA_AUTH_DEFAULT_ACCESS_VALIDITY_MINUTES,
                refresh_token_validity_days => ?NOVA_AUTH_DEFAULT_REFRESH_VALIDITY_DAYS,
                confirm_validity_days => 3,
                reset_validity_hours => 1,
                hash_algorithm => pbkdf2_sha256,
                token_bytes => ?NOVA_AUTH_DEFAULT_TOKEN_BYTES
            },
            Merged = maps:merge(Defaults, Cfg),
            persistent_term:put({nova_auth, Mod}, Merged),
            Merged;
        Cfg ->
            Cfg
    end.

-doc "Return a single config value for `Key` from the auth module `Mod`.".
-spec config(module(), atom()) -> term().
config(Mod, Key) ->
    maps:get(Key, config(Mod)).

-doc "Evict the cached configuration for `Mod` from persistent_term.".
-spec invalidate_cache(module()) -> true.
invalidate_cache(Mod) ->
    persistent_term:erase({nova_auth, Mod}).
