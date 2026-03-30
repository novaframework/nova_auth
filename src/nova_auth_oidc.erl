-module(nova_auth_oidc).
-moduledoc ~"""
Behaviour for OIDC provider configuration. Implementing modules define
provider endpoints, client credentials, scopes, and claims mapping.

Example:
```
-module(my_oidc_config).
-behaviour(nova_auth_oidc).
-export([config/0]).

config() ->
    #{
        providers => #{
            google => #{
                client_id => os:getenv("GOOGLE_CLIENT_ID"),
                client_secret => os:getenv("GOOGLE_CLIENT_SECRET"),
                discovery_url => ~"https://accounts.google.com/.well-known/openid-configuration"
            }
        },
        scopes => [~"openid", ~"profile", ~"email"],
        claims_mapping => #{
            ~"sub" => provider_uid,
            ~"email" => provider_email,
            ~"name" => provider_display_name
        }
    }.
```
""".

-export_type([oidc_config/0, provider_config/0]).

-type provider_config() :: #{
    client_id := binary() | string(),
    client_secret := binary() | string(),
    discovery_url => binary(),
    authorize_url => binary(),
    token_url => binary(),
    userinfo_url => binary(),
    jwks_uri => binary()
}.

-type oidc_config() :: #{
    providers := #{atom() => provider_config()},
    base_url => binary(),
    auth_path_prefix => binary(),
    scopes => [binary()],
    claims_mapping => #{binary() => atom()} | {module(), atom()},
    on_success => {redirect, binary()} | {status, pos_integer()},
    on_failure => {redirect, binary()} | {status, pos_integer()}
}.

-callback config() -> oidc_config().
