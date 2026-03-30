-module(nova_auth_oidc_jwt).
-moduledoc ~"""
Validates OIDC ID tokens (JWTs) against provider configuration.

Extracts and validates the payload from a JWT, maps claims using
the configured claims mapping, and returns an actor map.
""".

-export([validate_token/3]).

-doc ~"""
Validate an OIDC ID token for the given provider.

Decodes the JWT payload, verifies basic structure, and maps claims
according to the OIDC configuration module's `claims_mapping`.

Returns `{ok, Actor}` with mapped claims or `{error, Reason}`.
""".
-spec validate_token(module(), atom(), binary()) ->
    {ok, nova_auth:actor()} | {error, term()}.
validate_token(ConfigMod, Provider, Token) ->
    Config = ConfigMod:config(),
    Providers = maps:get(providers, Config, #{}),
    case maps:find(Provider, Providers) of
        {ok, _ProviderConfig} ->
            case decode_jwt_payload(Token) of
                {ok, Claims} ->
                    Mapping = maps:get(claims_mapping, Config, #{}),
                    Actor = nova_auth_claims:map(Mapping, Claims, #{provider => Provider}),
                    {ok, #{
                        id => maps:get(provider_uid, Actor, maps:get(~"sub", Claims, undefined)),
                        claims => Actor
                    }};
                {error, Reason} ->
                    {error, Reason}
            end;
        error ->
            {error, unknown_provider}
    end.

%% Decode the payload section of a JWT (base64url-encoded JSON).
-spec decode_jwt_payload(binary()) -> {ok, map()} | {error, term()}.
decode_jwt_payload(Token) ->
    case binary:split(Token, ~".", [global]) of
        [_, PayloadB64, _] ->
            try
                Decoded = base64:decode(PayloadB64, #{mode => urlsafe, padding => false}),
                {ok, json:decode(Decoded)}
            catch
                _:_ -> {error, invalid_jwt}
            end;
        _ ->
            {error, invalid_jwt_format}
    end.
