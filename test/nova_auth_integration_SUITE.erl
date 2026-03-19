-module(nova_auth_integration_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").
-include_lib("kura/include/kura.hrl").

-export([
    all/0,
    init_per_suite/1,
    end_per_suite/1
]).
-export([
    test_register_and_login/1,
    test_login_wrong_password/1,
    test_login_nonexistent_user/1,
    test_session_token_flow/1,
    test_change_password/1,
    test_change_password_wrong_current/1,
    test_confirm_token_flow/1,
    test_reset_token_flow/1
]).

all() ->
    [
        test_register_and_login,
        test_login_wrong_password,
        test_login_nonexistent_user,
        test_session_token_flow,
        test_change_password,
        test_change_password_wrong_current,
        test_confirm_token_flow,
        test_reset_token_flow
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(telemetry),
    {ok, _} = application:ensure_all_started(pgo),
    ok = test_auth_repo:start(),
    setup_tables(),
    Config.

end_per_suite(_Config) ->
    teardown_tables(),
    ok.

%%----------------------------------------------------------------------
%% Tests
%%----------------------------------------------------------------------

test_register_and_login(_Config) ->
    cleanup_users(),
    Params = #{
        email => <<"test@example.com">>,
        password => <<"password123456">>,
        password_confirmation => <<"password123456">>
    },
    {ok, User} = nova_auth_accounts:register(
        test_auth_config, fun test_auth_user:registration_changeset/2, Params
    ),
    ?assertMatch(#{email := <<"test@example.com">>}, User),

    {ok, AuthUser} = nova_auth_accounts:authenticate(
        test_auth_config, <<"test@example.com">>, <<"password123456">>
    ),
    ?assertEqual(maps:get(id, User), maps:get(id, AuthUser)).

test_login_wrong_password(_Config) ->
    cleanup_users(),
    register_user(<<"wrong@example.com">>, <<"password123456">>),
    ?assertEqual(
        {error, invalid_credentials},
        nova_auth_accounts:authenticate(
            test_auth_config, <<"wrong@example.com">>, <<"badpassword1">>
        )
    ).

test_login_nonexistent_user(_Config) ->
    ?assertEqual(
        {error, invalid_credentials},
        nova_auth_accounts:authenticate(
            test_auth_config, <<"nobody@example.com">>, <<"password123456">>
        )
    ).

test_session_token_flow(_Config) ->
    cleanup_users(),
    {ok, User} = register_user(<<"session@example.com">>, <<"password123456">>),
    {ok, Token} = nova_auth_session:generate_session_token(test_auth_config, User),
    ?assert(is_binary(Token)),

    {ok, Found} = nova_auth_session:get_user_by_session_token(test_auth_config, Token),
    ?assertEqual(maps:get(id, User), maps:get(id, Found)),

    ok = nova_auth_session:delete_session_token(test_auth_config, Token),
    ?assertMatch(
        {error, _},
        nova_auth_session:get_user_by_session_token(test_auth_config, Token)
    ).

test_change_password(_Config) ->
    cleanup_users(),
    {ok, User} = register_user(<<"pwchange@example.com">>, <<"password123456">>),
    NewParams = #{
        password => <<"newpassword12345">>,
        password_confirmation => <<"newpassword12345">>
    },
    {ok, _Updated} = nova_auth_accounts:change_password(
        test_auth_config, User, <<"password123456">>, NewParams
    ),
    {ok, _} = nova_auth_accounts:authenticate(
        test_auth_config, <<"pwchange@example.com">>, <<"newpassword12345">>
    ).

test_change_password_wrong_current(_Config) ->
    cleanup_users(),
    {ok, User} = register_user(<<"pwfail@example.com">>, <<"password123456">>),
    ?assertEqual(
        {error, invalid_password},
        nova_auth_accounts:change_password(
            test_auth_config, User, <<"wrongcurrent12">>, #{
                password => <<"newpass1234567">>,
                password_confirmation => <<"newpass1234567">>
            }
        )
    ).

test_confirm_token_flow(_Config) ->
    cleanup_users(),
    {ok, User} = register_user(<<"confirm@example.com">>, <<"password123456">>),
    {ok, Token} = nova_auth_confirm:generate_confirm_token(test_auth_config, User),
    ?assert(is_binary(Token)),
    {ok, Confirmed} = nova_auth_confirm:confirm_user(test_auth_config, Token),
    ?assertNotEqual(undefined, maps:get(confirmed_at, Confirmed, undefined)).

test_reset_token_flow(_Config) ->
    cleanup_users(),
    {ok, User} = register_user(<<"reset@example.com">>, <<"password123456">>),
    {ok, Token} = nova_auth_reset:generate_reset_token(test_auth_config, User),
    ?assert(is_binary(Token)),
    {ok, _Reset} = nova_auth_reset:reset_password(test_auth_config, Token, #{
        password => <<"resetpass12345">>,
        password_confirmation => <<"resetpass12345">>
    }),
    {ok, _} = nova_auth_accounts:authenticate(
        test_auth_config, <<"reset@example.com">>, <<"resetpass12345">>
    ).

%%----------------------------------------------------------------------
%% Helpers
%%----------------------------------------------------------------------

register_user(Email, Password) ->
    nova_auth_accounts:register(
        test_auth_config, fun test_auth_user:registration_changeset/2, #{
            email => Email,
            password => Password,
            password_confirmation => Password
        }
    ).

cleanup_users() ->
    kura_repo_worker:pgo_query(test_auth_repo, <<"DELETE FROM user_tokens">>, []),
    kura_repo_worker:pgo_query(test_auth_repo, <<"DELETE FROM users">>, []),
    ok.

setup_tables() ->
    kura_repo_worker:pgo_query(test_auth_repo, <<"CREATE EXTENSION IF NOT EXISTS citext">>, []),
    kura_repo_worker:pgo_query(
        test_auth_repo,
        <<
            "\n"
            "        CREATE TABLE IF NOT EXISTS users (\n"
            "            id BIGSERIAL PRIMARY KEY,\n"
            "            email TEXT NOT NULL,\n"
            "            hashed_password TEXT NOT NULL,\n"
            "            confirmed_at TIMESTAMPTZ,\n"
            "            inserted_at TIMESTAMPTZ,\n"
            "            updated_at TIMESTAMPTZ\n"
            "        )\n"
            "    "
        >>,
        []
    ),
    kura_repo_worker:pgo_query(
        test_auth_repo,
        <<
            "\n"
            "        CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users (email)\n"
            "    "
        >>,
        []
    ),
    kura_repo_worker:pgo_query(
        test_auth_repo,
        <<
            "\n"
            "        CREATE TABLE IF NOT EXISTS user_tokens (\n"
            "            id BIGSERIAL PRIMARY KEY,\n"
            "            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,\n"
            "            token TEXT NOT NULL,\n"
            "            context TEXT NOT NULL,\n"
            "            inserted_at TIMESTAMPTZ\n"
            "        )\n"
            "    "
        >>,
        []
    ),
    kura_repo_worker:pgo_query(
        test_auth_repo,
        <<
            "\n"
            "        CREATE UNIQUE INDEX IF NOT EXISTS user_tokens_ctx_token_idx\n"
            "        ON user_tokens (context, token)\n"
            "    "
        >>,
        []
    ),
    ok.

teardown_tables() ->
    kura_repo_worker:pgo_query(test_auth_repo, <<"DROP TABLE IF EXISTS user_tokens">>, []),
    kura_repo_worker:pgo_query(test_auth_repo, <<"DROP TABLE IF EXISTS users">>, []),
    ok.
