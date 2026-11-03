-module(test_auth_user_plain).
-behaviour(kura_schema).
-include_lib("kura/include/kura.hrl").

-export([table/0, fields/0]).

table() -> <<"users">>.

fields() ->
    [
        #kura_field{name = id, type = id, primary_key = true, nullable = false},
        #kura_field{name = email, type = string, nullable = false},
        #kura_field{name = hashed_password, type = string, nullable = false},
        #kura_field{name = confirmed_at, type = utc_datetime},
        #kura_field{name = inserted_at, type = utc_datetime},
        #kura_field{name = updated_at, type = utc_datetime}
    ].
