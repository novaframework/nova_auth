-module(test_claims_mapping).

-export([to_actor/1]).

to_actor(#{~"sub" := Sub, ~"role" := Role}) ->
    #{id => Sub, role => binary_to_atom(Role)}.
