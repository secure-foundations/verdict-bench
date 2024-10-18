% A meta-interpreter for Prolog that outputs a Hilbert-style proof trace.
% To use, run the desired goal with `prove(Goal)`.

:- nb_setval(proof_id, 0).

gen_id(Id) :-
    nb_getval(proof_id, Id),
    NewId is Id + 1,
    nb_setval(proof_id, NewId).

% log_term(Term) :-
%     % Using this seems to prevent variable names _XXX to be changed due to GC
%     numbervars(Term, 0, _, [singletons(true)]),
%     write_term(Term, [quoted(true), numbervars(false)]).

% Log a proof step
log_proof(Id, Goal) :-
    gen_id(Id),
    write(Id), write(". "),
    % TODO: ignore_ops(true) will produce things like ==(...)
    write_term(Goal, [ignore_ops(true), quoted(true), numbervars(true)]),
    % write_canonical(Goal),
    % log_term(Goal),
    write(" by ").

% Helper function for prove(maplist(...), ...)
% prove_map(Fn, X, Y) :-
%     % Construct a new term Fn(X, Y)
%     Term =.. [Fn, X, Y],
%     prove(Term).

% prove(Goal, Id) tries to prove Goal and if success,
% the proof that Goal is true is associated with node Id
prove(true, Id) :- !,
    log_proof(Id, true),
    writeln("true").

prove((A, B), Id) :- !,
    prove(A, Id1),
    prove(B, Id2),
    log_proof(Id, (A, B)),
    write("and("), write(Id1), write(", "), write(Id2), writeln(")").

prove((A; B), Id) :- !,
    (prove(A, Id1), log_proof(Id, (A;B)), write("or-left("), write(Id1), writeln(")");
     prove(B, Id2), log_proof(Id, (A;B)), write("or-right("), write(Id2), writeln(")")).

% Special case for maplist
prove(maplist(Fn, List, Results), Id) :-
    !,
    % maplist(prove_map(Fn), List, Results),
    maplist(Fn, List, Results),
    log_proof(Id, maplist(Fn, List, Results)),
    writeln("built-in").

% Special case for include
prove(include(Fn, List, Results), Id) :-
    !,
    include(Fn, List, Results),
    log_proof(Id, include(Fn, List, Results)),
    writeln("built-in").

% Special case for forall(member(...), ...)
prove(forall(member(X, L), Goal), Id) :-
    !,
    % First prove the forall goal
    forall(member(X, L), Goal),
    % If successful, rerun all goals to gather proofs
    findall(Id, (member(X, L), once(prove(Goal, Id))), Ids),

    % Ids should have the same length as L, as a sanity check
    % length(Ids, N),
    % length(L, M),
    % N == M,

    log_proof(Id, forall(member(X, L), Goal)),
    write("forall-member("), write(Ids), writeln(")").

% Special case for forall(...)
prove(forall(Cond, Goal), Id) :-
    !,
    forall(Cond, Goal),
    % If successful, rerun all goals to gather proofs
    % NOTE: Here for each goal we only prove once since
    % there is an edge case where the goal can have
    % multiple solutions
    findall(Id, (Cond, once(prove(Goal, Id))), Ids),
    log_proof(Id, forall(Cond, Goal)),
    write("forall-base("), write(Ids), writeln(")").

% Builtin predicates
prove(Goal, Id) :-
    % predicate_property(Goal, P),
    % write(Goal), write(", "), writeln(P),
    (
        predicate_property(Goal, built_in);

        % TODO: rule out all libraries in https://www.swi-prolog.org/pldoc/man?section=libpl
        predicate_property(Goal, imported_from(lists));
        predicate_property(Goal, imported_from(strings));
        predicate_property(Goal, imported_from(url));
        predicate_property(Goal, imported_from(uri))
    ),
    !,
    Goal,
    log_proof(Id, Goal),
    writeln("built-in").

% Otherwise we try user-defined rule application
prove(Goal, Id) :-
    clause(Goal, Body, Ref),
    clause_property(Ref, line_count(Line)),
    clause_property(Ref, file(File)),

    (   clause_property(Ref, fact)

    ->  % If it's a fact, simplify the tactic and just use the "fact" tactic
        % (otherwise it might generate a new "true" tactic)
        log_proof(Id, Goal),
        write("fact("),
        write("\""), write(File), write("\":"),
        write(Line),
        writeln(")")

    ;   % Otherwise, apply the body
        prove(Body, BodyId),
        log_proof(Id, Goal),
        write("apply("), write(BodyId), write(", "),
        write("\""), write(File), write("\":"),
        write(Line),
        writeln(")")
    ).

prove(Goal) :-
    prove(Goal, _).
