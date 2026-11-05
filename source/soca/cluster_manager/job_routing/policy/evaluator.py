######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
The four passes that turn a policy version plus one job into a routing decision.

    defaults    fill a field the submission left unset
    overrides   replace a field whatever the submission said
    require     refuse the job
    routing     put regions, or clusters, in preference order

Within a pass, rules run in `order`, lowest first. Between passes the behaviour differs
and the difference is the point:

- defaults and overrides apply EVERY matching rule, because they describe independent
  fields and a cluster wants all of its defaults, not the first one.
- require stops at the FIRST match, because a refusal is final and evaluating further
  rules against a job that is already rejected would only lengthen the trace.
- routing stops at the first match, because the passes after it would otherwise each
  overwrite the region order the one before chose, making the LAST rule win -- the
  opposite of the `order` field's meaning.

The passes run in that sequence for one reason: a require rule and a routing rule must
see the job as it will actually be submitted. Running defaults after require would let
a rule refuse a job for missing a field the policy itself was about to fill.

FAIL-OPEN, DELIBERATELY. A rule whose predicate does not compile, or raises while being
evaluated, does not match -- and in the require pass that means the job is NOT refused.
A broken rule therefore costs a restriction rather than a user's submission. The error
is recorded against that rule in the decision's trace, which is the only place it can be
seen, because nothing else about the evaluation changes.

A policy with no routing rule, and an empty policy, both yield this cluster's own region
alone. That is the ordinary local job: routing is opt-in per rule, so a cluster that
joins a mesh and writes no policy keeps submitting locally.
"""

from __future__ import annotations

import math
import time
import uuid
from typing import Any, List, Optional

from utils.validators import Validators

from .engine import (
    CompileError,
    EvalError,
    FunctionRegistry,
    apply_action,
    compile_predicate_cached,
    evaluate as evaluate_predicate,
    evaluate_expression,
)
from .models import (
    ActionType,
    EvaluationContext,
    PolicyVersion,
    RoutingDecision,
    Rule,
    RuleTraceEntry,
)

# What a routing rule gets when it names no ceiling. A hop ceiling stops a job being
# forwarded around the mesh indefinitely; a reset ceiling stops the consumed-region list
# being cleared forever.
_DEFAULT_HOP_CEILING = 10
_DEFAULT_RESET_CEILING = 3


def evaluate(
    *,
    eval_ctx: EvaluationContext,
    policy: PolicyVersion,
    job_uuid: str,
    registry: Optional[FunctionRegistry] = None,
) -> RoutingDecision:
    """
    Run one job through a policy version.

    MUTATES `eval_ctx.job`: that is how the defaults and overrides passes take effect,
    and the mutated job is what the caller submits. A caller that needs the original
    must pass a copy -- which the Replay view does, because it answers what a rule
    would have done without changing anything.
    """
    started = time.perf_counter()
    if registry is None:
        registry = FunctionRegistry()

    decision = RoutingDecision(
        eval_id=new_eval_id(),
        job_uuid=job_uuid,
        mesh_id=policy.mesh_id,
        version_id=policy.version_id,
        accepted=True,
    )

    enabled = [rule for rule in policy.rules if rule.enabled]

    for rule in _pass(enabled, ActionType.DEFAULTS):
        if _matches(rule, eval_ctx, registry, decision):
            decision.defaults_filled.extend(_run_action(rule, eval_ctx, registry, decision))

    for rule in _pass(enabled, ActionType.OVERRIDES):
        if _matches(rule, eval_ctx, registry, decision):
            decision.overrides_applied.extend(_run_action(rule, eval_ctx, registry, decision))

    for rule in _pass(enabled, ActionType.REQUIRE):
        if _matches(rule, eval_ctx, registry, decision):
            decision.accepted = False
            decision.deny_message = _deny_message(rule, decision)
            decision.total_eval_ms = _elapsed_ms(started)
            return decision

    for rule in _pass(enabled, ActionType.ROUTING):
        if _matches(rule, eval_ctx, registry, decision):
            _apply_routing(rule, eval_ctx, registry, decision)
            break

    if not decision.region_priority and not decision.cluster_priority:
        decision.region_priority = [eval_ctx.origin_region]

    decision.total_eval_ms = _elapsed_ms(started)
    return decision


def new_eval_id() -> str:
    """
    An identifier for one evaluation, ordered by time when sorted as text.

    Millisecond epoch, zero padded to a fixed width, then random bytes to separate two
    evaluations in the same millisecond. The padding is what makes the text order match
    the time order: the prototype left the number unpadded and was sortable only by
    accident, for as long as the epoch keeps its current digit count.

    Not a KSUID despite being used where one was planned. Said plainly because a reader
    who believes it is one would expect the encoded timestamp to be recoverable at a
    fixed offset, and the separator here is a literal `-` that the random half cannot
    contain but a longer epoch would shift.
    """
    return f"{int(time.time() * 1000):016d}-{uuid.uuid4().hex[:12]}"


def _pass(rules: List[Rule], action: ActionType) -> List[Rule]:
    """The enabled rules for one action, in the order they run."""
    return sorted((rule for rule in rules if rule.action == action), key=lambda rule: rule.order)


def _matches(
    rule: Rule,
    eval_ctx: EvaluationContext,
    registry: FunctionRegistry,
    decision: RoutingDecision,
) -> bool:
    """
    Evaluate one rule's predicate, recording a trace entry either way.

    The facts are rendered fresh for every rule, not once per evaluation. Required for
    correctness rather than tidiness: the defaults pass mutates the job, so a rule whose
    predicate reads a field an earlier rule filled must see the filled value.
    """
    started = time.perf_counter()
    matched = False
    error: Optional[str] = None
    try:
        matched = evaluate_predicate(
            rule.when,
            eval_ctx.as_cel_dict(),
            registry=registry,
            pre_compiled=compile_predicate_cached(rule.when),
        )
    except (CompileError, EvalError) as failure:
        error = str(failure)

    decision.trace.append(
        RuleTraceEntry(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            action=rule.action,
            matched=bool(matched) and error is None,
            predicate_eval_ms=_elapsed_ms(started),
            error=error,
        )
    )
    return bool(matched) and error is None


def _run_action(
    rule: Rule,
    eval_ctx: EvaluationContext,
    registry: FunctionRegistry,
    decision: RoutingDecision,
) -> List[Any]:
    """Run a matched rule's action, recording a second trace entry if it raises."""
    try:
        return apply_action(rule, eval_ctx.job, eval_ctx.as_cel_dict(), registry)
    except (CompileError, EvalError) as failure:
        _trace_action_error(decision, rule, str(failure))
        return []


def _apply_routing(
    rule: Rule,
    eval_ctx: EvaluationContext,
    registry: FunctionRegistry,
    decision: RoutingDecision,
) -> None:
    """
    Read the matched routing rule's parameters into the decision.

    `cluster_priority` is read as well as `region_priority`. The prototype modelled the
    field and then never populated it, so a policy naming clusters -- the only way to
    express two clusters that share a region and bill different departments -- was
    parsed and dropped.
    """
    body = rule.then or {}
    try:
        decision.region_priority = _string_list(body.get("region_priority"), eval_ctx, registry)
        decision.cluster_priority = _string_list(body.get("cluster_priority"), eval_ctx, registry)
        decision.hop_ceiling = _positive_int(body.get("hop_ceiling"), _DEFAULT_HOP_CEILING)
        decision.reset_ceiling = _positive_int(body.get("reset_ceiling"), _DEFAULT_RESET_CEILING)
        decision.odcr_probe = _flag(body.get("odcr_probe"), "odcr_probe", True)
        decision.split_horizon = _flag(body.get("split_horizon"), "split_horizon", True)
    except (CompileError, EvalError, ValueError) as failure:
        # A routing rule whose body is malformed leaves the decision local-only, with
        # the reason in the trace. Keeping a half-read body would route the job on
        # whichever fields happened to parse before the bad one.
        #
        # ValueError is still caught although nothing here raises one any more: it
        # holds fail-open if some path below ever grows one, which is cheaper than
        # staking the guarantee on having enumerated them all.
        decision.region_priority = []
        decision.cluster_priority = []
        _trace_action_error(decision, rule, str(failure))
        return


def _deny_message(rule: Rule, decision: RoutingDecision) -> str:
    """
    The refusal an administrator sees, or this module's own when the rule's is not text.

    SUBSTITUTED rather than raised, unlike every other malformed `then` value, because
    the require pass has no handler: an EvalError here would leave `evaluate` entirely
    and the job would receive no decision at all, which is the defect this guard is
    the same class as. The refusal itself stands either way -- the predicate matched,
    and that match is the restriction the administrator wrote; only its wording is
    wrong. The stated value went straight into a field typed `str`, so a rule carrying
    a map put that map's repr in front of the user whose job was refused.
    """
    stated = (rule.then or {}).get("deny_message")
    generated = f"refused by routing rule {rule.name}"
    if stated is None or stated == "":
        return generated
    if not Validators.is_string(stated):
        _trace_action_error(
            decision, rule, f"a deny_message must be text, not {type(stated).__name__}"
        )
        return generated
    return stated


def _flag(value: Any, name: str, default: bool) -> bool:
    """
    A boolean switch from a rule body, refusing a value that only looks like one.

    `bool()` reads every non-empty string as true, so a rule saying `"false"`, `"no"`
    or `"off"` enabled the thing the administrator wrote it to disable -- silently,
    because unlike a bad ceiling nothing recorded it in the trace. The model declares
    both fields `bool`, so a genuine bool is what correct authoring produces and every
    other spelling is a mistake worth naming.
    """
    if value is None:
        return default
    if not Validators.is_bool(value):
        raise EvalError(f"{name} must be true or false, not {value!r}")
    return value


def _string_list(
    specification: Any,
    eval_ctx: EvaluationContext,
    registry: FunctionRegistry,
) -> List[str]:
    """
    Resolve a routing rule's list of regions or clusters.

    Either a literal list, or `{"expr": "<predicate>"}` whose value is a list -- the
    same marker a defaults or overrides value uses, so one convention covers every
    place a rule can carry an expression instead of a value. A bare string is a literal
    in a value position and would be a type error here, so it is refused rather than
    compiled: the prototype compiled it, which made a single region name read as code.

    The ITEMS are checked too, by `_names`, because a list of the right shape can still
    hold the wrong thing.
    """
    if specification is None:
        return []
    if isinstance(specification, (list, tuple)):
        return _names(specification, "a region or cluster list")
    if Validators.is_dict(specification) and set(specification) == {"expr"}:
        resolved = evaluate_expression(
            specification["expr"], eval_ctx.as_cel_dict(), registry=registry
        )
        if not isinstance(resolved, (list, tuple)):
            raise EvalError(
                f"an expr for a region or cluster list must yield a list, not "
                f"{type(resolved).__name__}"
            )
        return _names(resolved, "an expr for a region or cluster list")
    raise EvalError(
        f"a region or cluster list must be a list or an expr, not {type(specification).__name__}"
    )


def _names(items: Any, source: str) -> List[str]:
    """
    Every item of a region or cluster list, refusing one that is not already text.

    `str()` coerced whatever it was handed, so a list holding None became a region
    literally named "None" and one holding a map became that map's repr -- a stated
    value silently misread into something nobody wrote, with nothing in the trace. The
    orchestrator then fails to find the region, one layer away from the rule at fault.
    """
    names: List[str] = []
    for item in items:
        if not Validators.is_string(item):
            raise EvalError(
                f"{source} must hold region or cluster names, not {type(item).__name__}"
            )
        names.append(item)
    return names


def _positive_int(value: Any, default: int) -> int:
    """A ceiling from a rule body, refusing a value that would disable the ceiling."""
    if value is None:
        return default
    # Each predicate rejects a bool on its own -- is_int excludes it and is_float and
    # is_string do not match it -- so the explicit bool clause the raw form needed is
    # not repeated here.
    if Validators.is_int(value):
        # An int is read as written rather than converted. float() drops the low bit
        # above 2**53, so a ceiling of 9007199254740993 came back one lower; and it
        # raises OverflowError, not ValueError, on an int too large to convert, which
        # the caller does not catch -- so such a rule would leave the job with no
        # decision at all rather than with a refusal in its trace.
        number = int(value)
    else:
        if not (Validators.is_float(value) or Validators.is_string(value)):
            raise EvalError(f"a ceiling must be a number, not {type(value).__name__}")
        try:
            parsed = float(value)
        except ValueError:
            raise EvalError(f"a ceiling must be a number, not {value!r}") from None
        # Refused rather than truncated so the two spellings of one value agree: int()
        # read 5.9 as 5 and raised a parse error on "5.5", and that error reached the
        # administrator's trace as a Python message about base 10.
        if not math.isfinite(parsed) or parsed != int(parsed):
            raise EvalError(f"a ceiling must be a whole number, not {value!r}")
        number = int(parsed)
    if number < 1:
        raise EvalError(f"a ceiling must be at least 1, not {number}")
    return number


def _trace_action_error(decision: RoutingDecision, rule: Rule, error: str) -> None:
    """Record that a matched rule's action raised, as a second entry for that rule."""
    decision.trace.append(
        RuleTraceEntry(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            action=rule.action,
            matched=True,
            predicate_eval_ms=0.0,
            error=error,
            notes="the rule matched and its action raised",
        )
    )


def _elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000
