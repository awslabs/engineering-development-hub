######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
The predicate language a routing rule is written in, and the executor for its action.

A deliberately small subset of CEL, evaluated over Python's own parsed AST. `celpy`,
the full CEL implementation, is not used for two reasons: it is not in the controller's
permitted install set, and the surface a routing rule needs is about twenty operators,
which is small enough to audit line by line. The public entry points are
`compile_predicate` and `evaluate`, and they are the shape a `celpy` adapter would
have, so swapping the implementation later does not reach the callers.

The language:

  literals        int, float, string, bool, null
  lookups         job.resources.ncpus, cluster.peers[0].region
  operators       == != < <= > >= && || !
  membership      x in [a, b, c]
  methods         .contains(x) .startsWith(x) .endsWith(x)
  built-ins       has(x.y), size(x)
  registered      anything a caller puts in a FunctionRegistry, including the
                  dotted form a policy writes as cluster.capacity_pct(region)

Not supported, and rejected at compile time rather than at submission time: arithmetic,
assignment, comprehensions, lambdas, f-strings, and every other Python node outside the
allowed set. A rule that cannot compile is refused when an administrator saves it,
which is the only moment a human is present to read the error.

WHAT THIS IS NOT. It is not a sandbox for hostile input, and it must not be relied on
as one. A rule is authored by a cluster administrator through an authenticated admin
surface, and an administrator can already run commands on the controller. The
restrictions here exist so that a MISTAKE in a rule fails loudly instead of doing
something surprising to a user's job.

Four behaviours differ from the prototype this is ported from, each because the
prototype was run and observed rather than read:

- `size()` evaluated its argument twice, so a registered function in its argument ran
  twice per predicate. Now once.
- The documented `.contains`, `.startsWith` and `.endsWith` were unimplemented: the
  call name was flattened to `job.queue.contains`, which resolved to no registered
  function and raised. They are implemented here as methods.
- Attribute lookup used `getattr`, so `has(job.user.__class__)` answered true and a
  rule could walk out of the facts it was given into Python's object model. Names
  beginning with an underscore are now refused at compile time.
- `in` against a string tested for a SUBSTRING, so `"ice" in job.user` matched alice.
  The right operand must now be a list, tuple or map, and a string receiver is directed
  to `.contains`.
"""

from __future__ import annotations

import ast as _ast
import functools
import logging
import operator as _operator
from typing import Any, Callable, Dict, List, Optional

from utils.validators import Validators

from .models import ActionType, FieldChange, JobContext, Rule

logger = logging.getLogger("soca_logger")


class CompileError(Exception):
    """A predicate could not be parsed, or used something outside the language."""


class EvalError(Exception):
    """A compiled predicate failed while being evaluated."""


class FunctionRegistry:
    """
    The functions a predicate may call, beyond the built-ins.

    Supplied per evaluation rather than imported, because the useful ones answer from
    DynamoDB or cluster config and this module reaches neither. A caller on the
    submission path registers implementations that do; a test registers stubs.

    A function receives `(args, context)`, where `args` is the list of evaluated
    argument values and `context` is the fact dict the predicate is running against.
    """

    def __init__(self) -> None:
        self._functions: Dict[str, Callable[[List[Any], Dict[str, Any]], Any]] = {}

    def register(self, name: str, function: Callable[[List[Any], Dict[str, Any]], Any]) -> None:
        self._functions[name] = function

    def names(self) -> List[str]:
        return sorted(self._functions)

    def call(self, name: str, args: List[Any], context: Dict[str, Any]) -> Any:
        """
        Invoke a registered function, normalizing whatever it raises to EvalError.

        The normalization is the boundary this class exists to be. A registered
        implementation answers from DynamoDB or cluster config, so it can raise
        ClientError, KeyError or TypeError -- none of which the evaluator catches. Left
        unwrapped, one of those escapes the per-rule handler and aborts the whole
        evaluation, so a transient throttle on a capacity lookup would deny a job a
        decision entirely. That is the opposite of the documented fail-open rule, under
        which a rule that raises merely does not match.

        EvalError is re-raised unchanged so a nested evaluation's message is not
        wrapped twice.
        """
        if name not in self._functions:
            raise EvalError(f"unknown function: {name}")
        try:
            return self._functions[name](args, context)
        except EvalError:
            raise
        except Exception as error:
            raise EvalError(f"function {name} raised {type(error).__name__}: {error}") from error


# Every AST node the language permits. Anything else is refused at compile time.
#
# `ast.Index` is absent deliberately. It is deprecated, and `ast.parse` has not
# produced it for a subscript since Python 3.9, so a branch handling it would be
# unreachable on every interpreter this ships on -- which is worse than its absence,
# because unreachable compatibility code reads as a supported case.
_ALLOWED_NODES = frozenset(
    {
        _ast.Expression,
        _ast.BoolOp,
        _ast.UnaryOp,
        _ast.Compare,
        _ast.Call,
        _ast.Name,
        _ast.Attribute,
        _ast.Subscript,
        _ast.Constant,
        _ast.List,
        _ast.Tuple,
        _ast.And,
        _ast.Or,
        _ast.Not,
        # Unary minus, so a negative number can be written as one. Without it `-1`
        # parses as USub over Constant(1) -- the AST is not folded -- and a rule
        # comparing against a negative threshold is refused for using a node type,
        # which reads as the language lacking numbers.
        _ast.USub,
        _ast.Eq,
        _ast.NotEq,
        _ast.Lt,
        _ast.LtE,
        _ast.Gt,
        _ast.GtE,
        _ast.In,
        _ast.NotIn,
        _ast.Load,
    }
)

# Methods callable on a value, rather than looked up in the registry. A receiver is
# part of the call, so these cannot be registered: a registry is keyed by name, and
# the name here depends on the expression to its left.
_STRING_METHODS = frozenset({"contains", "startsWith", "endsWith"})

_COMPARISONS = {
    _ast.Eq: _operator.eq,
    _ast.NotEq: _operator.ne,
    _ast.Lt: _operator.lt,
    _ast.LtE: _operator.le,
    _ast.Gt: _operator.gt,
    _ast.GtE: _operator.ge,
}

# Sentinel for a lookup that resolved to nothing. Distinct from None, which is a value
# a fact may legitimately hold, and never returned to a caller.
_MISSING = object()

# Closing bracket for each opening one, for finding the extent of a `!` operand.
_OPENING_BRACKETS = {"(": ")", "[": "]", "{": "}"}

# CEL spells its constants in lower case, where Python's parser sees three ordinary
# names. Resolved here rather than rewritten in the source text, because a name is a
# whole token at this point: a substitution over the raw string would also hit a field
# called `nullable` or a fact called `is_true`.
#
# The common case this exists for is the rule that always applies, written `when:
# "true"`. Without it that predicate is a lookup of an absent fact, and the rule
# silently never matches.
_CEL_LITERALS = {"true": True, "false": False, "null": None}

# The bare field names a rule's `then` may set, as the module docstring describes them.
#
# `resources` and `tags` are reachable only through their dotted form. They are maps,
# and replacing one wholesale with a scalar leaves a JobContext whose `as_cel_dict`
# raises while rendering it -- outside the fail-open boundary, so a single mistyped key
# cost the job its decision rather than costing the rule its effect.
#
# The remaining columns are the parsed submission values, which a rule reaches as
# `resources.*` because `as_cel_dict` lifts them into that map.
_SETTABLE_BARE_FIELDS = frozenset({"queue", "project"})


def compile_predicate(predicate: str) -> _ast.Expression:
    """
    Parse and check a predicate, returning the compiled form `evaluate` accepts.

    Named for what it does rather than `compile`, which would shadow the builtin inside
    this module and read as the builtin at every call site in the next one.

    Raises CompileError, which is the error an administrator saving a rule should see.
    """
    if not Validators.is_string(predicate) or not predicate.strip():
        raise CompileError("a predicate must be a non-empty string")
    try:
        tree = _ast.parse(_to_python_source(predicate).strip(), mode="eval")
    except SyntaxError as error:
        raise CompileError(f"parse error: {error}") from error
    _check(tree.body)
    return tree


@functools.lru_cache(maxsize=512)
def _compile_cached(predicate: str) -> _ast.Expression:
    return compile_predicate(predicate)


def compile_predicate_cached(predicate: str) -> _ast.Expression:
    """
    `compile_predicate`, memoized on the predicate text.

    For the submission path, where the same rule set is evaluated once per job and
    re-parsing every predicate every time is pure waste -- which is what `pre_compiled`
    exists to avoid, and what passing `compile_predicate(...)` into it inline defeated.

    THE RETURNED TREE IS SHARED between callers and must not be mutated. Nothing in
    this module writes to a tree, and a caller that needs to should use
    `compile_predicate` for an unshared one. A predicate that fails to compile is not
    cached, because `lru_cache` does not memoize a raised exception -- so an invalid
    rule is re-parsed per job, which is the cost of a case an administrator is meant to
    have been shown at save time.

    Bounded, so a long-lived process cannot accumulate an entry per predicate it has
    ever seen. A policy version holds a finite rule set, but a daemon serving many
    versions over its lifetime would otherwise keep every one of them.
    """
    return _compile_cached(predicate)


def evaluate(
    predicate: str,
    context: Dict[str, Any],
    *,
    registry: Optional[FunctionRegistry] = None,
    pre_compiled: Optional[_ast.Expression] = None,
) -> bool:
    """
    Evaluate a predicate against a fact dict, as a bool.

    `pre_compiled` lets a caller parse once and evaluate per job; when it is given,
    `predicate` is not parsed and is used only in error messages.
    """
    tree = pre_compiled if pre_compiled is not None else compile_predicate(predicate)
    value = _eval(tree.body, context, registry if registry is not None else FunctionRegistry())
    return bool(value)


def evaluate_expression(
    expression: str,
    context: Dict[str, Any],
    *,
    registry: Optional[FunctionRegistry] = None,
    pre_compiled: Optional[_ast.Expression] = None,
) -> Any:
    """
    Evaluate an expression to its VALUE rather than to a bool.

    The same language as `evaluate`, and the entry point for the places a rule carries
    an expression whose result is not a condition: a defaults value, or the list of
    regions a routing rule prefers. Separate from `evaluate` because that one answers a
    predicate and coercing a list of regions to True would hide the mistake.
    """
    tree = pre_compiled if pre_compiled is not None else compile_predicate(expression)
    return _eval(tree.body, context, registry if registry is not None else FunctionRegistry())


def _to_python_source(predicate: str) -> str:
    """
    Rewrite the operators CEL spells differently from Python: && || !

    `&&` and `||` are a straight substitution, because `and` and `or` sit at the same
    place in both precedence tables. `!` is not: it is emitted as a parenthesized
    `(not <operand>)`, since Python's `not` binds looser than the comparison and
    membership operators where CEL's `!` binds tighter.

    Characters inside a string literal are copied verbatim, so a quoted value
    containing `&&` or `!` is left alone. An escaped quote does not end the literal.

    Whether a quote is escaped is decided by the PARITY of the backslash run before
    it, not by the single preceding character. A literal ending in an escaped
    backslash -- `"a\\"` -- puts one backslash before the closing quote, so a
    single-character test reads the quote as escaped, never closes the literal, and
    scans the rest of the predicate as though it were inside one. The `&&` after it
    is then not rewritten and the whole rule is refused with a parse error.
    """
    out: List[str] = []
    index = 0
    length = len(predicate)
    quote: Optional[str] = None
    while index < length:
        char = predicate[index]
        if quote is not None:
            out.append(char)
            if char == quote and _backslash_run_before(predicate, index) % 2 == 0:
                quote = None
            index += 1
            continue
        if char in ('"', "'"):
            quote = char
            out.append(char)
            index += 1
            continue
        if predicate.startswith("&&", index):
            out.append(" and ")
            index += 2
            continue
        if predicate.startswith("||", index):
            out.append(" or ")
            index += 2
            continue
        if char == "!" and not predicate.startswith("!=", index):
            # Parenthesized, because `not` does not bind the way `!` does. CEL's `!`
            # binds TIGHTER than ==, !=, <, in; Python's `not` binds LOOSER than all
            # of them. So a bare substitution reassociates the expression:
            #
            #   !job.flag == "yes"      CEL (!flag) == "yes", Python not (flag == "yes")
            #   !job.flag in [a, b]     CEL (!flag) in [a, b], Python not (flag in ...)
            #
            # Both parse and both evaluate, to the answer the administrator did not
            # write -- the same shape of defect as `in` against a string reading as a
            # substring. And `job.a == !job.b`, which CEL allows, became
            # `job.a ==  not job.b`: a syntax error, so a valid rule was refused.
            end = _unary_operand_end(predicate, index + 1)
            out.append("(not ")
            out.append(_to_python_source(predicate[index + 1 : end]))
            out.append(")")
            index = end
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _unary_operand_end(predicate: str, start: int) -> int:
    """
    Where the operand of a `!` at `start - 1` ends.

    CEL applies `!` to a unary expression, which is a run of unary operators followed
    by a member: a primary plus any selectors, indexes and calls on it. So `!!flag`,
    `!job.flags.gpu` and `!has(job.project)` are each one operand, while the `==` in
    `!job.flag == "yes"` is not part of one.
    """
    index = _skip_space(predicate, start)
    length = len(predicate)

    # A nested unary belongs to this operand. The recursive rewrite of the operand
    # text handles the inner `!` itself.
    while index < length and (
        predicate[index] == "-"
        or (predicate[index] == "!" and not predicate.startswith("!=", index))
    ):
        index = _skip_space(predicate, index + 1)

    if index >= length:
        raise CompileError("`!` must be followed by a value")

    char = predicate[index]
    if char in _OPENING_BRACKETS:
        index = _balanced_end(predicate, index)
    elif char in ('"', "'"):
        index = _string_end(predicate, index)
    elif char.isidentifier():
        index += 1
        while index < length and (predicate[index].isalnum() or predicate[index] == "_"):
            index += 1
    elif char.isdigit():
        index += 1
        while index < length and (predicate[index].isdigit() or predicate[index] == "."):
            index += 1
    else:
        raise CompileError(f"`!` must be followed by a value, not {char!r}")

    # Selectors bind tighter than `!`, so they are part of the operand. CEL allows
    # whitespace between tokens, so `!job . flag` is the same operand as `!job.flag`;
    # stopping at the space would emit `(not job).flag`, which resolves to nothing.
    while True:
        after = _skip_space(predicate, index)
        if after >= length:
            return index
        char = predicate[after]
        if char == ".":
            name = _skip_space(predicate, after + 1)
            if name < length and predicate[name].isidentifier():
                index = name + 1
                while index < length and (
                    predicate[index].isalnum() or predicate[index] == "_"
                ):
                    index += 1
                continue
            raise CompileError("a `.` after `!` is not followed by an attribute name")
        if char in ("(", "["):
            index = _balanced_end(predicate, after)
            continue
        return index


def _skip_space(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _balanced_end(predicate: str, open_index: int) -> int:
    """Where the bracket opened at `open_index` closes. Quoted brackets do not count."""
    expected = [_OPENING_BRACKETS[predicate[open_index]]]
    index = open_index + 1
    length = len(predicate)
    while index < length and expected:
        char = predicate[index]
        if char in ('"', "'"):
            index = _string_end(predicate, index)
            continue
        if char in _OPENING_BRACKETS:
            expected.append(_OPENING_BRACKETS[char])
            index += 1
            continue
        if char == expected[-1]:
            expected.pop()
            index += 1
            continue
        index += 1
    if expected:
        raise CompileError("a bracket opened after `!` is never closed")
    return index


def _string_end(predicate: str, open_index: int) -> int:
    """Where the literal opened at `open_index` closes, by backslash-run parity."""
    quote = predicate[open_index]
    index = open_index + 1
    length = len(predicate)
    while index < length:
        if predicate[index] == quote and _backslash_run_before(predicate, index) % 2 == 0:
            return index + 1
        index += 1
    raise CompileError("a string literal opened after `!` is never closed")


def _backslash_run_before(text: str, index: int) -> int:
    """How many backslashes immediately precede `index`. Odd means it is escaped."""
    run = 0
    position = index - 1
    while position >= 0 and text[position] == "\\":
        run += 1
        position -= 1
    return run


def _check(node: _ast.AST) -> None:
    """Refuse any node outside the language, and any underscore-prefixed attribute."""
    for current in _ast.walk(node):
        if type(current) not in _ALLOWED_NODES:
            raise CompileError(f"not part of the policy language: {type(current).__name__}")
        if isinstance(current, _ast.Attribute) and current.attr.startswith("_"):
            # Refused here rather than at lookup time so an administrator sees it when
            # saving the rule. A predicate reads the facts it was given; an attribute
            # starting with an underscore is not one of them, it is Python's own object
            # model reached through getattr.
            raise CompileError(f"attribute names may not start with an underscore: {current.attr}")


def _eval(node: _ast.AST, context: Dict[str, Any], registry: FunctionRegistry) -> Any:
    """
    Evaluate one node to a value.

    Always a value, never the (value, present) pair `_lookup` deals in. Keeping the
    presence flag inside `_lookup` is what lets a registered function return a 2-tuple
    without it being mistaken for one.
    """
    if isinstance(node, _ast.Constant):
        return node.value

    if isinstance(node, _ast.BoolOp):
        if isinstance(node.op, _ast.And):
            return all(bool(_eval(value, context, registry)) for value in node.values)
        return any(bool(_eval(value, context, registry)) for value in node.values)

    if isinstance(node, _ast.UnaryOp):
        if isinstance(node.op, _ast.USub):
            operand = _eval(node.operand, context, registry)
            # is_int excludes bool and is_float rejects it, so this is "a number that is
            # not a bool" without the double negative the raw isinstance form needed.
            if not (Validators.is_int(operand) or Validators.is_float(operand)):
                raise EvalError(f"cannot negate {type(operand).__name__}")
            return -operand
        return not bool(_eval(node.operand, context, registry))

    if isinstance(node, _ast.Compare):
        left = _eval(node.left, context, registry)
        for operator_node, right_node in zip(node.ops, node.comparators):
            right = _eval(right_node, context, registry)
            if not _compare(operator_node, left, right):
                return False
            left = right
        return True

    if isinstance(node, _ast.Call):
        return _eval_call(node, context, registry)

    if isinstance(node, (_ast.Name, _ast.Attribute, _ast.Subscript)):
        value = _lookup(node, context, registry)
        return None if value is _MISSING else value

    if isinstance(node, (_ast.List, _ast.Tuple)):
        return [_eval(element, context, registry) for element in node.elts]

    raise EvalError(f"cannot evaluate: {type(node).__name__}")


def _eval_call(node: _ast.Call, context: Dict[str, Any], registry: FunctionRegistry) -> Any:
    """Evaluate a call: a method on a value, a built-in, or a registered function."""
    if isinstance(node.func, _ast.Attribute) and node.func.attr in _STRING_METHODS:
        return _eval_method(node, context, registry)

    name = _call_name(node.func)

    if name == "has":
        # The one function that needs its argument UNevaluated, because the question it
        # answers is whether the lookup resolves at all.
        if Validators.is_list_length_not_equal_of(node.args, 1):
            raise EvalError("has() takes exactly one argument")
        value = _lookup(node.args[0], context, registry)
        return value is not _MISSING and value is not None

    args = [_eval(argument, context, registry) for argument in node.args]

    if name == "size":
        if Validators.is_list_length_not_equal_of(args, 1):
            raise EvalError("size() takes exactly one argument")
        subject = args[0]
        if subject is None:
            return 0
        try:
            return len(subject)
        except TypeError:
            raise EvalError(f"size() needs a string, list or map, not {type(subject).__name__}") from None

    return registry.call(name, args, context)


def _eval_method(node: _ast.Call, context: Dict[str, Any], registry: FunctionRegistry) -> bool:
    """
    Evaluate `receiver.contains(x)`, `.startsWith(x)` or `.endsWith(x)`.

    A missing receiver RAISES rather than answering false. False would be inverted by
    `!` into a match, so a rule reading `!job.queue.startsWith("gpu")` would fire for
    every job that has no queue at all -- the opposite of what its author meant. An
    error makes the rule not match whatever the surrounding logic is, and lands in the
    decision's trace where the author can see it. The guard a policy should use is
    `has(job.queue) && job.queue.startsWith("gpu")`.
    """
    method = node.func.attr
    path = _describe(node.func.value)
    receiver = _lookup(node.func.value, context, registry)
    if receiver is _MISSING or receiver is None:
        raise EvalError(f"{path} is not set, so .{method}() cannot be applied; guard it with has({path})")

    if Validators.is_list_length_not_equal_of(node.args, 1):
        raise EvalError(f".{method}() takes exactly one argument")
    argument = _eval(node.args[0], context, registry)

    if method == "contains":
        if Validators.is_string(receiver):
            if not Validators.is_string(argument):
                raise EvalError(".contains() on a string needs a string argument")
            return argument in receiver
        if isinstance(receiver, (list, tuple, dict)):
            try:
                return argument in receiver
            except TypeError:
                # The same gap `_compare` guards for the `in` operator, at its sibling
                # site: a map receiver hashes the argument, so an unhashable argument
                # -- a map or a list, both of which the facts hold -- raises TypeError.
                # That is neither CompileError nor EvalError, so no handler on the path
                # caught it and the whole evaluation aborted, leaving the job with no
                # decision at all.
                raise EvalError(
                    f".contains() cannot test a {type(argument).__name__} for "
                    f"membership of a {type(receiver).__name__}"
                ) from None
        raise EvalError(f".contains() needs a string, list or map, not {type(receiver).__name__}")

    if not Validators.is_string(receiver) or not Validators.is_string(argument):
        raise EvalError(f".{method}() needs a string receiver and a string argument")
    return receiver.startswith(argument) if method == "startsWith" else receiver.endswith(argument)


def _lookup(node: _ast.AST, context: Dict[str, Any], registry: FunctionRegistry) -> Any:
    """
    Resolve a lookup, returning `_MISSING` when it does not resolve.

    Mapping keys only, never `getattr`: the facts are plain dicts, and attribute access
    is what let the prototype's predicates reach Python's object model.
    """
    if isinstance(node, _ast.Name):
        if node.id in _CEL_LITERALS:
            return _CEL_LITERALS[node.id]
        return context[node.id] if node.id in context else _MISSING

    if isinstance(node, _ast.Attribute):
        base = _lookup(node.value, context, registry)
        if base is _MISSING or base is None:
            return _MISSING
        if Validators.is_dict(base):
            return base[node.attr] if node.attr in base else _MISSING
        return _MISSING

    if isinstance(node, _ast.Subscript):
        base = _lookup(node.value, context, registry)
        if base is _MISSING or base is None:
            return _MISSING
        index = _eval(node.slice, context, registry)
        try:
            return base[index]
        except (KeyError, IndexError, TypeError):
            return _MISSING

    # A call or literal in a lookup position: evaluate it. `has(size(x))` lands here,
    # and so does `has(cluster.capacity_pct("us-east-2"))`.
    return _eval(node, context, registry)


def _call_name(node: _ast.AST) -> str:
    """The registry key for a call: `foo`, or the dotted `cluster.capacity_pct`."""
    if isinstance(node, _ast.Name):
        return node.id
    if isinstance(node, _ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}"
    raise EvalError(f"cannot call: {type(node).__name__}")


def _describe(node: _ast.AST) -> str:
    """A dotted path for an error message, or `<expression>` when it is not one."""
    if isinstance(node, _ast.Name):
        return node.id
    if isinstance(node, _ast.Attribute):
        return f"{_describe(node.value)}.{node.attr}"
    return "<expression>"


def _compare(operator_node: _ast.AST, left: Any, right: Any) -> bool:
    """
    Compare two values.

    Membership requires a list, tuple or map on the right. A string there used to mean
    a substring test, which made `"ice" in job.user` match alice -- a rule that reads
    as an equality check against a set and behaves as a prefix-free text search.
    """
    if isinstance(operator_node, (_ast.In, _ast.NotIn)):
        negated = isinstance(operator_node, _ast.NotIn)
        if right is None:
            return negated
        if Validators.is_string(right):
            raise EvalError("`in` needs a list or map on the right; for text use .contains()")
        if not isinstance(right, (list, tuple, dict)):
            raise EvalError(f"`in` needs a list or map on the right, not {type(right).__name__}")
        try:
            return (left not in right) if negated else (left in right)
        except TypeError:
            # A map on the right hashes the left operand, so an unhashable left -- a
            # map or a list, both of which the facts hold -- raises TypeError. That is
            # neither CompileError nor EvalError, so no handler on the path caught it
            # and the whole evaluation aborted: the job received no decision at all,
            # which is the one outcome the fail-open rule exists to prevent.
            #
            # Refused rather than answered False, matching the two refusals above. The
            # mistake is the same class as theirs, and a rule's trace entry is the only
            # place an administrator learns the rule was broken rather than unmatched.
            raise EvalError(
                f"`in` cannot test a {type(left).__name__} for membership of a "
                f"{type(right).__name__}"
            ) from None

    function = _COMPARISONS.get(type(operator_node))
    if function is None:
        raise EvalError(f"unsupported comparison: {type(operator_node).__name__}")

    if left is None or right is None:
        # Ordering against an absent value is false, while equality still answers. A
        # rule comparing a field it did not check for presence therefore does not
        # match, rather than raising and losing the rest of the policy.
        if isinstance(operator_node, _ast.Eq):
            return left is right or left == right
        if isinstance(operator_node, _ast.NotEq):
            return not (left is right or left == right)
        return False

    try:
        return bool(function(left, right))
    except TypeError:
        # Comparing a string to a number is a rule-authoring mistake, not a match.
        return False


# ----------------------------------------------------------------------------------
# Actions
# ----------------------------------------------------------------------------------


def apply_action(
    rule: Rule,
    job: JobContext,
    context: Dict[str, Any],
    registry: FunctionRegistry,
) -> List[FieldChange]:
    """
    Run a matched rule's action, mutating `job`, and report what it changed.

    Require and routing rules change no field: a denial is the caller's to raise, and a
    routing rule's effect is read from `rule.then` by the evaluator.
    """
    if rule.action == ActionType.DEFAULTS:
        return _apply(rule, job, context, registry, only_when_unset=True)
    if rule.action == ActionType.OVERRIDES:
        return _apply(rule, job, context, registry, only_when_unset=False)
    if rule.action in (ActionType.REQUIRE, ActionType.ROUTING):
        return []
    raise EvalError(f"unknown action: {rule.action}")


def _apply(
    rule: Rule,
    job: JobContext,
    context: Dict[str, Any],
    registry: FunctionRegistry,
    *,
    only_when_unset: bool,
) -> List[FieldChange]:
    """
    Apply a rule's field map, ATOMICALLY: every field is resolved and checked before
    any is written.

    Field-at-a-time writing made a rule's effect disagree with its own audit record. A
    rule whose second field carried a malformed expr, or named a field a job does not
    have, raised after the first field was already written; the caller catches that and
    records no changes, so the job was submitted carrying a mutation absent from the
    trace. The Replay view answers its question by comparing a stored decision against
    a recomputed one, so a mutation it cannot see is a decision it cannot explain.

    Applying none of the fields rather than some is also the behaviour the module's
    fail-open rule already describes: a broken rule costs its own effect, nothing more.
    """
    planned: List[FieldChange] = []
    for field, specification in (rule.then or {}).items():
        current = _read_field(job, field)
        if only_when_unset and current is not None and current != "":
            continue
        new_value = _resolve(specification, context, registry)
        if only_when_unset and (new_value is None or new_value == ""):
            # A default that resolves to nothing leaves the field unset rather than
            # writing an empty value, which would make the field look supplied to
            # every later rule.
            continue
        if new_value == current:
            continue
        # Checked in the resolve pass so an unwritable field name is refused before
        # any sibling field has been written.
        _check_field_writable(job, field)
        planned.append(
            FieldChange(rule_id=rule.rule_id, field=field, old_value=current, new_value=new_value)
        )

    for change in planned:
        _write_field(job, change.field, change.new_value)
    return planned


def _resolve(specification: Any, context: Dict[str, Any], registry: FunctionRegistry) -> Any:
    """
    Resolve a `then` value: a literal, or `{"expr": "<predicate>"}` to evaluate.

    The marker is explicit because the prototype guessed, treating a string as an
    expression when it contained any of `()[].+`. That makes the meaning of a value
    depend on its punctuation: a walltime of "24:00:00" stays a literal, while a
    project named "team.hpc" or a queue named "gpu+large" is silently compiled and
    resolves to nothing. Guessing is affordable only while no policy has been written,
    which is now.
    """
    if Validators.is_dict(specification) and set(specification) == {"expr"}:
        expression = specification["expr"]
        if not Validators.is_string(expression):
            raise EvalError("an expr value must be a string")
        return _eval(compile_predicate(expression).body, context, registry)
    return specification


def _read_field(job: JobContext, field: str) -> Any:
    """Read a dotted field: a column of JobContext, or an entry of resources or tags."""
    if "." not in field:
        return getattr(job, field, None)
    head, rest = field.split(".", 1)
    if head == "resources":
        return job.resources.get(rest)
    if head == "tags":
        return job.tags.get(rest)
    return None


def _check_field_writable(job: JobContext, field: str) -> None:
    """
    Raise unless `field` names something a rule may set, writing nothing.

    Separate from `_write_field` so the whole field map can be validated before the
    first write, which is what makes a rule's action atomic.
    """
    if "." not in field:
        if not hasattr(job, field):
            # A rule naming a field the job does not have would otherwise create an
            # attribute that nothing reads, and report the change as applied.
            raise EvalError(f"a job has no field named {field}")
        if field not in _SETTABLE_BARE_FIELDS:
            # hasattr alone admitted every column of JobContext -- nine fields outside
            # the documented set, `user` and the two maps among them. Separate from the
            # message above because the two mistakes are different: that one names a
            # field that does not exist, this one names a field that does and is not a
            # rule's to set.
            raise EvalError(
                f"a rule can set queue, project, resources.* or tags.*, not {field}"
            )
        return
    head = field.split(".", 1)[0]
    if head in ("resources", "tags"):
        return
    raise EvalError(f"a rule can set queue, project, resources.* or tags.*, not {field}")


def _write_field(job: JobContext, field: str, value: Any) -> None:
    # Re-checked rather than assumed, so the write cannot be reached with a field name
    # the resolve pass never saw.
    _check_field_writable(job, field)
    if "." not in field:
        setattr(job, field, value)
        return
    head, rest = field.split(".", 1)
    if head == "resources":
        job.resources[rest] = value
        return
    job.tags[rest] = value
