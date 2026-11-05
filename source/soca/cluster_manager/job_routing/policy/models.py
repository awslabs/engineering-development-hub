######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
The routing policy's data model: a rule, the facts a rule can read, and the decision.

Every type here is JSON-serializable through `as_audit_dict`, because a decision is
written to the routing history table and read back by the Replay view. A decision that
could not be serialized could not be replayed, and a routing decision that cannot be
replayed cannot be explained to the user whose job was sent to another region.

The context classes each render themselves with `as_cel_dict`, and they all OMIT a
field whose value is None rather than substituting an empty string. That is load
bearing: the predicate language's `has()` answers whether a field is present, so a
missing project stored as "" would make `has(job.project)` true and a rule written to
catch jobs with no project would never match one.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from utils.validators import Validators


class ActionType(str, Enum):
    """What a matched rule does.

    A `str` enum so a value survives JSON serialization as its own name, which is what
    makes a stored decision readable without this module.
    """

    DEFAULTS = "defaults"
    OVERRIDES = "overrides"
    REQUIRE = "require"
    ROUTING = "routing"


class RoutingStatus(str, Enum):
    """Where one job is in the routing lifecycle.

    Held by the delegation ledger rather than by a decision: a decision is made once
    and never changes, while a job's status moves as attempts succeed or fail.
    """

    ROUTING = "routing"
    HELD = "held"
    RESETTING = "resetting"
    LOCKED = "locked"
    LAUNCHED = "launched"
    REJECTED = "rejected"


@dataclasses.dataclass
class Rule:
    """
    One rule in a policy version.

    `when` is a predicate in the language `engine` implements. `then` is the action
    body, whose shape depends on `action`: a field map for defaults and overrides, a
    deny message for require, and the routing parameters for routing.
    """

    rule_id: str
    name: str
    action: ActionType
    when: str
    then: Dict[str, Any]
    enabled: bool = True
    # Lower runs first, within the pass this rule's action selects.
    order: int = 0
    description: str = ""


@dataclasses.dataclass
class PolicyVersion:
    """
    Every rule as it stood at one version, which is the unit that gets promoted.

    A version rather than a mutable rule set because a routing decision names the
    version that produced it. Editing rules in place would leave a stored decision
    citing a policy that no longer exists, and the Replay view answers its question by
    re-running the cited version.
    """

    mesh_id: str
    version_id: str
    status: str
    rules: List[Rule]
    created_at: int
    created_by: str
    description: str = ""
    # Held as a dict rather than a dataclass so the rollback schema can grow without a
    # migration of stored versions. None means the evaluator's own defaults.
    auto_rollback_policy: Optional[Dict[str, Any]] = None
    auto_rollback_fired_at: Optional[int] = None
    # Set once, when the version becomes production. Never modified afterwards,
    # because a warmup window is measured from it.
    promoted_at: Optional[int] = None


@dataclasses.dataclass
class JobContext:
    """
    The job being evaluated, as the policy sees it.

    Mutable, unlike most models in this tree, because the defaults and overrides passes
    change it: that mutation IS the action's effect, and the changed job is what the
    hook applies to the in-flight submission.
    """

    queue: Optional[str]
    project: Optional[str]
    user: str
    resources: Dict[str, Any] = dataclasses.field(default_factory=dict)
    tags: Dict[str, str] = dataclasses.field(default_factory=dict)
    select_str: Optional[str] = None
    ncpus: Optional[int] = None
    mem_gb: Optional[float] = None
    walltime: Optional[str] = None
    instance_type: Optional[str] = None
    base_os: Optional[str] = None

    def as_cel_dict(self) -> Dict[str, Any]:
        """
        Render the job as the `job` a predicate reads.

        The named resource fields are lifted INTO `resources`, so a policy writes
        `job.resources.ncpus` whether the value arrived as a column of this class or
        inside the free-form resource map. An explicitly set field wins over a
        same-named entry in the map, because the column is the parsed value and the
        map entry is whatever the submission happened to carry.
        """
        rendered: Dict[str, Any] = {
            "user": self.user,
            "resources": dict(self.resources),
            "tags": dict(self.tags),
        }
        for field in ("queue", "project", "select_str"):
            value = getattr(self, field)
            if value is not None:
                rendered[field] = value
        for field in ("ncpus", "mem_gb", "walltime", "instance_type", "base_os"):
            value = getattr(self, field)
            if value is not None:
                rendered["resources"][field] = value
        return rendered


@dataclasses.dataclass
class UserContext:
    """The submitting user, as the policy sees them."""

    username: str
    groups: List[str] = dataclasses.field(default_factory=list)
    team: Optional[str] = None
    email: Optional[str] = None

    def as_cel_dict(self) -> Dict[str, Any]:
        """
        Render the user as the `user` a predicate reads.

        `team` and `email` are omitted when unset rather than rendered as "", for the
        reason given in the module docstring: a rule catching users with no team is
        written as `!has(user.team)`, and an empty string would make that never match.
        """
        rendered: Dict[str, Any] = {
            "username": self.username,
            "groups": list(self.groups),
        }
        for field in ("team", "email"):
            value = getattr(self, field)
            if value is not None:
                rendered[field] = value
        return rendered


@dataclasses.dataclass
class ClusterContext:
    """
    This cluster and its peers, as the policy sees them.

    Each entry of `peer_summaries` is the mesh's own view of one peer: its cluster id,
    region, health, free capacity and architecture. A routing rule reads it to put
    regions in order, so it carries whatever the policy is allowed to route ON.
    """

    self_cluster_id: str
    self_region: str
    peer_summaries: List[Dict[str, Any]] = dataclasses.field(default_factory=list)

    def as_cel_dict(self) -> Dict[str, Any]:
        return {
            "self_cluster_id": self.self_cluster_id,
            "self_region": self.self_region,
            "peers": [dict(peer) for peer in self.peer_summaries],
        }


@dataclasses.dataclass
class EvaluationContext:
    """
    Every fact a predicate may reference, for one evaluation of one job.

    `consumed_regions`, `hop_count` and `reset_count` are what stop a job circling the
    mesh: they describe where this job has already been, so a routing rule can exclude
    those regions and a ceiling can end the attempt.
    """

    job: JobContext
    user: UserContext
    cluster: ClusterContext
    now_ts: int
    origin_region: str
    origin_cluster_id: str
    consumed_regions: List[str] = dataclasses.field(default_factory=list)
    hop_count: int = 0
    reset_count: int = 0

    def as_cel_dict(self) -> Dict[str, Any]:
        """
        Render every fact as the dict a predicate is evaluated against.

        `now` is derived from `now_ts` rather than read from the clock, so two
        evaluations of the same context give the same answer. That is what lets the
        Replay view re-run a stored decision and get the stored result: a rule reading
        `now.hour_utc` would otherwise answer differently at replay time than it did
        at submission time, and the view exists to explain the original decision.
        """
        moment = datetime.fromtimestamp(self.now_ts, tz=timezone.utc)
        return {
            "job": self.job.as_cel_dict(),
            "user": self.user.as_cel_dict(),
            "cluster": self.cluster.as_cel_dict(),
            "now": {
                "ts": self.now_ts,
                "hour_utc": moment.hour,
                "minute_utc": moment.minute,
                # Monday is 0, matching datetime rather than cron.
                "weekday": moment.weekday(),
                "iso": moment.isoformat(),
            },
            "origin_region": self.origin_region,
            "origin_cluster_id": self.origin_cluster_id,
            "consumed_regions": list(self.consumed_regions),
            "hop_count": self.hop_count,
            "reset_count": self.reset_count,
        }


@dataclasses.dataclass
class FieldChange:
    """One field a defaults or overrides rule changed, and what it was before."""

    rule_id: str
    # Dotted, as the rule wrote it: "queue", "resources.walltime", "tags.budget".
    field: str
    old_value: Any
    new_value: Any


@dataclasses.dataclass
class RuleTraceEntry:
    """
    One rule's outcome during an evaluation.

    Recorded for every rule considered, matched or not, because the Replay view's
    question is usually "why did this rule NOT fire". A trace holding only the matches
    cannot answer it.
    """

    rule_id: str
    rule_name: str
    action: ActionType
    matched: bool
    predicate_eval_ms: float
    # Set when the predicate failed to compile or raised. A rule whose predicate
    # errored does not match, so this is the only record that it was reached at all.
    error: Optional[str] = None
    notes: str = ""


@dataclasses.dataclass
class RoutingDecision:
    """
    What a policy version decided about one job.

    `accepted` false with a `deny_message` is a refusal from a require rule. Accepted
    with a `region_priority` of this cluster's own region alone is the ordinary local
    job, and is what an empty policy produces.
    """

    eval_id: str
    job_uuid: str
    mesh_id: str
    version_id: str

    accepted: bool
    deny_message: Optional[str] = None
    region_priority: List[str] = dataclasses.field(default_factory=list)
    # Cluster ids in preference order, when the policy names clusters rather than
    # regions. Needed because two clusters can share a region while billing different
    # departments, which a region list cannot express. Empty means the orchestrator
    # expands `region_priority` instead.
    cluster_priority: List[str] = dataclasses.field(default_factory=list)
    hop_ceiling: int = 10
    reset_ceiling: int = 3
    odcr_probe: bool = True
    split_horizon: bool = True

    defaults_filled: List[FieldChange] = dataclasses.field(default_factory=list)
    overrides_applied: List[FieldChange] = dataclasses.field(default_factory=list)

    trace: List[RuleTraceEntry] = dataclasses.field(default_factory=list)
    total_eval_ms: float = 0.0

    def as_audit_dict(self) -> Dict[str, Any]:
        """
        Render the decision as plain JSON types, for the history table.

        Enums are reduced to their values throughout rather than at the one place a
        decision is known to hold one. `ActionType` subclasses `str`, so a serializer
        would accept it either way and the conversion looks redundant -- but what is
        written here is read back by the Replay view and compared against a freshly
        computed decision, and `ActionType.DEFAULTS == "defaults"` holding does not
        make `repr` or a dict equality over mixed types behave.
        """
        return _plain(dataclasses.asdict(self))


def _plain(value: Any) -> Any:
    """Reduce enums to their values, recursively, leaving other types alone."""
    if isinstance(value, Enum):
        return value.value
    if Validators.is_dict(value):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value
