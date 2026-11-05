######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

"""
The mesh peer lifecycle state machine.

Deliberately free of Flask. Whether a transition is legal, and whether it needs
agreement this release cannot collect, is domain logic rather than HTTP, and
separating it has two concrete consequences.

It is unit-testable with no web dependencies. `flask_restful` is declared in no
requirements file in this repository, so a test that imported the endpoint module
would pass only in an environment where that package happened to be installed.
CR3 shipped exactly that defect in the other direction, where the daemon's
dependency-free tests failed at collection because one of them imported a CDK
module, and the fix was to stop the tests requiring a toolchain the code under
test does not need. Putting the decisions here means the tests exercise the real
rules rather than a restatement of them.

It also puts the rules in one place that both the API and, later, the fence
protocol can share, rather than in a Flask resource where the only way to reuse
them is to import a web module.

`plan_transition` decides; the caller performs. Nothing here reads or writes
DynamoDB, so a test can enumerate every action against every state without a
table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Optional

from overlay_daemon.models import FenceOperation, Lifecycle

# Action name mapped to the state it moves a peer INTO and the states it may
# legally move FROM.
#
# The prototype had no such table: each endpoint set its target state gated only
# on the row existing, so `approve` would set ACTIVE on a REVOKED peer and put an
# emergency-revoked cluster back into routing on the next sync, and `tombstone`
# would skip DECOMMISSIONED entirely.
TRANSITIONS = {
    "approve": (Lifecycle.ACTIVE, frozenset({Lifecycle.PENDING})),
    "reject": (Lifecycle.REJECTED, frozenset({Lifecycle.PENDING})),
    # The three quorum-gated actions derive their target and their permitted
    # source states from FenceOperation rather than repeating them, because the
    # daemon needs the same rule when it applies a proposal that reached quorum and
    # cannot import this module. Lifecycle lives beside FenceOperation in the
    # daemon's models, so that is where the rule belongs; this table reads it.
    "decommission": (
        FenceOperation.DECOMMISSION.target_lifecycle,
        FenceOperation.DECOMMISSION.permitted_from,
    ),
    "tombstone": (
        FenceOperation.TOMBSTONE.target_lifecycle,
        FenceOperation.TOMBSTONE.permitted_from,
    ),
    "reclaim": (
        FenceOperation.RECLAIM.target_lifecycle,
        FenceOperation.RECLAIM.permitted_from,
    ),
    # Revoke is the emergency brake, so it is permitted from every state that can
    # still be carrying traffic or holding a usable key. Deliberately NOT from
    # REVOKED, which would rewrite the history of an existing revocation, nor from
    # TOMBSTONED, where the key is already gone.
    "revoke": (
        Lifecycle.REVOKED,
        frozenset(
            {
                Lifecycle.PENDING,
                Lifecycle.ACTIVE,
                Lifecycle.DECOMMISSIONED,
                Lifecycle.AVAILABLE_FOR_RECLAIM,
                Lifecycle.TAKEOVER_PENDING,
            }
        ),
    ),
}

# States that no action in this CR moves out of, named rather than inferred so the
# dead-end test has something to check against instead of accepting every
# unreachable state.
TERMINAL_STATES = frozenset({Lifecycle.REJECTED, Lifecycle.REVOKED})

# States this CR never produces, so nothing here needs to move out of them. Named
# for the same reason: the test that looks for dead ends must be able to tell a
# deliberate omission from a forgotten one.
NOT_PRODUCED_BY_THIS_CR = frozenset({Lifecycle.TAKEOVER_PENDING})

# Actions the fence protocol will own once it lands.
QUORUM_ACTIONS = frozenset({"decommission", "tombstone", "reclaim"})

# Above this many ACTIVE peers, one administrator's decision is not sufficient
# agreement and the action must go through a quorum proposal.
ADMIN_DECIDES_UP_TO_ACTIVE_PEERS = 2


class Outcome:
    """Why `plan_transition` answered as it did. Values are stable for the UI."""

    ALLOWED = "allowed"
    UNKNOWN_ACTION = "unknown_action"
    WRONG_STATE = "wrong_state"
    NEEDS_QUORUM = "needs_quorum"


@dataclass(frozen=True)
class Decision:
    """
    The answer, plus the text an operator should read when it is no.

    `target` is set only when the transition is allowed, so a caller cannot write
    a lifecycle out of a refusal by reading a field that was populated anyway.
    """

    outcome: str
    reason: str = ""
    target: Optional[Lifecycle] = None

    @property
    def allowed(self) -> bool:
        return self.outcome == Outcome.ALLOWED


def permitted_actions(current: Lifecycle) -> list:
    """
    Which actions are legal from a state, ignoring quorum.

    Surfaced to the UI so it can disable what cannot be done, rather than
    reimplementing this table in JavaScript and drifting from it.
    """
    return sorted(
        action
        for action, (_target, allowed_from) in TRANSITIONS.items()
        if current in allowed_from
    )


def plan_transition(
    *,
    action: str,
    current: Lifecycle,
    active_peer_count: int,
) -> Decision:
    """
    Decide whether an action may be performed, without performing it.

    Refuses a quorum action on a mesh large enough to require agreement, rather
    than performing it directly. The prototype fell through to a direct mutation
    whenever its fence module could not be imported, which is the dangerous
    direction: an environment where that import fails is one where destructive
    operations silently bypass quorum. Refusing costs a wait; mutating costs the
    guarantee the protocol exists for.
    """
    entry = TRANSITIONS.get(action)
    if entry is None:
        return Decision(
            outcome=Outcome.UNKNOWN_ACTION,
            reason=(
                f"{action!r} is not a peer lifecycle action. Known actions: "
                f"{sorted(TRANSITIONS)}."
            ),
        )
    target, allowed_from = entry

    if current not in allowed_from:
        return Decision(
            outcome=Outcome.WRONG_STATE,
            reason=(
                f"Cannot {action} a peer that is {current.value}. {action} is "
                f"permitted only from "
                f"{sorted(state.value for state in allowed_from)}."
            ),
        )

    if action in QUORUM_ACTIONS and active_peer_count > ADMIN_DECIDES_UP_TO_ACTIVE_PEERS:
        return Decision(
            outcome=Outcome.NEEDS_QUORUM,
            reason=(
                f"This mesh has {active_peer_count} active peers, and {action} on "
                f"a mesh of more than {ADMIN_DECIDES_UP_TO_ACTIVE_PEERS} requires "
                f"agreement from a quorum of peers rather than one "
                f"administrator's decision. The protocol that collects that "
                f"agreement is not part of this release, so this is refused "
                f"rather than applied directly."
            ),
        )

    return Decision(outcome=Outcome.ALLOWED, target=target)
