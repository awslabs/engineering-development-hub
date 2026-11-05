######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
The routing policy layer: what an administrator's rules decide about one job.

The layers, bottom up:

  models.py     the rule, the facts a rule can read, and the decision.
  engine.py     the predicate language: compile a rule's `when`, evaluate it
                against those facts, and apply a matched rule's `then`.
  evaluator.py  the four passes that turn a policy version plus one job into a
                decision.

Nothing here reaches DynamoDB, Flask or boto3. A policy is evaluated on the
submission hot path, once per job, from a systemd process that PBS is waiting on; it
is also evaluated by the Replay view inside uwsgi to answer "what would this rule
have done". Both need the same answer from the same code, so this layer stays clear
of network calls and of a web framework. The one shared dependency is
`utils.validators`, which is itself import-free beyond the standard library.

Deliberately NOT a sibling of `job_routing`: a routing decision is made for a job
this package already models, and a second top-level package would give the tree two
`models.py` files, one holding a delegation row and one holding a rule, with nothing
in either name to say which is which.

The package imports nothing at import time, for the reason the parent package does
not: reading a rule must not pull in an evaluator, and evaluating a rule must not
pull in a scheduler driver.

Where the policy comes FROM arrives with the rule store. `engine.compile_predicate`
returns the compiled form and `engine.evaluate` accepts it as `pre_compiled` precisely
so a caller can hold it across jobs, and `engine.compile_predicate_cached` does that
holding for the submission path.

That cache is keyed on the predicate TEXT, which is what makes it safe without an
invalidation signal: compiling is a pure function of the text, so a promoted version
whose predicate changed is a different key, and one whose predicate did not needs no
new entry. A cache keyed on a rule or version id would need invalidating, and a cache
with no invalidation signal is how a promoted policy fails to take effect.
"""
