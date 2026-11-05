######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
Cross-cluster job routing.

The layers, bottom up:

  scheduler_drivers/  the engine abstraction. Stdlib only, no Flask, no mesh.
  models.py           the delegation row. Stdlib only, for the same reason.
  policy/             the rules an administrator writes, and what they decide about one
                      job. Stdlib only for a third reason: a decision is made on the
                      submission hot path, from a process PBS is waiting on, and
                      replayed later from inside uwsgi to explain itself.
  delegation_store.py the ledger. Needs boto3; goes through the mesh's own
                      configured session rather than a client of its own.
  dispatch_client.py  the transport to a peer's mesh sidecar.
  delegation_sync.py  one reconciliation pass over this cluster's delegations.

Still to arrive: the cache that holds the production policy for the hot path, and the
routing daemon that evaluates it per job and acts on the decision. The package is
deliberately empty of imports so that importing a driver never pulls in a routing
daemon, a mesh client or Flask.
"""
