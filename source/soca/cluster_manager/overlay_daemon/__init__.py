######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                               #
######################################################################################################################

"""
edh-overlay-daemon: cross-region WireGuard mesh sync agent.

Runs as a systemd unit on each cluster's controller. It bootstraps the cluster
into a mesh (creating it, or joining one another cluster created), then polls
the mesh's DynamoDB Global Table for peer configuration and renders the local
WireGuard interface and peer hostname file from it.

The mesh's shared state lives in DynamoDB Global Tables deployed by
helpers/cdk/cross_region/ddb_global_tables.py. When the peer clusters live in
different AWS accounts, those tables sit in the mesh creator's account and this
daemon reaches them by assuming the participant role built by
helpers/cdk/cross_region/mesh_iam.py::build_mesh_participant_role.

See docs/cross_region/README.md for the feature overview and
docs/cross_region/MultiAccount.md for the cross-account trust model.

Module layout:
  __main__.py        CLI entrypoint: bootstrap plus the sync loop
  bootstrap.py       mesh CREATE / JOIN flows
  ddb_client.py      typed DDB Global Table + Secrets Manager access layer
  table_names.py     runtime resolution of the per-mesh physical table names
  schema.py          row schema registry and version dispatch
  models.py          peer / mesh / health / audit data classes
  wg_config.py       render and apply the WireGuard configuration
  hosts_writer.py    write /etc/edh-mesh-hosts for peer name resolution

Peer health probing, PBS integration, the fence protocol and the job-routing
policy engine are separate subsystems that build on this package; they are not
part of it.
"""

# The daemon reports this in its heartbeat row so a mixed-version mesh can be
# diagnosed from any member. It is the EDH version rather than a version of its
# own: the daemon ships inside EDH, and a separately maintained string would go
# stale and report the same value on every cluster forever, which is precisely
# what the heartbeat field exists to distinguish.
try:
    from utils.version import __version__
except ImportError:  # pragma: no cover - utils is absent in a bare script
    # Deliberately not a version-shaped string, so it cannot be mistaken for
    # one if it reaches a heartbeat row or a comparison.
    __version__ = "unknown"
