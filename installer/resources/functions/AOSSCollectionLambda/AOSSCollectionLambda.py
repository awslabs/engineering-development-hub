######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#  SPDX-License-Identifier: Apache-2.0                                                                                #
######################################################################################################################
"""
CloudFormation custom-resource Lambda that creates an OpenSearch Serverless
(AOSS) **NextGen** collection group + collection.

Why a Lambda instead of CfnCollectionGroup? NextGen (scale-to-zero, minimum OCU
capacity = 0) is selected via the `generation="NEXTGEN"` request parameter,
which exists in boto3 >= 1.43.x but is NOT yet exposed by the CloudFormation
`AWS::OpenSearchServerless::CollectionGroup` resource (aws-cdk-lib 2.251.0).
boto3 can therefore reach NextGen before CloudFormation can.

The encryption policy, network policy, data-access policy and VPC endpoint stay
as native CloudFormation resources (they reference the collection by *name*, so
they do not need the collection to exist first).

Resource properties (event["ResourceProperties"]):
    ClusterId           required  - cluster id (used for naming/logging)
    CollectionName      required  - AOSS collection name (3-32 chars)
    CollectionGroupName required  - AOSS collection group name (3-32 chars)
    CollectionType      optional  - SEARCH (default) | VECTORSEARCH
    StandbyReplicas     optional  - ENABLED | DISABLED (default DISABLED)
    MaxIndexingOcu      optional  - max indexing OCUs (default 2)
    MaxSearchOcu        optional  - max search OCUs (default 2)

Response data: CollectionId, CollectionArn, CollectionEndpoint, DashboardEndpoint

Manual testing (no CloudFormation):
    # dry-run: print the boto3 calls without touching AWS (no creds needed)
    AOSS_DRY_RUN=1 python AOSSCollectionLambda.py create --cluster-id edh-test

    # real create against AWS (needs creds; NextGen scales to zero so idle cost ~0)
    python AOSSCollectionLambda.py create --cluster-id edh-test --region us-east-2
    python AOSSCollectionLambda.py delete --cluster-id edh-test --region us-east-2

Run with the bundled boto3 1.43.23 layer on PYTHONPATH so `generation` is
available, e.g.:
    PYTHONPATH=installer/resources/.lambda_layers/boto3-1.43.23/python \
        AOSS_DRY_RUN=1 python AOSSCollectionLambda.py create --cluster-id edh-test
"""

import json
import logging
import os
import time

import boto3

try:
    import cfnresponse
except ImportError:  # allows `import AOSSCollectionLambda` in unit tests w/o the helper
    cfnresponse = None

logging.getLogger().setLevel(logging.INFO)
log = logging.getLogger("aoss_collection")

# Set AOSS_DRY_RUN=1 to log intended API calls without executing them.
DRY_RUN = os.environ.get("AOSS_DRY_RUN", "") not in ("", "0", "false", "False")

# NextGen scale-to-zero: minimum OCU capacity is 0.
_MIN_OCU = 0
_DEFAULT_MAX_OCU = 2
_GENERATION = "NEXTGEN"
_ACTIVE_TIMEOUT_SECONDS = 600
_POLL_INTERVAL_SECONDS = 10

_client = None


def _aoss(region=None):
    """Lazily build (and cache) the opensearchserverless client."""
    global _client
    if _client is None:
        _client = boto3.client("opensearchserverless", region_name=region)
    return _client


def _props(event):
    p = event.get("ResourceProperties", {}) or {}
    cluster_id = p.get("ClusterId", "")
    collection_name = p.get("CollectionName") or f"{cluster_id}-analytics".lower()
    group_name = p.get("CollectionGroupName") or f"{cluster_id}-cg".lower()
    return {
        "cluster_id": cluster_id,
        "collection_name": collection_name,
        "group_name": group_name,
        "collection_type": (p.get("CollectionType") or "SEARCH").upper(),
        "standby_replicas": (p.get("StandbyReplicas") or "DISABLED").upper(),
        "max_indexing_ocu": int(p.get("MaxIndexingOcu", _DEFAULT_MAX_OCU)),
        "max_search_ocu": int(p.get("MaxSearchOcu", _DEFAULT_MAX_OCU)),
    }


def _call(client, op, **kwargs):
    """Invoke a boto3 op, or just log it under DRY_RUN."""
    if DRY_RUN:
        log.info("[DRY_RUN] %s(%s)", op, json.dumps(kwargs, default=str))
        return {}
    return getattr(client, op)(**kwargs)


def _wait_collection_active(client, name):
    """Poll until the collection is ACTIVE; raise on FAILED or timeout."""
    if DRY_RUN:
        log.info("[DRY_RUN] would wait for collection %s to become ACTIVE", name)
        return {}
    deadline = time.time() + _ACTIVE_TIMEOUT_SECONDS
    while time.time() < deadline:
        details = client.batch_get_collection(names=[name]).get(
            "collectionDetails", []
        )
        if details:
            status = details[0].get("status")
            log.info("Collection %s status=%s", name, status)
            if status == "ACTIVE":
                return details[0]
            if status in ("FAILED",):
                raise RuntimeError(f"Collection {name} entered status {status}")
        time.sleep(_POLL_INTERVAL_SECONDS)
    raise TimeoutError(
        f"Collection {name} not ACTIVE after {_ACTIVE_TIMEOUT_SECONDS}s"
    )


def create_collection(props, region=None):
    """Create the NextGen collection group + collection. Idempotent on conflict."""
    client = _aoss(region)
    # NextGen collection groups require standby replicas ENABLED (the API rejects
    # DISABLED). Scale-to-zero comes from min OCU = 0, not from standby.
    standby = "ENABLED" if _GENERATION == "NEXTGEN" else props["standby_replicas"]
    log.info(
        "Creating AOSS NextGen group=%s collection=%s (gen=%s, min=%s, maxIdx=%s, "
        "maxSearch=%s, standby=%s, type=%s)",
        props["group_name"],
        props["collection_name"],
        _GENERATION,
        _MIN_OCU,
        props["max_indexing_ocu"],
        props["max_search_ocu"],
        standby,
        props["collection_type"],
    )

    # 1) Collection group (NextGen, scale-to-zero via min OCU = 0)
    try:
        _call(
            client,
            "create_collection_group",
            name=props["group_name"],
            standbyReplicas=standby,
            description=f"{props['cluster_id']} analytics collection group",
            generation=_GENERATION,
            capacityLimits={
                "minIndexingCapacityInOCU": _MIN_OCU,
                "maxIndexingCapacityInOCU": props["max_indexing_ocu"],
                "minSearchCapacityInOCU": _MIN_OCU,
                "maxSearchCapacityInOCU": props["max_search_ocu"],
            },
        )
    except Exception as err:
        if "ConflictException" in type(err).__name__ or "already exists" in str(err):
            log.info("Collection group %s already exists, reusing", props["group_name"])
        else:
            raise

    # 2) Collection inside the group (inherits NextGen from the group)
    try:
        _call(
            client,
            "create_collection",
            name=props["collection_name"],
            type=props["collection_type"],
            description=f"{props['cluster_id']} analytics collection",
            collectionGroupName=props["group_name"],
        )
    except Exception as err:
        if "ConflictException" in type(err).__name__ or "already exists" in str(err):
            log.info("Collection %s already exists, reusing", props["collection_name"])
        else:
            raise

    details = _wait_collection_active(client, props["collection_name"])
    data = {
        "CollectionId": details.get("id", ""),
        "CollectionArn": details.get("arn", ""),
        "CollectionEndpoint": details.get("collectionEndpoint", ""),
        "DashboardEndpoint": details.get("dashboardEndpoint", ""),
    }
    log.info("Collection ready: %s", json.dumps(data, default=str))
    return data


def delete_collection(props, region=None):
    """Delete the collection then its group. Best-effort, non-fatal."""
    client = _aoss(region)
    # Resolve collection id (delete_collection keys on id, not name)
    try:
        if not DRY_RUN:
            details = client.batch_get_collection(
                names=[props["collection_name"]]
            ).get("collectionDetails", [])
            if details:
                _call(client, "delete_collection", id=details[0]["id"])
        else:
            _call(client, "delete_collection", id=f"<id-of:{props['collection_name']}>")
    except Exception as err:
        log.warning("delete_collection best-effort failure: %s", err)

    try:
        if not DRY_RUN:
            groups = client.list_collection_groups().get(
                "collectionGroupSummaries", []
            )
            gid = next(
                (g["id"] for g in groups if g.get("name") == props["group_name"]),
                None,
            )
            if gid:
                _call(client, "delete_collection_group", id=gid)
        else:
            _call(client, "delete_collection_group", id=f"<id-of:{props['group_name']}>")
    except Exception as err:
        log.warning("delete_collection_group best-effort failure: %s", err)


def lambda_handler(event, context):
    log.info("Event: %s", json.dumps(event, default=str))
    request_type = event.get("RequestType", "")
    props = _props(event)
    physical_id = props["collection_name"] or "aoss-collection"
    try:
        if request_type == "Delete":
            delete_collection(props)
            data = {}
        else:  # Create / Update
            data = create_collection(props)
        if cfnresponse:
            cfnresponse.send(
                event, context, cfnresponse.SUCCESS, data, physicalResourceId=physical_id
            )
        return data
    except Exception as err:
        log.exception("AOSSCollectionLambda failed")
        if cfnresponse:
            cfnresponse.send(
                event,
                context,
                cfnresponse.FAILED,
                {"error": str(err)},
                physicalResourceId=physical_id,
            )
        raise


# ---------------------------------------------------------------------------
# Manual test harness (not used by Lambda runtime)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Manually test AOSSCollectionLambda")
    parser.add_argument("action", choices=["create", "delete"])
    parser.add_argument("--cluster-id", required=True)
    parser.add_argument("--collection-name")
    parser.add_argument("--collection-group-name")
    parser.add_argument("--collection-type", default="SEARCH")
    parser.add_argument("--standby", default="DISABLED")
    parser.add_argument("--max-indexing", type=int, default=_DEFAULT_MAX_OCU)
    parser.add_argument("--max-search", type=int, default=_DEFAULT_MAX_OCU)
    parser.add_argument("--region", default=os.environ.get("AWS_REGION"))
    parser.add_argument(
        "--dry-run", action="store_true", help="print API calls without executing"
    )
    args = parser.parse_args()

    if args.dry_run:
        DRY_RUN = True

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    # Stub cfnresponse so the harness never tries to POST to a CFN ResponseURL.
    class _StubCfn:
        SUCCESS = "SUCCESS"
        FAILED = "FAILED"

        @staticmethod
        def send(event, context, status, data, physicalResourceId=None, **kw):
            print(f"\ncfnresponse -> {status}  physicalId={physicalResourceId}")
            print(f"responseData = {json.dumps(data, indent=2, default=str)}")

    cfnresponse = _StubCfn  # noqa: F811

    fake_event = {
        "RequestType": "Delete" if args.action == "delete" else "Create",
        "ResourceProperties": {
            "ClusterId": args.cluster_id,
            "CollectionName": args.collection_name,
            "CollectionGroupName": args.collection_group_name,
            "CollectionType": args.collection_type,
            "StandbyReplicas": args.standby,
            "MaxIndexingOcu": args.max_indexing,
            "MaxSearchOcu": args.max_search,
        },
    }
    # region threads through the lazy client
    _aoss(args.region)
    try:
        result = lambda_handler(fake_event, None)
        print(f"\nhandler returned: {json.dumps(result, indent=2, default=str)}")
    except Exception as exc:  # noqa: BLE001
        print(f"\nhandler raised: {exc}")
        sys.exit(1)
