# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for utils.user_pref_store -- DDB CRUD + the 3-tier resolver.

Off-cluster: a FakeDDB stands in for the low-level DynamoDB client (monkeypatched
onto ``store._ddb``) and the SSM tier-2 seam (``store._read_ssm``) is stubbed.
No AWS, no network.

Run:  python3 -m pytest utils/test_user_pref_store.py -v
"""

import logging

import pytest

from utils import user_pref_store as store


# ---------------------------------------------------------------------------
# Fake low-level DynamoDB client
# ---------------------------------------------------------------------------
class FakeDDB:
    """Minimal in-memory stand-in for the boto3 low-level dynamodb client.

    Storage: ``self.items[username] = {attr: ddb_attr_map}``. Supports the four
    operations the store uses (get_item, update_item SET/REMOVE, delete_item,
    paginated scan).
    """

    def __init__(self):
        self.items = {}
        self.scan_pages = None  # optional canned pagination for all_usernames

    def get_item(self, TableName, Key, ConsistentRead=False):
        uname = Key["username"]["S"]
        item = self.items.get(uname)
        return {"Item": dict(item)} if item is not None else {}

    def update_item(self, TableName, Key, UpdateExpression,
                    ExpressionAttributeNames, ExpressionAttributeValues=None):
        uname = Key["username"]["S"]
        item = self.items.setdefault(uname, {"username": {"S": uname}})
        # resolve the single #k placeholder
        attr = ExpressionAttributeNames["#k"]
        if UpdateExpression.startswith("SET"):
            item[attr] = ExpressionAttributeValues[":v"]
        elif UpdateExpression.startswith("REMOVE"):
            item.pop(attr, None)
        else:  # pragma: no cover
            raise AssertionError(f"unexpected expr {UpdateExpression}")

    def delete_item(self, TableName, Key):
        self.items.pop(Key["username"]["S"], None)

    def scan(self, **kwargs):
        if self.scan_pages is not None:
            # serve canned pages keyed by ExclusiveStartKey presence
            start = kwargs.get("ExclusiveStartKey")
            idx = 0 if start is None else start["_i"]
            return self.scan_pages[idx]
        items = [{"username": {"S": u}} for u in self.items]
        return {"Items": items}


@pytest.fixture
def fake(monkeypatch):
    f = FakeDDB()
    monkeypatch.setattr(store, "_ddb", lambda: f)
    # default: no admin SSM value unless a test overrides it
    monkeypatch.setattr(store, "_read_ssm", lambda key: None)
    return f


# ---------------------------------------------------------------------------
# encode / decode helpers
# ---------------------------------------------------------------------------
def test_to_ddb_value():
    assert store._to_ddb_value("bool", True) == {"BOOL": True}
    assert store._to_ddb_value("int", 7) == {"N": "7"}
    assert store._to_ddb_value("enum", "fr") == {"S": "fr"}
    assert store._to_ddb_value("string", "hi") == {"S": "hi"}


def test_from_ddb_value():
    assert store._from_ddb_value({"BOOL": False}) is False
    assert store._from_ddb_value({"N": "3"}) == 3
    assert store._from_ddb_value({"S": "fr"}) == "fr"
    assert store._from_ddb_value({"NULL": True}) is None


# ---------------------------------------------------------------------------
# get_raw_row
# ---------------------------------------------------------------------------
def test_get_raw_row_empty(fake):
    assert store._get_raw_row("nobody") == {}


def test_get_raw_row_filters_to_catalog_keys(fake):
    fake.items["jsmith"] = {
        "username": {"S": "jsmith"},
        "language": {"S": "fr"},
        "vdi_tile_masking": {"BOOL": True},
        "stray_attr": {"S": "ignored"},  # not a catalog key -> filtered out
    }
    assert store._get_raw_row("jsmith") == {"language": "fr", "vdi_tile_masking": True}


# ---------------------------------------------------------------------------
# resolver: 3 tiers + self-healing
# ---------------------------------------------------------------------------
def test_resolve_tier1_user_value(fake):
    fake.items["jsmith"] = {"username": {"S": "jsmith"}, "language": {"S": "fr"}}
    r = store.resolve_pref("jsmith", "language").message
    assert r["value"] == "fr"
    assert r["is_set"] is True
    assert r["source"] == "user"
    assert "fr" in r["allowed"]


def test_resolve_tier3_code_default_no_row(fake):
    # no row, no SSM admin default -> code default
    r = store.resolve_pref("newbie", "vdi_tile_masking").message
    assert r["value"] is False
    assert r["is_set"] is False
    assert r["source"] == "default"


def test_resolve_tier2_admin_default(fake, monkeypatch):
    # SSM org default DIFFERS from the shipped code default (false) -> admin
    monkeypatch.setattr(store, "_read_ssm", lambda key: "true")
    r = store.resolve_pref("newbie", "vdi_tile_masking").message
    assert r["value"] is True
    assert r["is_set"] is False
    assert r["source"] == "admin"


def test_resolve_seeded_default_reports_source_default(fake, monkeypatch):
    # SSM holds the install-time seed == shipped code default (false). This
    # carries no admin intent, so it must resolve as source="default", NOT
    # "admin" -- "admin" is reserved for a genuine org-default deviation.
    monkeypatch.setattr(store, "_read_ssm", lambda key: "false")
    r = store.resolve_pref("newbie", "vdi_tile_masking").message
    assert r["value"] is False
    assert r["is_set"] is False
    assert r["source"] == "default"


def test_resolve_self_heals_invalid_stored_value(fake, caplog):
    # stored an enum value that is no longer valid -> treated as absent
    fake.items["jsmith"] = {"username": {"S": "jsmith"}, "language": {"S": "xx"}}
    with caplog.at_level(logging.WARNING, logger="soca_logger"):
        r = store.resolve_pref("jsmith", "language").message
    assert r["value"] == "en"          # fell through to code default
    assert r["is_set"] is False
    assert r["source"] == "default"
    assert any("self-healing" in rec.message for rec in caplog.records)


def test_resolve_invalid_admin_default_falls_to_code(fake, monkeypatch, caplog):
    # SSM holds garbage for a bool -> ignored, fall to code default False
    monkeypatch.setattr(store, "_read_ssm", lambda key: "banana")
    with caplog.at_level(logging.WARNING, logger="soca_logger"):
        r = store.resolve_pref("newbie", "vdi_tile_masking").message
    assert r["value"] is False
    assert r["source"] == "default"


def test_resolve_all_returns_every_key(fake):
    out = store.resolve_all("newbie").message
    assert set(out.keys()) == set(store.catalog._all_keys())
    assert out["language"]["value"] == "en"
    assert out["vdi_tile_masking"]["value"] is False


# ---------------------------------------------------------------------------
# writes
# ---------------------------------------------------------------------------
def test_set_pref_valid_persists(fake):
    r = store.set_pref("jsmith", "vdi_tile_masking", True)
    assert r.success is True
    assert r.message is True
    assert fake.items["jsmith"]["vdi_tile_masking"] == {"BOOL": True}


def test_set_pref_creates_sparse_row(fake):
    # writing one pref creates the item with ONLY that attribute (+ PK)
    store.set_pref("fresh", "language", "ja")
    assert set(fake.items["fresh"].keys()) == {"username", "language"}
    assert fake.items["fresh"]["language"] == {"S": "ja"}


def test_set_pref_invalid_rejected_no_write(fake):
    r = store.set_pref("jsmith", "language", "xx")
    assert r.success is False
    assert r.status_code == 400
    assert "jsmith" not in fake.items  # nothing written


def test_set_pref_unknown_key_rejected(fake):
    r = store.set_pref("jsmith", "bogus", "x")
    assert r.success is False
    assert r.status_code == 400


def test_clear_pref_removes_attribute(fake):
    fake.items["jsmith"] = {
        "username": {"S": "jsmith"},
        "language": {"S": "fr"},
        "vdi_tile_masking": {"BOOL": True},
    }
    r = store.clear_pref("jsmith", "language")
    assert r.success is True
    assert "language" not in fake.items["jsmith"]
    assert "vdi_tile_masking" in fake.items["jsmith"]  # untouched


def test_clear_pref_unknown_key_rejected(fake):
    r = store.clear_pref("jsmith", "bogus")
    assert r.success is False
    assert r.status_code == 400


def test_clear_all_deletes_row(fake):
    fake.items["jsmith"] = {"username": {"S": "jsmith"}, "language": {"S": "fr"}}
    r = store.clear_all("jsmith")
    assert r.success is True
    assert "jsmith" not in fake.items


# ---------------------------------------------------------------------------
# maintenance: paginated scan
# ---------------------------------------------------------------------------
def test_all_usernames_paginates(fake):
    fake.scan_pages = [
        {"Items": [{"username": {"S": "a"}}, {"username": {"S": "b"}}],
         "LastEvaluatedKey": {"_i": 1}},
        {"Items": [{"username": {"S": "c"}}]},  # no LastEvaluatedKey -> stop
    ]
    assert store.all_usernames().message == ["a", "b", "c"]
