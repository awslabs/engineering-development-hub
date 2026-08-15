# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for utils.user_pref_catalog -- the code-side preference catalog and
its single validator. Pure: no AWS, no DDB, no Flask request context.

Run:  python3 -m pytest utils/test_user_pref_catalog.py -v
"""

from utils import user_pref_catalog as catalog


# --- introspection helpers --------------------------------------------------
def test_all_keys_contains_v1_prefs():
    keys = catalog._all_keys()
    assert "language" in keys
    assert "vdi_tile_masking" in keys
    assert "show_session_uuid_tile" in keys


def test_is_known():
    assert catalog._is_known("language") is True
    assert catalog._is_known("vdi_tile_masking") is True
    assert catalog._is_known("show_session_uuid_tile") is True
    assert catalog._is_known("not_a_pref") is False


def test_spec_and_default_for():
    assert catalog._spec("language")["type"] == "enum"
    assert catalog._spec("vdi_tile_masking")["type"] == "bool"


def test_show_session_uuid_tile_is_bool_default_false():
    assert catalog._spec("show_session_uuid_tile")["type"] == "bool"
    assert catalog._default_for("show_session_uuid_tile") is False
    assert catalog._spec("nope") is None
    assert catalog._default_for("vdi_tile_masking") is False
    assert catalog._default_for("language") == "en"
    assert catalog._default_for("nope") is None


def test_allowed_values_resolves_language_callable():
    allowed = catalog._allowed_values("language")
    # off-cluster -> static fallback mirror of app.LANGUAGES keys
    assert "en" in allowed
    assert "fr" in allowed
    assert "ja" in allowed
    # non-enum / unknown -> None
    assert catalog._allowed_values("vdi_tile_masking") is None
    assert catalog._allowed_values("nope") is None


# --- validation: unknown key ------------------------------------------------
def test_validate_unknown_key_is_400():
    r = catalog.validate("bogus_key", "x")
    assert r.success is False
    assert r.status_code == 400
    assert "unknown preference key" in r.message


# --- validation: bool -------------------------------------------------------
def test_validate_bool_native():
    assert catalog.validate("vdi_tile_masking", True).message is True
    assert catalog.validate("vdi_tile_masking", False).message is False


def test_validate_bool_from_string():
    assert catalog.validate("vdi_tile_masking", "true").message is True
    assert catalog.validate("vdi_tile_masking", "false").message is False


def test_validate_bool_rejects_garbage():
    r = catalog.validate("vdi_tile_masking", "banana")
    assert r.success is False
    assert r.status_code == 400


# --- validation: enum -------------------------------------------------------
def test_validate_enum_member_ok():
    r = catalog.validate("language", "fr")
    assert r.success is True
    assert r.message == "fr"


def test_validate_enum_non_member_rejected():
    r = catalog.validate("language", "xx")
    assert r.success is False
    assert r.status_code == 400
    assert "not in allowed values" in r.message


# --- the two early-adopter prefs ---------------------------------------------
def test_default_landing_page_enum():
    assert catalog._spec("default_landing_page")["type"] == "enum"
    assert catalog._default_for("default_landing_page") == "home"
    assert "virtual_desktops" in catalog._allowed_values("default_landing_page")
    assert catalog.validate("default_landing_page", "my_account").message == "my_account"
    assert catalog.validate("default_landing_page", "nope").success is False


def test_vdi_cards_per_row_int_range():
    assert catalog._spec("vdi_cards_per_row")["type"] == "int"
    assert catalog._default_for("vdi_cards_per_row") == 3
    assert catalog.validate("vdi_cards_per_row", 4).message == 4
    assert catalog.validate("vdi_cards_per_row", "2").message == 2   # coerced
    assert catalog.validate("vdi_cards_per_row", 0).success is False  # below min 1
    assert catalog.validate("vdi_cards_per_row", 7).success is False  # above max 6


# --- validation: synthetic int / string prefs (exercise constraint paths) ---
def test_validate_int_range(monkeypatch):
    monkeypatch.setitem(
        catalog.PREFERENCES, "_t_int", {"type": "int", "default": 1, "min": 0, "max": 5}
    )
    assert catalog.validate("_t_int", 3).message == 3
    assert catalog.validate("_t_int", "4").message == 4  # coerced
    assert catalog.validate("_t_int", -1).success is False
    assert catalog.validate("_t_int", 6).success is False


def test_validate_string_constraints(monkeypatch):
    monkeypatch.setitem(
        catalog.PREFERENCES,
        "_t_str",
        {"type": "string", "default": "", "maxlen": 4, "pattern": r"[a-z]+"},
    )
    assert catalog.validate("_t_str", "abc").message == "abc"
    assert catalog.validate("_t_str", "toolong").success is False  # maxlen
    assert catalog.validate("_t_str", "AB").success is False  # pattern
