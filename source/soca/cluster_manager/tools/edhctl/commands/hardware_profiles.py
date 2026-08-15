# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
edhctl hardware-profile / usb-profile -- operational CLI for the Hardware
Profile feature (USB device allowlists).

Follows the established edhctl pattern of DIRECT data-store access (as
`userprefs` does for DynamoDB): it assembles the same Aurora connection the web
tier uses -- from the /configuration/Database/* SSM keys + DatabaseAdminSecret
-- and runs read/operational SQL. No Flask app context and no web-tier config
import (which would resolve the DB URI at import time).

Scope is intentionally operational: list / show / resolve (preview) / bind.
Authoring profiles and entries (with the 8-field validation) lives in the
admin WebUI + REST API, not here.
"""

import logging
import sys
from urllib.parse import quote_plus

import click

from commands.common import confirm, is_controller_instance, print_output
from utils.config import SocaConfig
from utils.aws.secretsmanager_client import SocaSecret

logger = logging.getLogger("soca_logger")

_AURORA_PROVIDER = "aurora_serverless_v2"


def _fail(message):
    print_output(message, error=True)
    sys.exit(1)


def _db_connection():
    """Open a direct SQLAlchemy connection to Aurora (controller-only).

    Assembles the URI the same way web_interface/config.py does. Exits with a
    clear message if the feature's DB provider is not Aurora or creds/SSM are
    unavailable. Returns an open Connection (caller closes / uses `with`).
    """
    if not is_controller_instance():
        _fail("hardware-profile commands must be run on the controller instance.")

    _provider = (
        SocaConfig(key="/configuration/Database/provider").get_value().get("message")
    )
    if _provider != _AURORA_PROVIDER:
        _fail(
            f"Hardware Profiles require the Aurora database provider "
            f"(found: {_provider}). Nothing to query."
        )

    _endpoint = (
        SocaConfig(key="/configuration/Database/endpoint").get_value().get("message")
    )
    _port = SocaConfig(key="/configuration/Database/port").get_value().get("message")
    _name = SocaConfig(key="/configuration/Database/name").get_value().get("message")
    if not (_endpoint and _port and _name):
        _fail("Database endpoint/port/name SSM keys are not set.")

    _secret = SocaSecret(secret_id="DatabaseAdminSecret").get_secret()
    if not _secret.success:
        _fail(f"Unable to read DatabaseAdminSecret: {_secret.message}")
    _creds = _secret.message
    _user = _creds.get("username")
    _password = _creds.get("password")
    if not (_user and _password):
        _fail("DatabaseAdminSecret is missing username/password.")

    try:
        from sqlalchemy import create_engine

        _uri = (
            f"postgresql+psycopg://{_user}:{quote_plus(_password)}"
            f"@{_endpoint}:{_port}/{_name}?sslmode=require"
        )
        _engine = create_engine(_uri, pool_pre_ping=True)
        return _engine.connect()
    except Exception as err:
        _fail(f"Unable to connect to the database: {err}")


def _render_filter_line(row) -> str:
    """Render a (label, class-triple, vid, pid, autoshare, skip_reset) row."""
    label, base_class, sub_class, protocol, vid, pid, autoshare, skip_reset = row
    return "{},{},{},{},{},{},{},{}".format(
        label, base_class, sub_class, protocol, vid, pid,
        1 if autoshare else 0, 1 if skip_reset else 0,
    )


@click.group(name="hardware-profile")
def hardware_profile():
    """Manage EDH Hardware Profiles (USB device allowlist bindings)."""
    pass


@hardware_profile.command(name="list")
@click.option("--output", default="text", help="text | json | yaml")
@click.pass_context
def hp_list(ctx, output):
    """List active Hardware Profiles."""
    from sqlalchemy import text

    with _db_connection() as conn:
        rows = conn.execute(
            text(
                "SELECT id, profile_name, description, usb_profile_id "
                "FROM hardware_profiles WHERE is_active = true ORDER BY id"
            )
        ).fetchall()
    result = [
        {
            "id": r[0],
            "profile_name": r[1],
            "description": r[2],
            "usb_profile_id": r[3],
        }
        for r in rows
    ]
    print_output(result if output != "text" else _format_table(result), output=output)


@hardware_profile.command(name="show")
@click.argument("hp_id", type=int)
@click.option("--output", default="json", help="text | json | yaml")
@click.pass_context
def hp_show(ctx, hp_id, output):
    """Show a Hardware Profile, its USB sub-profile entries, and bindings."""
    from sqlalchemy import text

    with _db_connection() as conn:
        hp = conn.execute(
            text(
                "SELECT id, profile_name, description, usb_profile_id "
                "FROM hardware_profiles WHERE id = :id AND is_active = true"
            ),
            {"id": hp_id},
        ).fetchone()
        if hp is None:
            _fail(f"HardwareProfile {hp_id} not found")
        entries = []
        if hp[3] is not None:
            entries = [
                _render_filter_line(r)
                for r in conn.execute(
                    text(
                        "SELECT device_label, base_class, sub_class, protocol, vid, "
                        "pid, support_autoshare, skip_reset FROM usb_profile_entries "
                        "WHERE usb_profile_id = :up ORDER BY id"
                    ),
                    {"up": hp[3]},
                ).fetchall()
            ]
        stacks = [
            r[0]
            for r in conn.execute(
                text("SELECT id FROM software_stacks WHERE hardware_profile_id = :id"),
                {"id": hp_id},
            ).fetchall()
        ]
        projects = [
            r[0]
            for r in conn.execute(
                text("SELECT id FROM projects WHERE hardware_profile_id = :id"),
                {"id": hp_id},
            ).fetchall()
        ]
    print_output(
        {
            "id": hp[0],
            "profile_name": hp[1],
            "description": hp[2],
            "usb_profile_id": hp[3],
            "usb_devices_conf": entries,
            "bound_software_stack_ids": stacks,
            "bound_project_ids": projects,
        },
        output=output,
    )


@hardware_profile.command(name="resolve")
@click.option("--stack", "software_stack_id", type=int, required=True, help="Software Stack id")
@click.option("--project", "project_id", type=int, default=None, help="Project id (optional)")
@click.option("--output", default="text", help="text | json | yaml")
@click.pass_context
def hp_resolve(ctx, software_stack_id, project_id, output):
    """Preview the effective usb-devices.conf for a Stack (+ optional Project).

    Applies Project-over-Stack resolution -- the same logic the boot-time
    resolver Lambda uses.
    """
    from sqlalchemy import text

    _sql = text(
        "SELECT e.device_label, e.base_class, e.sub_class, e.protocol, e.vid, "
        "e.pid, e.support_autoshare, e.skip_reset "
        "FROM software_stacks st "
        "LEFT JOIN projects p ON p.id = :pid AND p.is_active = true "
        "JOIN hardware_profiles hp "
        "  ON hp.id = COALESCE(p.hardware_profile_id, st.hardware_profile_id) "
        "  AND hp.is_active = true "
        "JOIN usb_profiles up ON up.id = hp.usb_profile_id AND up.is_active = true "
        "JOIN usb_profile_entries e ON e.usb_profile_id = up.id "
        "WHERE st.id = :sid ORDER BY e.id"
    )
    with _db_connection() as conn:
        rows = conn.execute(_sql, {"sid": software_stack_id, "pid": project_id}).fetchall()
    lines = [_render_filter_line(r) for r in rows]
    if output == "text":
        print_output("\n".join(lines) if lines else "(empty allowlist -- DCV defaults)")
    else:
        print_output({"lines": lines}, output=output)


@hardware_profile.command(name="bind")
@click.option("--stack", "software_stack_id", type=int, default=None)
@click.option("--project", "project_id", type=int, default=None)
@click.option("--profile", "hp_id", type=int, default=None, help="HardwareProfile id to bind")
@click.option("--clear", is_flag=True, help="Clear the binding instead of setting it")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@click.pass_context
def hp_bind(ctx, software_stack_id, project_id, hp_id, clear, yes):
    """Bind (or --clear) a Hardware Profile on a Software Stack or Project."""
    from sqlalchemy import text

    if (software_stack_id is None) == (project_id is None):
        _fail("Specify exactly one of --stack or --project.")
    if not clear and hp_id is None:
        _fail("Specify --profile <id> to bind, or --clear to remove the binding.")

    _target_table = "software_stacks" if software_stack_id is not None else "projects"
    _target_id = software_stack_id if software_stack_id is not None else project_id
    _value = None if clear else hp_id
    _desc = "clear" if clear else f"bind HardwareProfile {hp_id}"
    if not yes and not confirm(f"About to {_desc} on {_target_table} {_target_id}."):
        print_output("Aborted.")
        return

    with _db_connection() as conn:
        if _value is not None:
            _hp = conn.execute(
                text("SELECT id FROM hardware_profiles WHERE id = :id AND is_active = true"),
                {"id": _value},
            ).fetchone()
            if _hp is None:
                _fail(f"HardwareProfile {_value} not found or inactive")
        _res = conn.execute(
            text(
                f"UPDATE {_target_table} SET hardware_profile_id = :hp WHERE id = :id"
            ),
            {"hp": _value, "id": _target_id},
        )
        conn.commit()
        if _res.rowcount == 0:
            _fail(f"{_target_table} {_target_id} not found")
    print_output(f"OK: {_desc} on {_target_table} {_target_id}")


@click.group(name="usb-profile")
def usb_profile():
    """Inspect EDH USB device allowlist profiles."""
    pass


@usb_profile.command(name="list")
@click.option("--output", default="text", help="text | json | yaml")
@click.pass_context
def usb_list(ctx, output):
    """List active USB profiles."""
    from sqlalchemy import text

    with _db_connection() as conn:
        rows = conn.execute(
            text(
                "SELECT p.id, p.profile_name, p.description, COUNT(e.id) "
                "FROM usb_profiles p "
                "LEFT JOIN usb_profile_entries e ON e.usb_profile_id = p.id "
                "WHERE p.is_active = true GROUP BY p.id ORDER BY p.id"
            )
        ).fetchall()
    result = [
        {"id": r[0], "profile_name": r[1], "description": r[2], "entry_count": r[3]}
        for r in rows
    ]
    print_output(result if output != "text" else _format_table(result), output=output)


@usb_profile.command(name="show")
@click.argument("profile_id", type=int)
@click.option("--output", default="text", help="text | json | yaml")
@click.pass_context
def usb_show(ctx, profile_id, output):
    """Show a USB profile's rendered usb-devices.conf lines."""
    from sqlalchemy import text

    with _db_connection() as conn:
        prof = conn.execute(
            text("SELECT profile_name FROM usb_profiles WHERE id = :id AND is_active = true"),
            {"id": profile_id},
        ).fetchone()
        if prof is None:
            _fail(f"UsbProfile {profile_id} not found")
        rows = conn.execute(
            text(
                "SELECT device_label, base_class, sub_class, protocol, vid, pid, "
                "support_autoshare, skip_reset FROM usb_profile_entries "
                "WHERE usb_profile_id = :id ORDER BY id"
            ),
            {"id": profile_id},
        ).fetchall()
    lines = [_render_filter_line(r) for r in rows]
    if output == "text":
        print_output(
            f"# {prof[0]}\n" + ("\n".join(lines) if lines else "(no entries)")
        )
    else:
        print_output({"profile_name": prof[0], "lines": lines}, output=output)


def _format_table(rows: list) -> str:
    """Minimal text rendering for list output."""
    if not rows:
        return "(none)"
    _cols = list(rows[0].keys())
    _lines = ["  ".join(_cols)]
    for r in rows:
        _lines.append("  ".join(str(r.get(c, "")) for c in _cols))
    return "\n".join(_lines)
