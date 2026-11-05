# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
from commands.common import print_output, is_controller_instance
from utils.cache.client import SocaCacheClient
import sys
import json


def cache_client(is_admin: bool = False) -> SocaCacheClient:
    if is_admin:
        if is_controller_instance():
            return SocaCacheClient(is_admin=True)
        else:
            print_output(
                f"This command can only be executed from the SOCA controller host",
                error=True,
            )
    else:
        return SocaCacheClient(is_admin=False)


def check_protected_keys(key: str):
    _protected_str = ["/configuration", "/system", "/packages"]
    for path in _protected_str:
        if path in key:
            print_output(
                "Cannot modify protected keys. To update the cache for this key, modify 'config' first.",
                error=True,
            )
    else:
        return False


@click.group()
def cache():
    """Inspect and modify the controller's configuration cache."""
    pass


@cache.command()
@click.option(
    "-k",
    "--key",
    required=True,
    help="Specify a SOCA configuration key or configuration tree",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
def get(key, output):
    """Read a key from the cache."""
    _q = cache_client().get(key=key).get("message")
    if _q == "CACHE_MISS":
        print_output("Key not found in cache", error=True)
    else:
        if isinstance(_q, bytes):
            print_output(str(_q), output=output)
        else:
            print_output(_q.decode(), output=output)


@cache.command()
@click.option(
    "-k",
    "--key",
    required=True,
    help="Specify a SOCA configuration key or configuration tree",
)
@click.option(
    "-v",
    "--value",
    required=True,
    help="Update Cache key value",
)
@click.option(
    "-e",
    "--expire",
    type=int,
    default=86400,
    help="Optional: Set Expiration",
)
def set(key, value, expire, called_from="config"):
    """Write a key to the cache with an optional expiry."""
    if called_from == "config":
        _q = cache_client(is_admin=True).set(key=key, value=value, ex=expire)
    else:
        if not check_protected_keys(key):
            _q = cache_client(is_admin=True).set(key=key, value=value, ex=expire)

    print_output("Cache updated")


@cache.command()
@click.option(
    "-k",
    "--key",
    required=True,
    help="Specify a SOCA configuration key or configuration tree",
)
def delete(key):
    """Remove a key from the cache."""
    _q = cache_client(is_admin=True).delete(key=key)
    print_output("Key deleted from cache")


@cache.command()
@click.option(
    "-p",
    "--pattern",
    required=True,
    help="Filter specific keys, for example: soca*",
)
def scan(pattern):
    """List cache keys matching a pattern."""
    _q = cache_client(is_admin=True).scan(match_pattern=pattern)
    print_output(_q.get("message"))
