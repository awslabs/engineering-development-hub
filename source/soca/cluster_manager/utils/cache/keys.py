# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Cache key construction for @soca_cache.

A key is built from two parts that have DIFFERENT jobs, and keeping them apart is
the whole design:

    edh:webui:aws:ec2:get_ec2_quota_value:f=b7603911:quota_code=L-F7808C92:#h=<64 hex>
    |-------------- prefix -------------|:|-- fn --|:|----- label -----|:|- identity -|

IDENTITY is the sha256 of a canonical encoding of (module, qualname, arguments),
and it is on EVERY key. Two calls share a key if and only if their canonical
encodings are equal, so injectivity is a property of the encoding and the hash
rather than of any text formatting done here.

LABEL is decoration. It exists so an operator can recognise an entry in
`cache scan` output and so a key carries its own meaning in a log line:

    edhctl cache scan   -p '*get_ec2_quota_value*'
    edhctl cache delete -k <key copied from the scan>

Because the identity segment is always present, a label that were ever ambiguous
could not cause a wrong cache hit. That is the correction this module needed. The
previous version made the READABLE TEXT the identity, which put two requirements
in direct conflict: readability demanded a restricted character set, a restricted
set demanded a lossy mapping, and a lossy mapping is exactly what destroys
injectivity. Six distinct collision classes shipped from that one decision --
empty containers sharing a rendering, an in-band element separator a string could
contain, a dict pair separator that was itself a safe character, lossy
sanitization of unsafe characters, type collapse of dict keys, and a reused
separator at every nesting depth with no depth encoding. Each was patched
individually; the structure kept producing more.

So the label is now emitted ONLY when it cannot be ambiguous, by construction
rather than by escaping: every argument must be a string or an int whose text
consists solely of _LABEL_SAFE characters. Anything else -- a container, an
object, a space, a separator, a glob metacharacter -- drops the label entirely and
leaves the key as prefix, function tag and identity. There is nothing to escape,
no lossy mapping and no nesting, so the classes of bug above are unrepresentable
rather than tested for.

Canonical encoding uses JSON, a format with a real parser, instead of a
hand-rolled delimiter scheme. Every value becomes a type-tagged JSON array, so
nesting is delimited structurally and no value can impersonate another's
structure. `tests/cache_keys/test_cache_key_canonical.py` decodes the encoding
back to the original value and compares it type-aware, which is the check the old
format could not pass because no decoder for it could exist.

Consequences worth knowing:

  - Keys are longer, and an operator copies one from `cache scan` rather than
    retyping it from memory. That is the price of identity that cannot be lost.
  - A set and a frozenset with the same members, and a list and a tuple with the
    same elements, now get DIFFERENT keys. The previous version conflated them
    deliberately for hit rate; that conflation is dropped because it is a
    judgement call sitting on the correctness boundary, and every caller in the
    tree passes a consistent type.
  - An argument whose type is not a JSON primitive or container is encoded from
    its repr, so two distinct instances of a class with a constant repr share a
    key. Every cached function in the tree takes str or list[str].
  - A self-referential argument raises RecursionError rather than being encoded
    ambiguously. Failing loudly is the safe direction on this boundary.

Scoping is unchanged: SocaCacheClient.key_fqdn() prepends /edh/<cluster>/ to
everything below, so two clusters sharing one Valkey never collide. The prefix
passed by each caller is the second scoping level and should stay namespaced
(edh:<area>:<name>) for the same reason.
"""

import hashlib
import json

from utils.validators import Validators

# Characters allowed in a label. Glob metacharacters (* ? [ ]) are excluded because
# `cache scan` is pattern-based and a key containing them cannot be matched
# reliably. The structural characters of the key format (":" and "=") are excluded
# so a label cannot introduce a segment, and "#" is excluded so no label can
# reproduce the identity marker.
_LABEL_SAFE = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@-"
)

# Structural characters of the key itself. Neither is in _LABEL_SAFE.
_SEGMENT_SEPARATOR = ":"
_NAME_SEPARATOR = "="

# Beyond this a key stops being something an operator can work with in a terminal,
# so the label is dropped and only the identity is kept. Redis itself allows far
# longer keys. The bound covers the WHOLE key including the identity segment.
MAX_KEY_LENGTH = 200

# Marker prefixing the identity digest. "#" is not in _LABEL_SAFE, so no argument
# name or value can render into it; the identity is also always the LAST segment,
# so the marker is protected by position as well as by charset.
DIGEST_MARKER = "#h"

# Marker prefixing the function tag, which is on every key so two cached functions
# sharing a prefix cannot serve each other's payloads.
FUNCTION_MARKER = "f"

# Bumped whenever the canonical encoding below changes meaning. It is part of the
# hashed input, so a bump deliberately invalidates every existing entry rather
# than letting two encodings share a key space.
_CANONICAL_VERSION = "v2"


def _dumps(encoded) -> str:
    """
    One deterministic JSON spelling for an already-canonical structure.

    sort_keys is set for completeness; the encoder emits arrays rather than
    objects, so ordering is decided before this point. ensure_ascii keeps the
    byte sequence identical regardless of the interpreter's default.
    """
    return json.dumps(encoded, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def _canonical(value):
    """
    Encode a value as a type-tagged JSON structure, injectively.

    Every branch emits [type_name, payload...], and containers nest their
    elements' encodings rather than joining rendered text. JSON arrays carry their
    own delimiters, so "end of inner list" and "next outer element" are distinct
    without a separator convention -- which is precisely what the previous
    flattening could not express: [["a","b"]] and [["a"],"b"] both flattened to
    l:l:a|b and shared a cache entry.

    Type is compared with `type(value) is`, not isinstance(), so a subclass is
    encoded as an object instead of silently taking a primitive's branch, and
    bool cannot be mistaken for int.

    This is the one place in the module that does NOT test type with Validators,
    and the exemption is measured rather than preferred. Validators is
    isinstance-based throughout, so with these branches on Validators.is_string a
    str subclass and the plain string carrying the same text produce a
    byte-identical key -- a wrong-TYPE hit, and a seventh collision class in the
    module whose contract is injectivity. Two named tests fail under that swap.
    Validators also has no is_tuple, is_set, is_frozenset or is_bytearray at all,
    is_list rejects tuples and is_bytes rejects bytearray, so four branches below
    have no equivalent even setting the subclass problem aside.

    _label() DOES use Validators, because a label is decoration: two values that
    share a label still key differently, since identity is computed here.
    """
    if value is None:
        return ["none"]

    _type = type(value)

    if _type is bool:
        return ["bool", "true" if value else "false"]
    if _type is int:
        # repr() rather than the JSON number, so arbitrary precision survives and
        # the spelling does not depend on the JSON encoder's float handling.
        return ["int", repr(value)]
    if _type is float:
        return ["float", repr(value)]
    if _type is str:
        # JSON quotes and escapes this, so no content can forge structure.
        return ["str", value]
    if _type is bytes:
        return ["bytes", value.hex()]
    if _type is bytearray:
        return ["bytearray", bytes(value).hex()]
    if _type is list:
        return ["list", [_canonical(_item) for _item in value]]
    if _type is tuple:
        return ["tuple", [_canonical(_item) for _item in value]]
    if _type in (set, frozenset):
        # Sorted on the ENCODED element, so a set built in a different order gets
        # the same key while remaining injective: the sorted multiset of element
        # encodings determines the set.
        return [
            "frozenset" if _type is frozenset else "set",
            sorted(_dumps(_canonical(_item)) for _item in value),
        ]
    if _type is dict:
        # Keys are encoded too, not str()'d: rendering keys with str() collapsed
        # type and let {1: "a"} and {"1": "a"} share an entry. Sorting on the
        # encoded key is total, because distinct keys encode distinctly.
        return [
            "dict",
            sorted(
                ([_dumps(_canonical(_k)), _canonical(value[_k])] for _k in value),
                key=lambda _pair: _pair[0],
            ),
        ]

    # Last resort. Documented in the module docstring as the one residual way two
    # distinct values can share a key: a class whose repr does not distinguish its
    # instances. The type name is included so two different classes with the same
    # repr text stay apart.
    return ["object", f"{_type.__module__}.{_type.__qualname__}", repr(value)]


def _digest(module: str, qualname: str, arguments: dict) -> str:
    """
    The key's identity: sha256 over the canonical encoding of the whole call.

    Not pickle, which the first version used: pickle.DEFAULT_PROTOCOL is 4 on
    python 3.13 and 5 on 3.14, so an interpreter upgrade silently orphaned every
    entry in the cache.
    """
    return hashlib.sha256(
        _dumps(
            [_CANONICAL_VERSION, module, qualname, _canonical(arguments)]
        ).encode("utf-8")
    ).hexdigest()


def _function_tag(module: str, qualname: str) -> str:
    """
    Short readable identity for the cached FUNCTION, folded into every key.

    Redundant against the digest, which already covers module and qualname, and
    kept for operability: it lets an operator tell two functions' entries apart in
    `cache scan` output without decoding anything.
    """
    return hashlib.sha256(f"{module}:{qualname}".encode("utf-8")).hexdigest()[:8]


def _is_label_safe(text: str) -> bool:
    """
    Whether text can appear in a label verbatim. Empty text is refused so an empty
    string argument cannot produce a bare "name=" that reads as a missing value.
    """
    if not text:
        return False
    for _char in text:
        if _char not in _LABEL_SAFE:
            return False
    return True


def _label(arguments: dict) -> str:
    """
    Human-readable summary of the arguments, or None when they cannot be shown
    verbatim.

    Deliberately narrow: strings and ints only, and only when every character is
    already safe. There is no escaping and no substitution, so nothing here can be
    lossy -- the question is only whether the arguments can be shown AS THEY ARE.
    Since the identity segment carries correctness, declining to label costs
    nothing but legibility.

    Type is tested with Validators here, per the repo's validation guideline, and
    NOT with the exact `type(v) is` that _canonical requires. The distinction is
    what the two functions produce: _canonical produces identity, so admitting a
    subclass there would merge it with its primitive and serve the wrong payload,
    while a label is decorative and can be shared by two values that key
    differently. Validators.is_int excludes bool, so a bool still declines the
    label rather than rendering as an ambiguous 1.
    """
    _parts = []
    for _name in arguments:
        _value = arguments[_name]

        if Validators.is_string(_value):
            _text = _value
        elif Validators.is_int(_value):
            _text = repr(_value)
        else:
            return None

        if not _is_label_safe(_name) or not _is_label_safe(_text):
            return None

        _parts.append(f"{_name}{_NAME_SEPARATOR}{_text}")

    if not _parts:
        return None
    return _SEGMENT_SEPARATOR.join(_parts)


def build_cache_key(prefix: str, module: str, qualname: str, arguments: dict) -> str:
    """
    The cache key for one call: prefix, function tag, optional label, identity.

    The identity segment is last and always present, so a key can be read
    left to right from most human-meaningful to most precise, and truncating the
    label can never change which entry is addressed.
    """
    _tag = f"{FUNCTION_MARKER}{_NAME_SEPARATOR}{_function_tag(module, qualname)}"
    _identity = (
        f"{DIGEST_MARKER}{_NAME_SEPARATOR}{_digest(module, qualname, arguments)}"
    )
    _unlabelled = _SEGMENT_SEPARATOR.join([prefix, _tag, _identity])

    _label_text = _label(arguments)
    if _label_text is None:
        return _unlabelled

    _labelled = _SEGMENT_SEPARATOR.join([prefix, _tag, _label_text, _identity])
    # Per the repo's validation guideline rather than a bare len() comparison.
    if Validators.is_string_length_lower_equal_than(_labelled, MAX_KEY_LENGTH):
        return _labelled
    return _unlabelled
