# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Locale-aware content loader.

For user-facing prose that does not fit the gettext model — multi-paragraph
documentation, tutorials with headings and code blocks, pages that change
structurally between locales — the right storage is a per-locale Markdown
file under `web_interface/content/`, not hundreds of sentence-fragment
msgids in the gettext catalog.

File naming:
    content/<name>.<locale>.md     # preferred
    content/<name>.en.md           # required fallback

The loader picks the current locale's file and falls back to English (which
must exist). Rendered HTML is cached in-memory — content edits require a
process restart, same semantics as the compiled `.mo` files.

Usage from a Flask view:
    from helpers.content_loader import render_localized_markdown
    html = render_localized_markdown("file_transfer_guide", locale="fr")

Usage from a Jinja template:
    {{ localized_markdown("file_transfer_guide") | safe }}

See docs/I18n.md § 12.8 for guidance on WHEN to use this vs gettext.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

import markdown as _markdown

_logger = logging.getLogger(__name__)

# content/ lives next to web_interface/ — resolve relative to this file
_CONTENT_DIR = Path(__file__).resolve().parent.parent / "content"

# Extensions give us fenced code blocks, tables, footnotes, and heading anchors
# without turning on arbitrary HTML execution. `extra` is the canonical set.
_MARKDOWN_EXTENSIONS = ["extra", "sane_lists", "toc"]


def _candidate_paths(name: str, locale: str) -> list[Path]:
    """Return the ordered list of files to try for a given name+locale."""
    candidates = [f"{name}.{locale}.md"]
    # e.g. pt_BR falls back to pt if pt_BR.md isn't present
    if "_" in locale:
        candidates.append(f"{name}.{locale.split('_')[0]}.md")
    candidates.append(f"{name}.en.md")
    return [_CONTENT_DIR / c for c in candidates]


@lru_cache(maxsize=256)
def render_localized_markdown(name: str, locale: str = "en") -> str:
    """Render a Markdown file for the requested locale to HTML.

    Falls back to English if the locale-specific file is missing.
    Returns an empty string (and logs a warning) if neither is found.
    Cached per (name, locale) to avoid re-parsing on every request.
    """
    for path in _candidate_paths(name, locale):
        if path.exists():
            try:
                source = path.read_text(encoding="utf-8")
            except OSError as exc:
                _logger.warning("content_loader: failed to read %s: %s", path, exc)
                continue
            return _markdown.markdown(source, extensions=_MARKDOWN_EXTENSIONS)
    _logger.warning(
        "content_loader: no file found for name=%r locale=%r (searched %s)",
        name, locale, _CONTENT_DIR,
    )
    return ""


def list_available_content() -> list[str]:
    """Return sorted list of content-name stems (without locale/extension).
    Useful for admin inventory or debug endpoints.
    """
    if not _CONTENT_DIR.exists():
        return []
    stems: set[str] = set()
    for p in _CONTENT_DIR.glob("*.md"):
        # name.locale.md → name
        parts = p.stem.split(".")
        if len(parts) >= 2:
            stems.add(".".join(parts[:-1]))
    return sorted(stems)


def clear_cache() -> None:
    """Drop the in-memory render cache. For tests / dev hot-reload."""
    render_localized_markdown.cache_clear()
