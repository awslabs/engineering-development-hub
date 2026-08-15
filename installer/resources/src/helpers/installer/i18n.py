# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Installer i18n setup using Python gettext."""

import gettext
import os

_LOCALE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "locale")
_DOMAIN = "installer"


def setup_i18n(lang: str | None = None) -> gettext.GNUTranslations | gettext.NullTranslations:
    """Initialize gettext for the installer. Returns the translation object."""
    if lang is None:
        lang = os.environ.get("EDH_LANG", os.environ.get("LANG", "en_US.UTF-8"))
    # Extract just the language code (e.g. "fr_FR" from "fr_FR.UTF-8")
    lang_code = lang.split(".")[0] if "." in lang else lang

    translation = gettext.translation(
        _DOMAIN,
        localedir=_LOCALE_DIR,
        languages=[lang_code, lang_code.split("_")[0], "en"],
        fallback=True,
    )
    translation.install()
    return translation


# Auto-initialize on import; _ is available globally after `from helpers.installer.i18n import _`
_translation = setup_i18n()
_ = _translation.gettext
