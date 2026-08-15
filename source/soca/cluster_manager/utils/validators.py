# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class Validators:
    @staticmethod
    def _return(name: str, result: bool, *args) -> bool:
        logger.debug(f"{name} {args}: {result}")
        return result

    @staticmethod
    def exist(value: Any) -> bool:
        return Validators._return("exist", value is not None, value)

    @staticmethod
    def is_string(value: Any) -> bool:
        return Validators._return("is_string", isinstance(value, str), value)

    @staticmethod
    def is_string_equal(value: Any, other: str) -> bool:
        return Validators._return("is_string_equal", isinstance(value, str) and value == other, value, other)

    @staticmethod
    def _string_len_check(value: Any, predicate, number: int, name: str) -> bool:
        # number -> expected length
        result = isinstance(value, str) and predicate(len(value), number)
        return Validators._return(name, result, value, number)

    @staticmethod
    def is_string_length_equal_of(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a == b, number, "is_string_length_equal_of"
        )

    @staticmethod
    def is_string_length_not_equal_of(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a != b, number, "is_string_length_not_equal_of"
        )

    @staticmethod
    def is_string_length_greater_than(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a > b, number, "is_string_length_greater_than"
        )

    @staticmethod
    def is_string_length_greater_equal_than(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a >= b, number, "is_string_length_greater_equal_than"
        )

    @staticmethod
    def is_string_length_lower_than(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a < b, number, "is_string_length_lower_than"
        )

    @staticmethod
    def is_string_length_lower_equal_than(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a <= b, number, "is_string_length_lower_equal_than"
        )

    @staticmethod
    def is_int(value: Any) -> bool:
        return Validators._return(
            "is_int", isinstance(value, int) and not isinstance(value, bool), value
        )

    @staticmethod
    def is_float(value: Any) -> bool:
        return Validators._return("is_float", isinstance(value, float), value)

    @staticmethod
    def is_bool(value: Any) -> bool:
        return Validators._return("is_bool", isinstance(value, bool), value)

    @staticmethod
    def is_bytes(value: Any) -> bool:
        return Validators._return("is_bytes", isinstance(value, bytes), value)

    @staticmethod
    def is_list(value: Any) -> bool:
        return Validators._return("is_list", isinstance(value, list), value)

    @staticmethod
    def is_dict(value: Any) -> bool:
        return Validators._return("is_dict", isinstance(value, dict), value)

    # list len() helper
    @staticmethod
    def _list_len_check(value: Any, predicate, number: int, name: str) -> bool:
        # number -> expected length

        result = isinstance(value, list) and predicate(len(value), number)
        return Validators._return(name, result, value, number)

    @staticmethod
    def is_list_length_equal_of(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a == b, number, "is_list_length_equal_of"
        )

    @staticmethod
    def is_list_length_not_equal_of(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a != b, number, "is_list_length_not_equal_of"
        )

    @staticmethod
    def is_list_length_greater_than(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a > b, number, "is_list_length_greater_than"
        )

    @staticmethod
    def is_list_length_greater_equal_than(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a >= b, number, "is_list_length_greater_equal_than"
        )

    @staticmethod
    def is_list_length_lower_than(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a < b, number, "is_list_length_lower_than"
        )

    @staticmethod
    def is_list_length_lower_equal_than(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a <= b, number, "is_list_length_lower_equal_than"
        )

    @staticmethod
    def is_list_not_empty(value: Any) -> bool:
        return Validators._return(
            "is_list_not_empty", isinstance(value, list) and bool(value), value
        )

    @staticmethod
    def is_dict_not_empty(value: Any) -> bool:
        return Validators._return(
            "is_dict_not_empty", isinstance(value, dict) and bool(value), value
        )

    @staticmethod
    def is_string_not_empty(value: Any) -> bool:
        return Validators._return(
            "is_string_not_empty", isinstance(value, str) and bool(value), value
        )

    @staticmethod
    def is_positive_int(value: Any) -> bool:
        return Validators._return(
            "is_positive_int",
            isinstance(value, int) and not isinstance(value, bool) and value > 0,
            value,
        )

    @staticmethod
    def is_non_negative_int(value: Any) -> bool:
        return Validators._return(
            "is_non_negative_int",
            isinstance(value, int) and not isinstance(value, bool) and value >= 0,
            value,
        )

    @staticmethod
    def is_int_greater_than(value: int, other: int) -> bool:
        return Validators._return("is_int_greater_than", value > other, value, other)

    @staticmethod
    def is_int_greater_or_equal(value: int, other: int) -> bool:
        return Validators._return("is_int_greater_or_equal", value >= other, value, other)

    @staticmethod
    def is_int_equal(value: int, other: int) -> bool:
        return Validators._return("is_int_equal", value == other, value, other)

    @staticmethod
    def is_int_lower_than(value: int, other: int) -> bool:
        return Validators._return("is_int_lower_than", value < other, value, other)

    @staticmethod
    def is_int_lower_or_equal(value: int, other: int) -> bool:
        return Validators._return("is_int_lower_or_equal", value <= other, value, other)

    @staticmethod
    def is_datetime(value: Any) -> bool:
        return Validators._return("is_datetime", isinstance(value, datetime), value)

    @staticmethod
    def is_future_datetime(value: Any) -> bool:
        return Validators._return(
            "is_future_datetime",
            isinstance(value, datetime) and value > datetime.now(),
            value,
        )

    @staticmethod
    def is_past_datetime(value: Any) -> bool:
        return Validators._return(
            "is_past_datetime",
            isinstance(value, datetime) and value < datetime.now(),
            value,
        )


# ---------------------------------------------------------------------------
# File-content heuristics
# ---------------------------------------------------------------------------
# Kept as a module-level function rather than a Validators staticmethod
# because it operates on a file path (doing I/O) rather than on an
# in-memory value, so it doesn't fit the Validators predicate shape. It
# lives here so it can be shared by views/tail.py and any future consumer
# (e.g. views/editor.py) that needs to guard against streaming a binary
# payload to the browser.
def is_binary_file(path: str, sample: int = 1024) -> bool:
    """
    Heuristic: is this file binary enough that streaming it to the browser
    would be useless or garbage?

    Strategy:
      1. If we can't open it, treat as binary (can't tail/edit anyway).
      2. NUL byte anywhere in the sample => binary (ELF, zip, gz, etc.)
      3. Try UTF-8 decode of the sample. If it decodes, it's text. This
         correctly handles non-ASCII text (accents, CJK, emoji) that the
         older byte-fraction heuristic falsely rejected.
      4. When reading a chunk from disk, the last few bytes may slice
         through a multi-byte UTF-8 codepoint; we trim up to 3 trailing
         bytes to avoid false negatives on otherwise-valid UTF-8.
      5. If UTF-8 decode fails (Latin-1 / legacy encodings / actual
         binary), fall back to the original byte-fraction heuristic. A
         file with >30% non-printable bytes is treated as binary.
    """
    try:
        with open(path, "rb") as f:
            data = f.read(sample)
    except OSError:
        return True
    if not data:
        return False
    if b"\x00" in data:
        return True

    # Trim potentially-split trailing codepoint. UTF-8 multi-byte
    # sequences: lead bytes are 0xC0..0xFD, continuation bytes are
    # 0x80..0xBF. If the sample ends mid-sequence we could get a false
    # "binary" verdict on otherwise-valid UTF-8. Walk back up to 3 bytes
    # to find the start of the last (possibly incomplete) codepoint and
    # drop it if it's incomplete.
    trimmed = data
    _trimmed_length = len(trimmed)
    if _trimmed_length >= 4 and trimmed[-1] >= 0x80:
        # Find the most recent lead byte by walking back over continuations.
        lead_idx = _trimmed_length - 1
        while lead_idx > _trimmed_length - 4 and trimmed[lead_idx] < 0xC0:
            lead_idx -= 1
        lead = trimmed[lead_idx]
        if lead >= 0xC0:
            # Expected total length of the codepoint starting at lead_idx.
            if   lead < 0xE0: expected = 2
            elif lead < 0xF0: expected = 3
            else:             expected = 4
            actual = _trimmed_length - lead_idx
            if actual < expected:
                trimmed = trimmed[:lead_idx]

    try:
        trimmed.decode("utf-8")
        return False
    except UnicodeDecodeError:
        pass

    # Latin-1-ish fallback: count non-printable bytes.
    text_chars = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    non_printable = sum(1 for b in data if b not in text_chars)
    return non_printable / len(data) > 0.30
