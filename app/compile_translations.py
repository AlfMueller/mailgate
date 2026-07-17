#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import ast
import re
import struct
from pathlib import Path

PLACEHOLDER_RE = re.compile(r"%\([^)]+\)[a-zA-Z]|{[A-Za-z_][A-Za-z0-9_]*}")


def _placeholders(value: str) -> set[str]:
    return set(PLACEHOLDER_RE.findall(value))


def _quoted(value: str) -> str:
    parsed = ast.literal_eval(value)
    if not isinstance(parsed, str):
        raise ValueError("PO value must be a quoted string")
    return parsed


def read_catalog(path: Path) -> dict[str, str]:
    messages: dict[str, str] = {}
    msgid: list[str] | None = None
    msgstr: list[str] | None = None
    section = ""
    fuzzy = False
    pending_fuzzy = False

    def commit() -> None:
        nonlocal msgid, msgstr, section, fuzzy
        if msgid is not None and msgstr is not None and not fuzzy:
            key = "".join(msgid)
            value = "".join(msgstr)
            if key and value and _placeholders(key) != _placeholders(value):
                raise ValueError(f"Placeholder mismatch for {key!r} in {path}")
            if key == "" or value:
                messages[key] = value
        msgid = None
        msgstr = None
        section = ""
        fuzzy = False

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("#,") and "fuzzy" in line:
            pending_fuzzy = True
        elif line.startswith("msgctxt ") or line.startswith("msgid_plural "):
            raise ValueError(f"Unsupported plural/context entry in {path}")
        elif line.startswith("msgid "):
            commit()
            fuzzy = pending_fuzzy
            pending_fuzzy = False
            msgid = [_quoted(line[6:])]
            msgstr = []
            section = "msgid"
        elif line.startswith("msgstr "):
            if msgid is None:
                raise ValueError(f"msgstr without msgid in {path}")
            msgstr = [_quoted(line[7:])]
            section = "msgstr"
        elif line.startswith('"'):
            if section == "msgid" and msgid is not None:
                msgid.append(_quoted(line))
            elif section == "msgstr" and msgstr is not None:
                msgstr.append(_quoted(line))
        elif not line:
            commit()
    commit()
    return messages


def compile_catalog(messages: dict[str, str]) -> bytes:
    keys = sorted(messages)
    encoded_keys = [key.encode("utf-8") for key in keys]
    encoded_values = [messages[key].encode("utf-8") for key in keys]
    count = len(keys)
    key_table_offset = 7 * 4
    value_table_offset = key_table_offset + count * 8
    key_data_offset = value_table_offset + count * 8
    key_data = b"".join(value + b"\0" for value in encoded_keys)
    value_data_offset = key_data_offset + len(key_data)
    value_data = b"".join(value + b"\0" for value in encoded_values)
    output = [
        struct.pack(
            "<7I",
            0x950412DE,
            0,
            count,
            key_table_offset,
            value_table_offset,
            0,
            0,
        )
    ]
    offset = key_data_offset
    for value in encoded_keys:
        output.append(struct.pack("<2I", len(value), offset))
        offset += len(value) + 1
    offset = value_data_offset
    for value in encoded_values:
        output.append(struct.pack("<2I", len(value), offset))
        offset += len(value) + 1
    output.extend((key_data, value_data))
    return b"".join(output)


def main() -> int:
    locale_root = Path(__file__).resolve().parent / "locale"
    catalogs = sorted(locale_root.glob("*/LC_MESSAGES/django.po"))
    if not catalogs:
        raise SystemExit(f"No translation catalogs found under {locale_root}")
    for po_path in catalogs:
        mo_path = po_path.with_suffix(".mo")
        mo_path.write_bytes(compile_catalog(read_catalog(po_path)))
        print(f"Compiled {po_path.relative_to(locale_root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
