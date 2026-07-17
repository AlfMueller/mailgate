# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import string

from django.utils.translation import gettext_lazy as _

DNS_LABEL_CHARACTERS = frozenset(string.ascii_letters + string.digits + "-")
DNS_EDGE_CHARACTERS = frozenset(string.ascii_letters + string.digits)


def _valid_authserv_id(value: str) -> bool:
    if not 1 <= len(value) <= 253:
        return False
    labels = value.split(".")
    return all(
        1 <= len(label) <= 63
        and label[0] in DNS_EDGE_CHARACTERS
        and label[-1] in DNS_EDGE_CHARACTERS
        and all(character in DNS_LABEL_CHARACTERS for character in label)
        for label in labels
    )


def normalise_authserv_ids(value: str) -> str:
    if not value.strip():
        return ""
    items = [item.strip().lower() for item in value.split(",")]
    if len(value) > 500 or any(not _valid_authserv_id(item) for item in items):
        raise ValueError(
            _(
                "Use comma-separated DNS-style authserv IDs. Spaces around commas are allowed; "
                "spaces inside an ID and control characters are not."
            )
        )
    return ",".join(dict.fromkeys(items))
