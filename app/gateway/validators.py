# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import re

from django.utils.translation import gettext_lazy as _

AUTHSERV_ID_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z"
)


def normalise_authserv_ids(value: str) -> str:
    if not value.strip():
        return ""
    items = [item.strip().lower() for item in value.split(",")]
    if any(not item or not AUTHSERV_ID_RE.fullmatch(item) for item in items):
        raise ValueError(
            _(
                "Use comma-separated DNS-style authserv IDs. Spaces around commas are allowed; "
                "spaces inside an ID and control characters are not."
            )
        )
    return ",".join(dict.fromkeys(items))
