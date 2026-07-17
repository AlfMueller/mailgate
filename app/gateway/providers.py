# SPDX-License-Identifier: AGPL-3.0-only

from dataclasses import dataclass

GENERIC_IMAPS = "generic_imaps"
HOSTPOINT = "hostpoint"


@dataclass(frozen=True)
class ProviderPreset:
    key: str
    label: str
    preset_version: int
    imap_host: str | None
    imap_port: int = 993
    default_authserv_ids: tuple[str, ...] = ()


PROVIDER_PRESETS = {
    GENERIC_IMAPS: ProviderPreset(
        key=GENERIC_IMAPS,
        label="Generic IMAPS",
        preset_version=1,
        imap_host=None,
    ),
    HOSTPOINT: ProviderPreset(
        key=HOSTPOINT,
        label="Hostpoint",
        preset_version=1,
        imap_host="imap.mail.hostpoint.ch",
    ),
}


def provider_choices() -> tuple[tuple[str, str], ...]:
    return tuple((preset.key, preset.label) for preset in PROVIDER_PRESETS.values())


def get_provider_preset(key: str) -> ProviderPreset:
    try:
        return PROVIDER_PRESETS[key]
    except KeyError as exc:
        raise ValueError("Unknown mail provider preset") from exc


def effective_imap_host(preset: ProviderPreset, configured_host: str) -> str:
    return preset.imap_host or configured_host
