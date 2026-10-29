"""Registry and manager for malware configuration decoders."""

from typing import Any

from .agent_tesla import AgentTeslaDecoder
from .asyncrat import AsyncRATDecoder
from .base import FamilyConfigDecoder
from .cobalt_strike import CobaltStrikeDecoder
from .redline import RedLineDecoder
from .remcos import RemcosDecoder

_REGISTERED_DECODERS: list[FamilyConfigDecoder] = [
    AgentTeslaDecoder(),
    CobaltStrikeDecoder(),
    RemcosDecoder(),
    AsyncRATDecoder(),
    RedLineDecoder(),
]


def register_decoder(decoder: FamilyConfigDecoder) -> None:
    """Register a new configuration decoder plugin."""
    _REGISTERED_DECODERS.append(decoder)


def run_family_decoders(data: bytes, metadata: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Execute all registered family decoders against sample bytes.

    Returns only decoders that successfully verified structural fingerprints
    and decrypted configuration parameters. Never returns guesses.
    """
    results: list[dict[str, Any]] = []
    meta = metadata or {}

    for decoder in _REGISTERED_DECODERS:
        try:
            if decoder.can_decode(data, meta):
                cfg = decoder.decode(data, meta)
                if cfg:
                    results.append(cfg)
        except Exception:
            continue

    return results
