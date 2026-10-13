"""Plugin interface for family-specific malware configuration decoders.

Every decoder must:
1. Declare the exact family name and target versions.
2. Verify structural markers via can_decode().
3. Return None or a structured result containing verified C2 endpoints, keys,
   and campaign identifiers. Guessing is prohibited.
"""

from abc import ABC, abstractmethod
from typing import Any


class FamilyConfigDecoder(ABC):
    """Abstract base class for malware configuration decoders."""

    family_name: str = "Unknown"
    target_version: str = "1.0"
    author: str = "OutPost Security Engineering"
    description: str = "Family-specific malware configuration extractor"

    @abstractmethod
    def can_decode(self, data: bytes, metadata: dict[str, Any]) -> bool:
        """Return True only if binary satisfies explicit family structural fingerprints."""
        raise NotImplementedError

    @abstractmethod
    def decode(self, data: bytes, metadata: dict[str, Any]) -> dict[str, Any] | None:
        """Extract and decrypt family configuration. Returns None if decoding fails."""
        raise NotImplementedError
