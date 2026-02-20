"""Usage metering and accounting.

This module implements usage tracking and receipt generation
for QASP connections.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

__all__ = [
    "Meter",
    "Receipt",
    "UsageRecord",
]


@dataclass(frozen=True)
class UsageRecord:
    """A record of resource usage."""

    resource: str
    operation: str
    units: int
    timestamp: datetime
    session_id: bytes


@dataclass(frozen=True)
class Receipt:
    """A signed usage receipt."""

    records: list[UsageRecord]
    total_units: int
    issued_at: datetime
    issuer: str
    signature: bytes


class Meter:
    """Usage metering for a QASP session."""

    def __init__(self, session_id: bytes) -> None:
        """Initialize the meter.

        Args:
            session_id: The session identifier.
        """
        self._session_id = session_id
        self._records: list[UsageRecord] = []

    def record(
        self,
        resource: str,
        operation: str,
        units: int = 1,
    ) -> UsageRecord:
        """Record usage of a resource.

        Args:
            resource: The resource being used.
            operation: The operation performed.
            units: The number of units consumed.

        Returns:
            The usage record.
        """
        raise NotImplementedError("Metering implementation pending")

    def generate_receipt(self, signing_key: bytes) -> Receipt:
        """Generate a signed receipt for all recorded usage.

        Args:
            signing_key: The key to sign the receipt.

        Returns:
            A signed Receipt.
        """
        raise NotImplementedError("Metering implementation pending")

    @property
    def total_units(self) -> int:
        """Return the total units recorded."""
        return sum(r.units for r in self._records)
