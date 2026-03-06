"""Budget-aware metering wrapper.

This module wraps the base Meter to enforce a budget ceiling,
suspending metering when the budget is exhausted.
"""

from __future__ import annotations

from enum import Enum, auto

from qasp.protocol.accounting import Meter, Receipt, UsageRecord

__all__ = [
    "BudgetExhaustedError",
    "BudgetMeter",
    "MeterStatus",
]


class MeterStatus(Enum):
    """Status of a budget meter."""

    ACTIVE = auto()
    SUSPENDED = auto()


class BudgetExhaustedError(Exception):
    """Raised when the budget has been exhausted."""


class BudgetMeter:
    """A metering wrapper that enforces a budget ceiling.

    Delegates to an inner Meter but tracks cumulative units and
    raises BudgetExhaustedError when the budget is reached.
    """

    def __init__(self, meter: Meter, budget: int) -> None:
        self._meter = meter
        self._budget = budget
        self._cumulative_units = 0
        self._status = MeterStatus.ACTIVE

    @property
    def status(self) -> MeterStatus:
        return self._status

    @property
    def cumulative_units(self) -> int:
        return self._cumulative_units

    @property
    def budget(self) -> int:
        return self._budget

    def record(
        self,
        resource: str,
        operation: str,
        units: int = 1,
    ) -> UsageRecord:
        if self._status == MeterStatus.SUSPENDED:
            raise BudgetExhaustedError(
                f"Budget exhausted ({self._cumulative_units}/{self._budget})"
            )
        usage = self._meter.record(resource, operation, units)
        self._cumulative_units += units
        if self._cumulative_units >= self._budget:
            self._status = MeterStatus.SUSPENDED
        return usage

    def generate_receipt(
        self,
        signing_key: bytes,
        prev_hash: bytes = b"",
    ) -> Receipt:
        return self._meter.generate_receipt(signing_key, prev_hash)
