"""QASP Auditor service.

Provides standalone dispute resolution, receipt chain verification,
and fault attribution.
"""

from .fault import (
    FLAG_EVIDENCE_TAMPERING,
    FLAG_METERING_FAULT,
    FLAG_SYSTEMATIC_OVERCHARGE,
    FLAG_SYSTEMATIC_UNDERREPORT,
    FaultAttributor,
    FaultRecord,
    FaultType,
)
from .service import AuditorService

__all__ = [
    "FLAG_EVIDENCE_TAMPERING",
    "FLAG_METERING_FAULT",
    "FLAG_SYSTEMATIC_OVERCHARGE",
    "FLAG_SYSTEMATIC_UNDERREPORT",
    "AuditorService",
    "FaultAttributor",
    "FaultRecord",
    "FaultType",
]
