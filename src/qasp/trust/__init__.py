"""Trust scoring and verification.

This module implements the QASP trust framework:
- Audit certification (VCs)
- Trust registry
- Bayesian reputation scoring
- Behavioral verification
"""

from qasp.trust.certification import (
    QASP_AUDIT_CONTEXT,
    VC_CONTEXT,
    AuditCredentialSubject,
    AuditVC,
    MLDSAProof,
    SLSALevel,
    create_audit_vc,
    verify_audit_vc,
)
from qasp.trust.exceptions import (
    CertificationError,
    DuplicateEntryError,
    EntryNotFoundError,
    InvalidProofError,
    InvalidSLSALevelError,
    InvalidVCError,
    RegistryError,
    TrustError,
    VCExpiredError,
    VCNotYetValidError,
)
from qasp.trust.registry import (
    TrustEntry,
    TrustRegistry,
    get_trust_registry,
)

__all__ = [
    "QASP_AUDIT_CONTEXT",
    "VC_CONTEXT",
    "AuditCredentialSubject",
    "AuditVC",
    "CertificationError",
    "DuplicateEntryError",
    "EntryNotFoundError",
    "InvalidProofError",
    "InvalidSLSALevelError",
    "InvalidVCError",
    "MLDSAProof",
    "RegistryError",
    "SLSALevel",
    "TrustEntry",
    "TrustError",
    "TrustRegistry",
    "VCExpiredError",
    "VCNotYetValidError",
    "behavioral",
    "certification",
    "create_audit_vc",
    "exceptions",
    "get_trust_registry",
    "registry",
    "reputation",
    "scoring",
    "verify_audit_vc",
]
