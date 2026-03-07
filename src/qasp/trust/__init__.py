"""Trust scoring and verification.

This module implements the QASP trust framework:
- Audit certification (VCs)
- Trust registry
- Bayesian reputation scoring
- Behavioral verification
- Composite trust scoring
"""

from qasp.trust.behavioral import (
    BehaviorDistribution,
    BehaviorState,
    BehavioralVerifier,
    CapabilityManifest,
    DriftDetector,
    create_manifest,
    is_permitted_transition,
    verify_manifest,
)
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
    BehavioralError,
    CertificationError,
    DuplicateEntryError,
    EntryNotFoundError,
    InvalidProofError,
    InvalidSLSALevelError,
    InvalidTransitionError,
    InvalidVCError,
    ManifestError,
    RegistryError,
    ReputationError,
    TrustError,
    VCExpiredError,
    VCNotYetValidError,
)
from qasp.trust.registry import (
    InMemoryRegistryBackend,
    RegistryBackend,
    SQLiteRegistryBackend,
    TrustEntry,
    TrustRegistry,
    get_trust_registry,
)
from qasp.trust.reputation import (
    ReputationModel,
    ReputationScore,
    WitnessReport,
    aggregate_witness_reports,
)
from qasp.trust.scoring import (
    TrustScore,
    TrustScorer,
    detect_collusion,
)

__all__ = [
    "QASP_AUDIT_CONTEXT",
    "VC_CONTEXT",
    "AuditCredentialSubject",
    "AuditVC",
    "BehaviorDistribution",
    "BehaviorState",
    "BehavioralError",
    "BehavioralVerifier",
    "CapabilityManifest",
    "DriftDetector",
    "CertificationError",
    "DuplicateEntryError",
    "EntryNotFoundError",
    "InMemoryRegistryBackend",
    "InvalidProofError",
    "InvalidSLSALevelError",
    "InvalidTransitionError",
    "InvalidVCError",
    "MLDSAProof",
    "ManifestError",
    "RegistryBackend",
    "RegistryError",
    "ReputationError",
    "ReputationModel",
    "ReputationScore",
    "SLSALevel",
    "SQLiteRegistryBackend",
    "TrustEntry",
    "TrustError",
    "TrustRegistry",
    "TrustScore",
    "TrustScorer",
    "VCExpiredError",
    "VCNotYetValidError",
    "WitnessReport",
    "aggregate_witness_reports",
    "behavioral",
    "certification",
    "create_audit_vc",
    "create_manifest",
    "detect_collusion",
    "exceptions",
    "get_trust_registry",
    "is_permitted_transition",
    "registry",
    "reputation",
    "scoring",
    "verify_audit_vc",
    "verify_manifest",
]
