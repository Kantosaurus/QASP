"""Identity management for QASP.

This module implements:
- did:qasp decentralized identifiers for AI agent identity
- Owner-agent binding for authorization
- X.509-PQ certificate integration
"""

from qasp.identity.binding import (
    OwnerBinding,
    Permission,
    attenuate_binding,
    create_owner_binding,
    verify_binding_chain,
    verify_owner_binding,
)
from qasp.identity.did import (
    DID,
    DIDDocument,
    DIDRegistry,
    VerificationMethod,
    create_did,
    decode_public_key_multibase,
    encode_public_key_multibase,
    get_registry,
    resolve_did,
    verify_did,
    verify_did_signature,
)
from qasp.identity.exceptions import (
    BindingError,
    BindingExpiredError,
    BindingPermissionError,
    DIDError,
    DIDResolutionError,
    IdentityError,
    InvalidBindingError,
    InvalidDIDError,
)

__all__ = [
    "DID",
    "BindingError",
    "BindingExpiredError",
    "BindingPermissionError",
    "DIDDocument",
    "DIDError",
    "DIDRegistry",
    "DIDResolutionError",
    "IdentityError",
    "InvalidBindingError",
    "InvalidDIDError",
    "OwnerBinding",
    "Permission",
    "VerificationMethod",
    "attenuate_binding",
    "create_did",
    "create_owner_binding",
    "decode_public_key_multibase",
    "encode_public_key_multibase",
    "get_registry",
    "resolve_did",
    "verify_binding_chain",
    "verify_did",
    "verify_did_signature",
    "verify_owner_binding",
]
