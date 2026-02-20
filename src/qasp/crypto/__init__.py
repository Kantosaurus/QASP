"""Post-quantum cryptography primitives.

This module provides wrappers for NIST-standardized post-quantum algorithms:
- ML-KEM-768 for key encapsulation
- ML-DSA-65 for digital signatures
- Hybrid X25519 + ML-KEM-768 for defense in depth
- HKDF-SHA-384 for key derivation
- AES-256-GCM for authenticated encryption
"""

__all__ = [
    "aead",
    "certificates",
    "hybrid",
    "kdf",
    "kem",
    "signatures",
]
