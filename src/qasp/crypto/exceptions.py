"""Exception hierarchy for QASP cryptographic operations.

This module defines specific exception types for different cryptographic
failure modes, enabling precise error handling without exposing key material.
"""

from __future__ import annotations

__all__ = [
    "CryptoError",
    "DecapsulationError",
    "DecryptionError",
    "EncapsulationError",
    "EncryptionError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "KeyDerivationError",
    "KeyGenerationError",
    "SignatureError",
    "VerificationError",
]


class CryptoError(Exception):
    """Base exception for all QASP cryptographic errors.

    All crypto-related exceptions inherit from this class, allowing
    callers to catch all crypto errors with a single except clause.
    """


class KeyGenerationError(CryptoError):
    """Raised when key generation fails.

    This may occur due to insufficient entropy or library initialization
    failures.
    """


class InvalidKeyError(CryptoError):
    """Raised when a key fails validation.

    This includes wrong key sizes, malformed keys, or keys that fail
    internal consistency checks.
    """


class EncapsulationError(CryptoError):
    """Raised when key encapsulation fails.

    This may occur due to invalid public keys or library errors during
    the encapsulation process.
    """


class DecapsulationError(CryptoError):
    """Raised when key decapsulation fails.

    This may occur due to invalid ciphertexts, wrong secret keys, or
    decapsulation failures detected by the KEM.
    """


class SignatureError(CryptoError):
    """Raised when signature creation fails.

    This is the base class for signature-related errors.
    """


class VerificationError(SignatureError):
    """Raised when signature verification fails due to an error.

    This indicates a failure in the verification process itself, not
    that the signature is invalid.
    """


class InvalidSignatureError(SignatureError):
    """Raised when a signature is invalid.

    This indicates the signature did not verify successfully against
    the message and public key.
    """


class KeyDerivationError(CryptoError):
    """Raised when key derivation fails.

    This may occur due to invalid input parameters or library errors.
    """


class EncryptionError(CryptoError):
    """Raised when authenticated encryption fails.

    This may occur due to invalid keys, nonces, or library errors.
    """


class DecryptionError(CryptoError):
    """Raised when authenticated decryption fails.

    This includes authentication tag verification failures, indicating
    the ciphertext was tampered with or the wrong key was used.
    """
