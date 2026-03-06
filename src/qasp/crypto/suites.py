"""Cipher suite registry for QASP.

This module defines the cipher suite registry with 16-bit IDs and
pre-loaded suites for post-quantum, hybrid, and classical modes.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from qasp.crypto.exceptions import UnknownCipherSuiteError

__all__ = [
    "CLASSICAL_SUITE_IDS",
    "CipherSuite",
    "CipherSuiteRegistry",
    "PQ_SUITE_IDS",
    "SUITE_CLASSICAL_COMPAT",
    "SUITE_HYBRID_TRANSITION",
    "SUITE_PQ_STRICT",
    "get_default_registry",
]

# Suite ID constants (16-bit)
SUITE_PQ_STRICT = 0x0001  # ML-KEM-768 + ML-DSA-65
SUITE_HYBRID_TRANSITION = 0x0002  # X25519+ML-KEM-768 + Ed25519+ML-DSA-65
SUITE_CLASSICAL_COMPAT = 0x0003  # X25519 + Ed25519

PQ_SUITE_IDS: frozenset[int] = frozenset({SUITE_PQ_STRICT, SUITE_HYBRID_TRANSITION})
CLASSICAL_SUITE_IDS: frozenset[int] = frozenset({SUITE_CLASSICAL_COMPAT})


@dataclass(frozen=True)
class CipherSuite:
    """A cipher suite definition.

    Attributes:
        id: 16-bit suite ID.
        name: Human-readable name.
        kem_algorithm: KEM algorithm name.
        sig_algorithm: Signature algorithm name.
        aead_algorithm: AEAD algorithm name.
        kdf_algorithm: KDF algorithm name.
        uses_hybrid_kem: Whether the suite uses hybrid KEM (X25519+ML-KEM).
        uses_pq_signatures: Whether the suite uses PQ signatures (ML-DSA).
        uses_classical_signatures: Whether the suite uses classical signatures (Ed25519).
    """

    id: int
    name: str
    kem_algorithm: str
    sig_algorithm: str
    aead_algorithm: str = "AES-256-GCM"
    kdf_algorithm: str = "HKDF-SHA-384"
    uses_hybrid_kem: bool = False
    uses_pq_signatures: bool = False
    uses_classical_signatures: bool = False


# Pre-defined suites
_PQ_STRICT = CipherSuite(
    id=SUITE_PQ_STRICT,
    name="PQ-Strict",
    kem_algorithm="ML-KEM-768",
    sig_algorithm="ML-DSA-65",
    uses_pq_signatures=True,
)

_HYBRID_TRANSITION = CipherSuite(
    id=SUITE_HYBRID_TRANSITION,
    name="Hybrid-Transition",
    kem_algorithm="X25519+ML-KEM-768",
    sig_algorithm="Ed25519+ML-DSA-65",
    uses_hybrid_kem=True,
    uses_pq_signatures=True,
    uses_classical_signatures=True,
)

_CLASSICAL_COMPAT = CipherSuite(
    id=SUITE_CLASSICAL_COMPAT,
    name="Classical-Compat",
    kem_algorithm="X25519",
    sig_algorithm="Ed25519",
    uses_classical_signatures=True,
)


class CipherSuiteRegistry:
    """Thread-safe registry for cipher suites.

    Provides lookup of cipher suite definitions by their 16-bit ID.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._suites: dict[int, CipherSuite] = {}

    def register(self, suite: CipherSuite) -> None:
        """Register a cipher suite.

        Args:
            suite: The cipher suite to register.
        """
        with self._lock:
            self._suites[suite.id] = suite

    def lookup(self, suite_id: int) -> CipherSuite:
        """Look up a cipher suite by ID.

        Args:
            suite_id: The 16-bit suite ID.

        Returns:
            The cipher suite definition.

        Raises:
            UnknownCipherSuiteError: If the suite ID is not registered.
        """
        with self._lock:
            suite = self._suites.get(suite_id)
        if suite is None:
            raise UnknownCipherSuiteError(f"Unknown cipher suite: 0x{suite_id:04x}")
        return suite

    def get_all(self) -> list[CipherSuite]:
        """Return all registered cipher suites."""
        with self._lock:
            return list(self._suites.values())

    def is_pq_capable(self, suite_id: int) -> bool:
        """Check if a suite ID is post-quantum capable."""
        return suite_id in PQ_SUITE_IDS

    def __contains__(self, suite_id: int) -> bool:
        """Check if a suite ID is registered."""
        with self._lock:
            return suite_id in self._suites


# Module-level singleton
_default_registry: CipherSuiteRegistry | None = None
_registry_lock = threading.Lock()


def get_default_registry() -> CipherSuiteRegistry:
    """Get the default cipher suite registry singleton.

    Pre-loaded with PQ-Strict, Hybrid-Transition, and Classical-Compat suites.

    Returns:
        The shared CipherSuiteRegistry instance.
    """
    global _default_registry
    if _default_registry is None:
        with _registry_lock:
            if _default_registry is None:
                reg = CipherSuiteRegistry()
                reg.register(_PQ_STRICT)
                reg.register(_HYBRID_TRANSITION)
                reg.register(_CLASSICAL_COMPAT)
                _default_registry = reg
    return _default_registry
