"""Unit tests for cipher suite registry."""

from __future__ import annotations

import dataclasses

import pytest

from qasp.crypto.exceptions import UnknownCipherSuiteError
from qasp.crypto.suites import (
    CLASSICAL_SUITE_IDS,
    PQ_SUITE_IDS,
    SUITE_CLASSICAL_COMPAT,
    SUITE_HYBRID_TRANSITION,
    SUITE_PQ_STRICT,
    CipherSuite,
    CipherSuiteRegistry,
    get_default_registry,
)


class TestSuiteConstants:
    """Test suite ID constants."""

    def test_pq_strict_id(self) -> None:
        assert SUITE_PQ_STRICT == 0x0001

    def test_hybrid_transition_id(self) -> None:
        assert SUITE_HYBRID_TRANSITION == 0x0002

    def test_classical_compat_id(self) -> None:
        assert SUITE_CLASSICAL_COMPAT == 0x0003

    def test_pq_suite_ids(self) -> None:
        assert PQ_SUITE_IDS == frozenset({0x0001, 0x0002})

    def test_classical_suite_ids(self) -> None:
        assert CLASSICAL_SUITE_IDS == frozenset({0x0003})


class TestDefaultRegistry:
    """Test the default registry is pre-loaded."""

    def test_preloaded_with_three_suites(self) -> None:
        reg = get_default_registry()
        suites = reg.get_all()
        assert len(suites) == 3

    def test_lookup_pq_strict(self) -> None:
        reg = get_default_registry()
        suite = reg.lookup(SUITE_PQ_STRICT)
        assert suite.name == "PQ-Strict"
        assert suite.uses_pq_signatures is True
        assert suite.uses_hybrid_kem is False

    def test_lookup_hybrid_transition(self) -> None:
        reg = get_default_registry()
        suite = reg.lookup(SUITE_HYBRID_TRANSITION)
        assert suite.name == "Hybrid-Transition"
        assert suite.uses_hybrid_kem is True
        assert suite.uses_pq_signatures is True
        assert suite.uses_classical_signatures is True

    def test_lookup_classical_compat(self) -> None:
        reg = get_default_registry()
        suite = reg.lookup(SUITE_CLASSICAL_COMPAT)
        assert suite.name == "Classical-Compat"
        assert suite.uses_classical_signatures is True
        assert suite.uses_pq_signatures is False

    def test_lookup_unknown_raises(self) -> None:
        reg = get_default_registry()
        with pytest.raises(UnknownCipherSuiteError):
            reg.lookup(0xFFFF)

    def test_contains_registered(self) -> None:
        reg = get_default_registry()
        assert SUITE_PQ_STRICT in reg
        assert 0xFFFF not in reg


class TestIsPqCapable:
    """Test PQ capability checks."""

    def test_pq_strict_is_pq(self) -> None:
        reg = get_default_registry()
        assert reg.is_pq_capable(SUITE_PQ_STRICT) is True

    def test_hybrid_is_pq(self) -> None:
        reg = get_default_registry()
        assert reg.is_pq_capable(SUITE_HYBRID_TRANSITION) is True

    def test_classical_is_not_pq(self) -> None:
        reg = get_default_registry()
        assert reg.is_pq_capable(SUITE_CLASSICAL_COMPAT) is False


class TestCustomRegistration:
    """Test custom suite registration."""

    def test_register_custom_suite(self) -> None:
        reg = CipherSuiteRegistry()
        custom = CipherSuite(
            id=0x1000,
            name="Custom-Suite",
            kem_algorithm="CustomKEM",
            sig_algorithm="CustomSig",
        )
        reg.register(custom)
        result = reg.lookup(0x1000)
        assert result.name == "Custom-Suite"

    def test_empty_registry_raises_on_lookup(self) -> None:
        reg = CipherSuiteRegistry()
        with pytest.raises(UnknownCipherSuiteError):
            reg.lookup(0x0001)


class TestCipherSuiteFrozen:
    """Test CipherSuite is a frozen dataclass."""

    def test_frozen(self) -> None:
        suite = CipherSuite(
            id=0x0001,
            name="Test",
            kem_algorithm="KEM",
            sig_algorithm="SIG",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            suite.id = 0x0002  # type: ignore[misc]

    def test_aead_default(self) -> None:
        suite = CipherSuite(
            id=0x0001,
            name="Test",
            kem_algorithm="KEM",
            sig_algorithm="SIG",
        )
        assert suite.aead_algorithm == "AES-256-GCM"
        assert suite.kdf_algorithm == "HKDF-SHA-384"
