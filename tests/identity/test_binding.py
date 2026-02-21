"""Tests for owner-agent binding."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from qasp.identity import (
    DID,
    Permission,
    attenuate_binding,
    create_owner_binding,
    verify_binding_chain,
    verify_owner_binding,
)
from qasp.identity.binding import OwnerBinding
from qasp.identity.exceptions import (
    BindingExpiredError,
    BindingPermissionError,
    InvalidBindingError,
)


class TestOwnerBinding:
    """Tests for binding creation and structure."""

    def test_create_binding(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """Can create a basic owner binding."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        assert binding.agent_did == sample_agent_did
        assert binding.owner_did == sample_owner_did
        assert Permission.COMM_INITIATE.value in binding.permissions

    def test_binding_has_signature(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """Binding has a signature."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        assert binding.signature is not None
        assert len(binding.signature) > 0

    def test_binding_has_timestamps(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """Binding has created and expiry timestamps."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        assert binding.created is not None
        assert binding.expiry is not None
        assert binding.expiry > binding.created

    def test_binding_has_nonce(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """Binding has a random nonce."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        assert binding.nonce is not None
        assert len(binding.nonce) == 16

    def test_binding_custom_validity(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """Can set custom validity period."""
        validity = 3600  # 1 hour
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
            validity_seconds=validity,
        )
        expected_expiry = binding.created + timedelta(seconds=validity)
        # Allow small time difference
        assert abs((binding.expiry - expected_expiry).total_seconds()) < 1

    def test_binding_to_cbor(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """Binding can be serialized to CBOR."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        cbor_data = binding.to_cbor()
        assert isinstance(cbor_data, bytes)
        assert len(cbor_data) > 0

    def test_binding_compute_hash(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """Binding hash is computed correctly."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        hash1 = binding.compute_hash()
        hash2 = binding.compute_hash()
        assert hash1 == hash2  # Deterministic
        assert len(hash1) == 48  # SHA-384


class TestBindingVerification:
    """Tests for binding verification."""

    def test_verify_valid_binding(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
        owner_public_key: bytes,
    ) -> None:
        """Valid binding verifies successfully."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        assert verify_owner_binding(binding, owner_public_key)

    def test_verify_with_wrong_key_fails(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
        agent_public_key: bytes,  # Wrong key
    ) -> None:
        """Verification fails with wrong public key."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        with pytest.raises(InvalidBindingError) as exc_info:
            verify_owner_binding(binding, agent_public_key)
        assert "signature verification failed" in str(exc_info.value)

    def test_verify_expired_binding(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
        owner_public_key: bytes,
    ) -> None:
        """Verification fails for expired binding."""
        # Create a valid binding first
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
            validity_seconds=1,
        )

        # Create an already-expired binding by copying with past expiry
        # The signature won't match, but expiry check happens first
        expired_binding = OwnerBinding(
            agent_did=binding.agent_did,
            owner_did=binding.owner_did,
            permissions=binding.permissions,
            expiry=datetime.now(UTC) - timedelta(seconds=10),  # Already expired
            created=binding.created,
            nonce=binding.nonce,
            signature=binding.signature,
            max_delegation_depth=binding.max_delegation_depth,
            parent_binding_hash=binding.parent_binding_hash,
        )

        # Verify the binding is expired
        assert expired_binding.is_expired()

        # Verification should fail with expiry check
        with pytest.raises(BindingExpiredError):
            verify_owner_binding(expired_binding, owner_public_key, check_expiry=True)

    def test_verify_without_expiry_check(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
        owner_public_key: bytes,
    ) -> None:
        """Can verify binding without checking expiry."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        # Should work without expiry check
        assert verify_owner_binding(binding, owner_public_key, check_expiry=False)


class TestBindingPermissions:
    """Tests for permission checking."""

    def test_has_permission(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """has_permission returns True for granted permission."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value, Permission.RESOURCE_REQUEST.value},
        )
        assert binding.has_permission(Permission.COMM_INITIATE)
        assert binding.has_permission(Permission.RESOURCE_REQUEST)

    def test_has_permission_string(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """has_permission works with string permission."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={"comm:initiate"},
        )
        assert binding.has_permission("comm:initiate")

    def test_has_permission_not_granted(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """has_permission returns False for non-granted permission."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        assert not binding.has_permission(Permission.TOKEN_ISSUE)

    def test_full_permission_grants_all(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """FULL permission grants all permissions."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.FULL.value},
        )
        assert binding.has_permission(Permission.COMM_INITIATE)
        assert binding.has_permission(Permission.TOKEN_ISSUE)
        assert binding.has_permission(Permission.IDENTITY_ROTATE_KEY)

    def test_check_permission_passes(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """check_permission passes for granted permission."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        # Should not raise
        binding.check_permission(Permission.COMM_INITIATE)

    def test_check_permission_raises(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
    ) -> None:
        """check_permission raises for non-granted permission."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        with pytest.raises(BindingPermissionError) as exc_info:
            binding.check_permission(Permission.TOKEN_ISSUE)
        assert "not granted" in str(exc_info.value)


class TestBindingAttenuation:
    """Tests for binding attenuation (delegation)."""

    def test_attenuate_binding(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        sample_second_agent_did: DID,
        owner_secret_key: bytes,
        agent_secret_key: bytes,
    ) -> None:
        """Can attenuate a binding to delegate to another agent."""
        # Create parent binding with delegation allowed
        parent = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value, Permission.RESOURCE_REQUEST.value},
            max_delegation_depth=1,
        )

        # Attenuate to second agent
        child = attenuate_binding(
            parent_binding=parent,
            agent_secret_key=agent_secret_key,
            new_agent_did=sample_second_agent_did,
            reduced_permissions={Permission.COMM_INITIATE.value},
        )

        assert child.agent_did == sample_second_agent_did
        assert child.owner_did == sample_owner_did  # Original owner
        assert Permission.COMM_INITIATE.value in child.permissions
        assert Permission.RESOURCE_REQUEST.value not in child.permissions

    def test_attenuate_reduces_delegation_depth(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        sample_second_agent_did: DID,
        owner_secret_key: bytes,
        agent_secret_key: bytes,
    ) -> None:
        """Attenuation reduces delegation depth."""
        parent = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
            max_delegation_depth=2,
        )

        child = attenuate_binding(
            parent_binding=parent,
            agent_secret_key=agent_secret_key,
            new_agent_did=sample_second_agent_did,
            reduced_permissions={Permission.COMM_INITIATE.value},
        )

        assert child.max_delegation_depth == 1  # Reduced by 1

    def test_attenuate_has_parent_hash(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        sample_second_agent_did: DID,
        owner_secret_key: bytes,
        agent_secret_key: bytes,
    ) -> None:
        """Attenuated binding references parent hash."""
        parent = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
            max_delegation_depth=1,
        )

        child = attenuate_binding(
            parent_binding=parent,
            agent_secret_key=agent_secret_key,
            new_agent_did=sample_second_agent_did,
            reduced_permissions={Permission.COMM_INITIATE.value},
        )

        assert child.parent_binding_hash is not None
        assert child.parent_binding_hash == parent.compute_hash()

    def test_attenuate_no_delegation_fails(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        sample_second_agent_did: DID,
        owner_secret_key: bytes,
        agent_secret_key: bytes,
    ) -> None:
        """Cannot attenuate binding with no delegation allowed."""
        parent = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
            max_delegation_depth=0,  # No delegation
        )

        with pytest.raises(InvalidBindingError) as exc_info:
            attenuate_binding(
                parent_binding=parent,
                agent_secret_key=agent_secret_key,
                new_agent_did=sample_second_agent_did,
                reduced_permissions={Permission.COMM_INITIATE.value},
            )
        assert "does not allow delegation" in str(exc_info.value)

    def test_attenuate_cannot_expand_permissions(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        sample_second_agent_did: DID,
        owner_secret_key: bytes,
        agent_secret_key: bytes,
    ) -> None:
        """Cannot attenuate to permissions not held."""
        parent = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
            max_delegation_depth=1,
        )

        with pytest.raises(InvalidBindingError) as exc_info:
            attenuate_binding(
                parent_binding=parent,
                agent_secret_key=agent_secret_key,
                new_agent_did=sample_second_agent_did,
                reduced_permissions={Permission.TOKEN_ISSUE.value},  # Not held
            )
        assert "Cannot delegate permissions not held" in str(exc_info.value)

    def test_attenuate_cannot_extend_validity(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        sample_second_agent_did: DID,
        owner_secret_key: bytes,
        agent_secret_key: bytes,
    ) -> None:
        """Cannot attenuate with longer validity than parent."""
        parent = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
            max_delegation_depth=1,
            validity_seconds=3600,  # 1 hour
        )

        with pytest.raises(InvalidBindingError) as exc_info:
            attenuate_binding(
                parent_binding=parent,
                agent_secret_key=agent_secret_key,
                new_agent_did=sample_second_agent_did,
                reduced_permissions={Permission.COMM_INITIATE.value},
                reduced_validity_seconds=7200,  # 2 hours - too long
            )
        assert "exceeds" in str(exc_info.value)


class TestBindingChain:
    """Tests for binding chain verification."""

    def test_verify_single_binding_chain(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        owner_secret_key: bytes,
        owner_public_key: bytes,
    ) -> None:
        """Can verify a chain with single binding."""
        binding = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
        )
        assert verify_binding_chain([binding], owner_public_key)

    def test_verify_empty_chain_fails(self, owner_public_key: bytes) -> None:
        """Empty chain verification fails."""
        with pytest.raises(InvalidBindingError) as exc_info:
            verify_binding_chain([], owner_public_key)
        assert "Empty binding chain" in str(exc_info.value)

    def test_root_binding_cannot_have_parent(
        self,
        sample_agent_did: DID,
        sample_owner_did: DID,
        sample_second_agent_did: DID,
        owner_secret_key: bytes,
        owner_public_key: bytes,
        agent_secret_key: bytes,
    ) -> None:
        """Root binding in chain cannot have parent hash."""
        # Create delegated binding
        parent = create_owner_binding(
            agent_did=sample_agent_did,
            owner_did=sample_owner_did,
            owner_secret_key=owner_secret_key,
            permissions={Permission.COMM_INITIATE.value},
            max_delegation_depth=1,
        )

        child = attenuate_binding(
            parent_binding=parent,
            agent_secret_key=agent_secret_key,
            new_agent_did=sample_second_agent_did,
            reduced_permissions={Permission.COMM_INITIATE.value},
        )

        # Try to use child as root (has parent hash)
        with pytest.raises(InvalidBindingError) as exc_info:
            verify_binding_chain([child], owner_public_key)
        assert "cannot have a parent" in str(exc_info.value)
