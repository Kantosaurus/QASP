"""QASP-Shake handshake protocol.

This module implements the QASP-Shake handshake for establishing
secure connections with post-quantum cryptography.

The handshake uses:
- ML-KEM-768 for key encapsulation (or hybrid X25519+ML-KEM-768)
- ML-DSA-65 for signatures
- HKDF-SHA-384 for key derivation

Message Flow:
    Client                                Server
      |  [IDLE]                      [IDLE]  |
      |--- ClientHello ------------------->  |
      |  [HELLO_SENT]          [HELLO_RECEIVED]
      |<-- ServerHello --------------------|
      |--- ClientAuth -------------------->  |
      |  [ESTABLISHED]          [ESTABLISHED]
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from qasp.crypto import hybrid, kem, signatures
from qasp.crypto.kdf import derive_qasp_session_key
from qasp.crypto.suites import (
    PQ_SUITE_IDS,
    SUITE_HYBRID_TRANSITION,
    SUITE_PQ_STRICT,
    get_default_registry,
)
from qasp.framing.messages import ClientAuth, ClientHello, ServerHello

if TYPE_CHECKING:
    from qasp.crypto.hybrid import HybridKeypair

__all__ = [
    "Handshake",
    "HandshakeConfig",
    "HandshakeErrorType",
    "HandshakeFailure",
    "HandshakeKeys",
    "HandshakeState",
]


# =============================================================================
# Constants
# =============================================================================

NONCE_SIZE = 32  # Size of client/server nonce in bytes
SESSION_ID_SIZE = 32  # Size of session ID in bytes
DEFAULT_PROTOCOL_VERSION = (1, 0)
DEFAULT_CIPHER_SUITE = SUITE_PQ_STRICT  # ML-KEM-768 + ML-DSA-65 + AES-256-GCM


# =============================================================================
# Enums
# =============================================================================


class HandshakeState(Enum):
    """Handshake state machine states."""

    INITIAL = auto()
    SENT_CLIENT_HELLO = auto()
    RECEIVED_CLIENT_HELLO = auto()
    SENT_SERVER_HELLO = auto()
    RECEIVED_SERVER_HELLO = auto()
    COMPLETE = auto()
    FAILED = auto()


class HandshakeErrorType(Enum):
    """Types of handshake errors."""

    VERSION_MISMATCH = auto()
    SUITE_MISMATCH = auto()
    AUTH_FAILED = auto()
    KEM_FAILED = auto()
    TIMEOUT = auto()
    UPGRADE_REQUIRED = auto()


# =============================================================================
# Data Classes
# =============================================================================


@dataclass(frozen=True)
class HandshakeConfig:
    """Configuration for the handshake protocol.

    Attributes:
        protocol_version: Protocol version to use/accept.
        supported_cipher_suites: Cipher suites supported by this endpoint.
        enable_hybrid: Whether to use hybrid X25519+ML-KEM mode.
        initial_timeout_ms: Initial timeout in milliseconds for handshake operations.
        max_timeout_ms: Maximum timeout after exponential backoff.
        backoff_multiplier: Multiplier for exponential backoff.
        max_retries: Maximum number of retry attempts.
    """

    protocol_version: tuple[int, int] = DEFAULT_PROTOCOL_VERSION
    supported_cipher_suites: tuple[int, ...] = (SUITE_HYBRID_TRANSITION,)
    enable_hybrid: bool = True
    initial_timeout_ms: int = 5000
    max_timeout_ms: int = 60000
    backoff_multiplier: float = 2.0
    max_retries: int = 3


@dataclass(frozen=True)
class HandshakeKeys:
    """Result of a successful handshake.

    Attributes:
        session_key: HKDF-derived session key (32 bytes for AES-256).
        peer_kem_public: Peer's KEM public key.
        peer_sig_public: Peer's signature public key.
        session_id: SHA-384(transcript)[:32] - unique session identifier.
    """

    session_key: bytes
    peer_kem_public: bytes
    peer_sig_public: bytes
    session_id: bytes


@dataclass(frozen=True)
class HandshakeFailure:
    """Represents a handshake failure.

    Attributes:
        error_type: The type of error that occurred.
        message: Human-readable error description.
        alert_code: QASP alert code to send to peer.
    """

    error_type: HandshakeErrorType
    message: str
    alert_code: int = 0


# =============================================================================
# Transcript Builder
# =============================================================================


class TranscriptBuilder:
    """Builds and manages the handshake transcript.

    The transcript is used for:
    1. Signature generation and verification
    2. Session ID derivation

    Transcript includes:
    - ClientHello: version || client_nonce || kem_pk || sig_pk || suites
    - ServerHello (pre-sig): version || server_nonce || kem_ct || kem_pk || sig_pk || suite
    - ServerHello signature (for ClientAuth signing)
    """

    def __init__(self) -> None:
        self._parts: list[bytes] = []
        self._client_hello_end: int = 0
        self._server_hello_presig_end: int = 0

    def add_client_hello(
        self,
        version: tuple[int, int],
        client_nonce: bytes,
        kem_public_key: bytes,
        sig_public_key: bytes,
        cipher_suites: tuple[int, ...],
    ) -> None:
        """Add ClientHello fields to the transcript."""
        self._parts.append(bytes([version[0], version[1]]))
        self._parts.append(client_nonce)
        self._parts.append(kem_public_key)
        self._parts.append(sig_public_key)
        suite_bytes = b"".join(s.to_bytes(2, "big") for s in cipher_suites)
        self._parts.append(suite_bytes)
        self._client_hello_end = len(self._parts)

    def add_server_hello_presig(
        self,
        version: tuple[int, int],
        server_nonce: bytes,
        kem_ciphertext: bytes,
        kem_public_key: bytes,
        sig_public_key: bytes,
        selected_suite: int,
    ) -> None:
        """Add ServerHello fields (before signature) to the transcript."""
        self._parts.append(bytes([version[0], version[1]]))
        self._parts.append(server_nonce)
        self._parts.append(kem_ciphertext)
        self._parts.append(kem_public_key)
        self._parts.append(sig_public_key)
        self._parts.append(selected_suite.to_bytes(2, "big"))
        self._server_hello_presig_end = len(self._parts)

    def add_server_signature(self, signature: bytes) -> None:
        """Add the server's signature to the transcript."""
        self._parts.append(signature)

    def get_server_signing_transcript(self) -> bytes:
        """Get the transcript for server to sign (ClientHello + ServerHello pre-sig)."""
        return b"".join(self._parts[: self._server_hello_presig_end])

    def get_client_signing_transcript(self) -> bytes:
        """Get the transcript for client to sign (includes server signature)."""
        return b"".join(self._parts)

    def get_full_transcript(self) -> bytes:
        """Get the complete transcript for session ID derivation."""
        return b"".join(self._parts)

    def compute_session_id(self) -> bytes:
        """Compute the session ID as SHA-384(transcript)[:32]."""
        full = self.get_full_transcript()
        digest = hashlib.sha384(full).digest()
        return digest[:SESSION_ID_SIZE]


# =============================================================================
# Handshake Class
# =============================================================================


# Type alias for handshake method returns
HandshakeResult = (
    ClientHello | ServerHello | ClientAuth | HandshakeKeys | HandshakeFailure
)


class Handshake:
    """QASP-Shake handshake manager.

    This class manages the cryptographic state machine for the
    QASP-Shake handshake protocol.

    Usage (Client):
        hs = Handshake(kem_keypair, sig_keypair, is_initiator=True)
        client_hello = hs.create_client_hello()
        # Send client_hello, receive server_hello
        result = hs.process_server_hello(server_hello)
        if isinstance(result, HandshakeFailure):
            # Handle failure
        client_auth = result
        # Send client_auth
        keys = hs.complete_client_handshake()

    Usage (Server):
        hs = Handshake(kem_keypair, sig_keypair, is_initiator=False)
        # Receive client_hello
        result = hs.process_client_hello(client_hello)
        if isinstance(result, HandshakeFailure):
            # Handle failure
        server_hello = result
        # Send server_hello, receive client_auth
        result = hs.process_client_auth(client_auth)
        if isinstance(result, HandshakeFailure):
            # Handle failure
        keys = result
    """

    def __init__(
        self,
        kem_keypair: HybridKeypair,
        sig_keypair: tuple[bytes, bytes],
        is_initiator: bool = True,
        config: HandshakeConfig | None = None,
        certificate: bytes | None = None,
    ) -> None:
        """Initialize the handshake.

        Args:
            kem_keypair: Local hybrid keypair for key encapsulation.
            sig_keypair: Local signature keypair as (public_key, secret_key).
            is_initiator: True if this side initiates (client), False for server.
            config: Handshake configuration. Uses defaults if None.
            certificate: Optional certificate for authentication.
        """
        self._kem_keypair = kem_keypair
        self._sig_public_key = sig_keypair[0]
        self._sig_secret_key = sig_keypair[1]
        self._is_initiator = is_initiator
        self._config = config or HandshakeConfig()
        self._certificate = certificate or b""

        # State machine
        self._state = HandshakeState.INITIAL

        # Handshake values
        self._client_nonce: bytes | None = None
        self._server_nonce: bytes | None = None
        self._peer_kem_public: bytes | None = None
        self._peer_sig_public: bytes | None = None
        self._shared_secret: bytes | None = None
        self._selected_suite: int | None = None

        # Transcript
        self._transcript = TranscriptBuilder()

        # Prepared values for later steps
        self._client_auth_message: ClientAuth | None = None
        self._session_key: bytes | None = None

    @property
    def state(self) -> HandshakeState:
        """Return the current handshake state."""
        return self._state

    # =========================================================================
    # Client Methods
    # =========================================================================

    def create_client_hello(self) -> ClientHello:
        """Create a ClientHello message.

        This is the first step for the client in the handshake.

        Returns:
            ClientHello message to send to the server.

        Raises:
            RuntimeError: If called in wrong state or by server.
        """
        if not self._is_initiator:
            raise RuntimeError("Only initiator (client) can create ClientHello")
        if self._state != HandshakeState.INITIAL:
            raise RuntimeError(f"Cannot create ClientHello in state {self._state}")

        # Generate client nonce
        self._client_nonce = secrets.token_bytes(NONCE_SIZE)

        # Get KEM public key based on hybrid mode
        if self._config.enable_hybrid:
            kem_pk = self._kem_keypair.public_key
        else:
            kem_pk = self._kem_keypair.mlkem_public

        # Build ClientHello
        client_hello = ClientHello(
            protocol_version=self._config.protocol_version,
            client_random=self._client_nonce,
            kem_public_key=kem_pk,
            sig_public_key=self._sig_public_key,
            cipher_suites=self._config.supported_cipher_suites,
            extensions=b"",
        )

        # Add to transcript
        self._transcript.add_client_hello(
            version=client_hello.protocol_version,
            client_nonce=client_hello.client_random,
            kem_public_key=client_hello.kem_public_key,
            sig_public_key=client_hello.sig_public_key,
            cipher_suites=client_hello.cipher_suites,
        )

        self._state = HandshakeState.SENT_CLIENT_HELLO
        return client_hello

    def process_server_hello(
        self,
        server_hello: ServerHello,
    ) -> ClientAuth | HandshakeFailure:
        """Process ServerHello and generate ClientAuth.

        This is called by the client after receiving ServerHello.

        Args:
            server_hello: The ServerHello message from the server.

        Returns:
            ClientAuth message to send, or HandshakeFailure on error.
        """
        if not self._is_initiator:
            raise RuntimeError("Only initiator (client) can process ServerHello")
        if self._state != HandshakeState.SENT_CLIENT_HELLO:
            raise RuntimeError(f"Cannot process ServerHello in state {self._state}")

        # Validate version
        if server_hello.protocol_version != self._config.protocol_version:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.VERSION_MISMATCH,
                message=f"Version mismatch: expected {self._config.protocol_version}, "
                f"got {server_hello.protocol_version}",
                alert_code=70,
            )

        # Validate cipher suite
        if server_hello.selected_cipher_suite not in self._config.supported_cipher_suites:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.SUITE_MISMATCH,
                message=f"Unsupported cipher suite: {server_hello.selected_cipher_suite}",
                alert_code=71,
            )

        # Store values
        self._server_nonce = server_hello.server_random
        self._peer_kem_public = server_hello.kem_public_key
        self._peer_sig_public = server_hello.sig_public_key
        self._selected_suite = server_hello.selected_cipher_suite

        # Add ServerHello (pre-signature) to transcript
        self._transcript.add_server_hello_presig(
            version=server_hello.protocol_version,
            server_nonce=server_hello.server_random,
            kem_ciphertext=server_hello.kem_ciphertext,
            kem_public_key=server_hello.kem_public_key,
            sig_public_key=server_hello.sig_public_key,
            selected_suite=server_hello.selected_cipher_suite,
        )

        # Verify server signature
        transcript_to_verify = self._transcript.get_server_signing_transcript()
        try:
            signatures.verify(
                public_key=server_hello.sig_public_key,
                message=transcript_to_verify,
                signature=server_hello.signature,
            )
        except Exception as e:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.AUTH_FAILED,
                message=f"Server signature verification failed: {e}",
                alert_code=51,
            )

        # Add server signature to transcript
        self._transcript.add_server_signature(server_hello.signature)

        # Suite-aware KEM dispatch
        selected_suite_info = get_default_registry().lookup(self._selected_suite)
        use_hybrid = selected_suite_info.uses_hybrid_kem

        # Decapsulate shared secret
        try:
            if use_hybrid:
                # Hybrid decapsulation
                self._shared_secret = hybrid.decapsulate(
                    self._kem_keypair,
                    server_hello.kem_ciphertext,
                )
            else:
                # ML-KEM only
                self._shared_secret = kem.decapsulate(
                    self._kem_keypair.mlkem_private,
                    server_hello.kem_ciphertext,
                )
        except Exception as e:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.KEM_FAILED,
                message=f"KEM decapsulation failed: {e}",
                alert_code=50,
            )

        # Prepare the KEM ciphertext for server's KEM public key
        # This provides forward secrecy from the client side as well
        try:
            if use_hybrid:
                client_kem_ct, client_shared = hybrid.encapsulate(
                    server_hello.kem_public_key
                )
            else:
                client_kem_ct, client_shared = kem.encapsulate(
                    server_hello.kem_public_key[32:]  # Skip X25519 portion if present
                    if len(server_hello.kem_public_key) > kem.ML_KEM_768_PUBLIC_KEY_SIZE
                    else server_hello.kem_public_key
                )
        except Exception as e:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.KEM_FAILED,
                message=f"Client KEM encapsulation failed: {e}",
                alert_code=50,
            )

        # Sign the transcript
        transcript_to_sign = self._transcript.get_client_signing_transcript()
        try:
            client_signature = signatures.sign(
                self._sig_secret_key,
                transcript_to_sign,
            )
        except Exception as e:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.AUTH_FAILED,
                message=f"Client signing failed: {e}",
                alert_code=51,
            )

        # Build ClientAuth
        client_auth = ClientAuth(
            kem_ciphertext=client_kem_ct,
            signature=client_signature,
            certificate=self._certificate,
        )

        # Store for completion
        self._client_auth_message = client_auth

        # Combine shared secrets: server's encapsulation + client's encapsulation
        combined_shared = self._shared_secret + client_shared

        # Derive session key
        if use_hybrid:
            # Split hybrid shared secret (X25519 || ML-KEM)
            x25519_ss = combined_shared[:32]
            mlkem_ss = combined_shared[32:64]
            x25519_ss_client = combined_shared[64:96]
            mlkem_ss_client = combined_shared[96:128]
            # Combine both directions
            mlkem_combined = mlkem_ss + mlkem_ss_client
            x25519_combined = x25519_ss + x25519_ss_client
            # Use first 32 bytes of each for KDF
            mlkem_for_kdf = hashlib.sha256(mlkem_combined).digest()
            x25519_for_kdf = hashlib.sha256(x25519_combined).digest()
        else:
            # ML-KEM only: pad X25519 portion with zeros
            mlkem_for_kdf = hashlib.sha256(combined_shared).digest()
            x25519_for_kdf = bytes(32)

        self._session_key = derive_qasp_session_key(
            mlkem_shared_secret=mlkem_for_kdf,
            x25519_shared_secret=x25519_for_kdf,
            client_nonce=self._client_nonce,
            server_nonce=self._server_nonce,
        )

        self._state = HandshakeState.RECEIVED_SERVER_HELLO
        return client_auth

    def complete_client_handshake(self) -> HandshakeKeys | HandshakeFailure:
        """Complete the client side handshake.

        Called after sending ClientAuth to finalize the handshake.

        Returns:
            HandshakeKeys containing the session key and peer info.
        """
        if not self._is_initiator:
            raise RuntimeError("Only initiator (client) can complete client handshake")
        if self._state != HandshakeState.RECEIVED_SERVER_HELLO:
            raise RuntimeError(
                f"Cannot complete client handshake in state {self._state}"
            )

        if (
            self._session_key is None
            or self._peer_kem_public is None
            or self._peer_sig_public is None
        ):
            return HandshakeFailure(
                error_type=HandshakeErrorType.AUTH_FAILED,
                message="Missing handshake values for completion",
                alert_code=51,
            )

        session_id = self._transcript.compute_session_id()

        self._state = HandshakeState.COMPLETE
        return HandshakeKeys(
            session_key=self._session_key,
            peer_kem_public=self._peer_kem_public,
            peer_sig_public=self._peer_sig_public,
            session_id=session_id,
        )

    # =========================================================================
    # Server Methods
    # =========================================================================

    def process_client_hello(
        self,
        client_hello: ClientHello,
    ) -> ServerHello | HandshakeFailure:
        """Process ClientHello and generate ServerHello.

        This is called by the server upon receiving ClientHello.

        Args:
            client_hello: The ClientHello message from the client.

        Returns:
            ServerHello message to send, or HandshakeFailure on error.
        """
        if self._is_initiator:
            raise RuntimeError("Only responder (server) can process ClientHello")
        if self._state != HandshakeState.INITIAL:
            raise RuntimeError(f"Cannot process ClientHello in state {self._state}")

        # Validate version
        if client_hello.protocol_version != self._config.protocol_version:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.VERSION_MISMATCH,
                message=f"Version mismatch: expected {self._config.protocol_version}, "
                f"got {client_hello.protocol_version}",
                alert_code=70,
            )

        # Find compatible cipher suite
        common_suites = set(client_hello.cipher_suites) & set(
            self._config.supported_cipher_suites
        )
        if not common_suites:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.SUITE_MISMATCH,
                message="No common cipher suites",
                alert_code=71,
            )

        # Downgrade resistance: PQ-capable server rejects classical-only client
        server_has_pq = bool(set(self._config.supported_cipher_suites) & PQ_SUITE_IDS)
        client_has_pq = bool(set(client_hello.cipher_suites) & PQ_SUITE_IDS)
        if server_has_pq and not client_has_pq:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.UPGRADE_REQUIRED,
                message="Server requires post-quantum capable cipher suite",
                alert_code=72,
            )

        # Select cipher suite (prefer our order)
        for suite in self._config.supported_cipher_suites:
            if suite in common_suites:
                self._selected_suite = suite
                break

        # Store client values
        self._client_nonce = client_hello.client_random
        self._peer_kem_public = client_hello.kem_public_key
        self._peer_sig_public = client_hello.sig_public_key

        # Generate server nonce
        self._server_nonce = secrets.token_bytes(NONCE_SIZE)

        # Add ClientHello to transcript
        self._transcript.add_client_hello(
            version=client_hello.protocol_version,
            client_nonce=client_hello.client_random,
            kem_public_key=client_hello.kem_public_key,
            sig_public_key=client_hello.sig_public_key,
            cipher_suites=client_hello.cipher_suites,
        )

        # Suite-aware KEM dispatch
        selected_suite_info = get_default_registry().lookup(self._selected_suite)
        use_hybrid = selected_suite_info.uses_hybrid_kem

        # Encapsulate to client's public key
        try:
            if use_hybrid:
                kem_ciphertext, self._shared_secret = hybrid.encapsulate(
                    client_hello.kem_public_key
                )
            else:
                kem_ciphertext, self._shared_secret = kem.encapsulate(
                    client_hello.kem_public_key
                )
        except Exception as e:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.KEM_FAILED,
                message=f"KEM encapsulation failed: {e}",
                alert_code=50,
            )

        # Get our KEM public key
        if use_hybrid:
            our_kem_pk = self._kem_keypair.public_key
        else:
            our_kem_pk = self._kem_keypair.mlkem_public

        # Add ServerHello (pre-signature) to transcript
        self._transcript.add_server_hello_presig(
            version=self._config.protocol_version,
            server_nonce=self._server_nonce,
            kem_ciphertext=kem_ciphertext,
            kem_public_key=our_kem_pk,
            sig_public_key=self._sig_public_key,
            selected_suite=self._selected_suite,
        )

        # Sign the transcript
        transcript_to_sign = self._transcript.get_server_signing_transcript()
        try:
            server_signature = signatures.sign(
                self._sig_secret_key,
                transcript_to_sign,
            )
        except Exception as e:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.AUTH_FAILED,
                message=f"Server signing failed: {e}",
                alert_code=51,
            )

        # Add signature to transcript
        self._transcript.add_server_signature(server_signature)

        # Build ServerHello
        server_hello = ServerHello(
            protocol_version=self._config.protocol_version,
            server_random=self._server_nonce,
            kem_ciphertext=kem_ciphertext,
            kem_public_key=our_kem_pk,
            sig_public_key=self._sig_public_key,
            selected_cipher_suite=self._selected_suite,
            signature=server_signature,
            extensions=b"",
        )

        self._state = HandshakeState.RECEIVED_CLIENT_HELLO
        return server_hello

    def process_client_auth(
        self,
        client_auth: ClientAuth,
    ) -> HandshakeKeys | HandshakeFailure:
        """Process ClientAuth and complete the handshake.

        This is called by the server upon receiving ClientAuth.

        Args:
            client_auth: The ClientAuth message from the client.

        Returns:
            HandshakeKeys on success, or HandshakeFailure on error.
        """
        if self._is_initiator:
            raise RuntimeError("Only responder (server) can process ClientAuth")
        if self._state != HandshakeState.RECEIVED_CLIENT_HELLO:
            raise RuntimeError(f"Cannot process ClientAuth in state {self._state}")

        if self._peer_sig_public is None:
            return HandshakeFailure(
                error_type=HandshakeErrorType.AUTH_FAILED,
                message="Missing client signature public key",
                alert_code=51,
            )

        # Verify client signature
        transcript_to_verify = self._transcript.get_client_signing_transcript()
        try:
            signatures.verify(
                public_key=self._peer_sig_public,
                message=transcript_to_verify,
                signature=client_auth.signature,
            )
        except Exception as e:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.AUTH_FAILED,
                message=f"Client signature verification failed: {e}",
                alert_code=51,
            )

        # Suite-aware KEM dispatch
        selected_suite_info = get_default_registry().lookup(self._selected_suite)
        use_hybrid = selected_suite_info.uses_hybrid_kem

        # Decapsulate client's KEM ciphertext
        try:
            if use_hybrid:
                client_shared = hybrid.decapsulate(
                    self._kem_keypair,
                    client_auth.kem_ciphertext,
                )
            else:
                client_shared = kem.decapsulate(
                    self._kem_keypair.mlkem_private,
                    client_auth.kem_ciphertext,
                )
        except Exception as e:
            self._state = HandshakeState.FAILED
            return HandshakeFailure(
                error_type=HandshakeErrorType.KEM_FAILED,
                message=f"Client KEM decapsulation failed: {e}",
                alert_code=50,
            )

        # Combine shared secrets: server's encapsulation + client's encapsulation
        combined_shared = self._shared_secret + client_shared

        # Derive session key
        if use_hybrid:
            # Split hybrid shared secret (X25519 || ML-KEM)
            x25519_ss = combined_shared[:32]
            mlkem_ss = combined_shared[32:64]
            x25519_ss_client = combined_shared[64:96]
            mlkem_ss_client = combined_shared[96:128]
            # Combine both directions
            mlkem_combined = mlkem_ss + mlkem_ss_client
            x25519_combined = x25519_ss + x25519_ss_client
            # Use first 32 bytes of each for KDF
            mlkem_for_kdf = hashlib.sha256(mlkem_combined).digest()
            x25519_for_kdf = hashlib.sha256(x25519_combined).digest()
        else:
            # ML-KEM only: pad X25519 portion with zeros
            mlkem_for_kdf = hashlib.sha256(combined_shared).digest()
            x25519_for_kdf = bytes(32)

        session_key = derive_qasp_session_key(
            mlkem_shared_secret=mlkem_for_kdf,
            x25519_shared_secret=x25519_for_kdf,
            client_nonce=self._client_nonce,
            server_nonce=self._server_nonce,
        )

        session_id = self._transcript.compute_session_id()

        self._state = HandshakeState.COMPLETE
        return HandshakeKeys(
            session_key=session_key,
            peer_kem_public=self._peer_kem_public,
            peer_sig_public=self._peer_sig_public,
            session_id=session_id,
        )
