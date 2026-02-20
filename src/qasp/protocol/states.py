"""Protocol state definitions.

This module defines the state machine for QASP connections,
including valid state transitions per the QASP protocol specification.
"""

from __future__ import annotations

from enum import Enum, auto

__all__ = [
    "VALID_TRANSITIONS",
    "ConnectionState",
    "ProtocolError",
    "StateTransitionError",
    "is_valid_transition",
]


class ProtocolError(Exception):
    """Base exception for protocol errors."""


class StateTransitionError(ProtocolError):
    """Raised when an invalid state transition is attempted."""

    def __init__(self, from_state: ConnectionState, to_state: ConnectionState) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(
            f"Invalid state transition: {from_state.name} -> {to_state.name}"
        )


class ConnectionState(Enum):
    """QASP connection state.

    States follow the QASP protocol specification:
    - IDLE: Initial state, no handshake started
    - HELLO_SENT: Client sent ClientHello, awaiting ServerHello
    - HELLO_RECEIVED: Server received ClientHello, processing
    - AUTHENTICATED: Mutual authentication complete
    - ESTABLISHED: Session established, ready for application data
    - CLOSING: Close initiated, awaiting acknowledgment
    - CLOSED: Connection closed
    - ERROR: Error state, connection must be reset
    """

    IDLE = auto()
    HELLO_SENT = auto()
    HELLO_RECEIVED = auto()
    AUTHENTICATED = auto()
    ESTABLISHED = auto()
    CLOSING = auto()
    CLOSED = auto()
    ERROR = auto()


# Valid state transitions per QASP protocol specification
# Key: current state, Value: set of valid next states
VALID_TRANSITIONS: dict[ConnectionState, frozenset[ConnectionState]] = {
    ConnectionState.IDLE: frozenset({
        ConnectionState.HELLO_SENT,      # Client initiates
        ConnectionState.HELLO_RECEIVED,  # Server receives ClientHello
        ConnectionState.ERROR,           # Error during init
    }),
    ConnectionState.HELLO_SENT: frozenset({
        ConnectionState.AUTHENTICATED,   # Server auth received
        ConnectionState.ERROR,           # Handshake failure
        ConnectionState.CLOSED,          # Connection aborted
    }),
    ConnectionState.HELLO_RECEIVED: frozenset({
        ConnectionState.AUTHENTICATED,   # Client auth received
        ConnectionState.ERROR,           # Handshake failure
        ConnectionState.CLOSED,          # Connection aborted
    }),
    ConnectionState.AUTHENTICATED: frozenset({
        ConnectionState.ESTABLISHED,     # Session key established
        ConnectionState.ERROR,           # Post-auth error
        ConnectionState.CLOSED,          # Connection aborted
    }),
    ConnectionState.ESTABLISHED: frozenset({
        ConnectionState.CLOSING,         # Graceful close initiated
        ConnectionState.ERROR,           # Runtime error
        ConnectionState.CLOSED,          # Abrupt close
    }),
    ConnectionState.CLOSING: frozenset({
        ConnectionState.CLOSED,          # Close completed
        ConnectionState.ERROR,           # Error during close
    }),
    ConnectionState.CLOSED: frozenset({
        ConnectionState.IDLE,            # Connection reset/reuse
    }),
    ConnectionState.ERROR: frozenset({
        ConnectionState.CLOSED,          # Error cleanup
        ConnectionState.IDLE,            # Reset after error
    }),
}


def is_valid_transition(
    from_state: ConnectionState,
    to_state: ConnectionState,
) -> bool:
    """Check if a state transition is valid.

    Args:
        from_state: The current state.
        to_state: The proposed next state.

    Returns:
        True if the transition is valid, False otherwise.
    """
    return to_state in VALID_TRANSITIONS.get(from_state, frozenset())
