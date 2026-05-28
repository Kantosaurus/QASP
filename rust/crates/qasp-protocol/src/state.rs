use core::fmt;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ConnectionState {
    Idle,
    HelloSent,
    HelloReceived,
    Authenticated,
    Established,
    Closing,
    Closed,
    Error,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct InvalidStateTransition {
    pub from: ConnectionState,
    pub to: ConnectionState,
}

impl fmt::Display for InvalidStateTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid QASP state transition: {:?} -> {:?}",
            self.from, self.to
        )
    }
}

impl std::error::Error for InvalidStateTransition {}

impl ConnectionState {
    pub fn may_transition_to(self, next: Self) -> bool {
        use ConnectionState::*;

        matches!(
            (self, next),
            (Idle, HelloSent | HelloReceived | Error)
                | (HelloSent, Authenticated | Error | Closed)
                | (HelloReceived, Authenticated | Error | Closed)
                | (Authenticated, Established | Error | Closed)
                | (Established, Closing | Error | Closed)
                | (Closing, Closed | Error)
                | (Closed, Idle)
                | (Error, Closed | Idle)
        )
    }

    pub fn transition_to(self, next: Self) -> Result<Self, InvalidStateTransition> {
        if self.may_transition_to(next) {
            Ok(next)
        } else {
            Err(InvalidStateTransition {
                from: self,
                to: next,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ConnectionState;

    #[test]
    fn supports_normal_client_handshake_lifecycle() {
        let state = ConnectionState::Idle
            .transition_to(ConnectionState::HelloSent)
            .unwrap()
            .transition_to(ConnectionState::Authenticated)
            .unwrap()
            .transition_to(ConnectionState::Established)
            .unwrap()
            .transition_to(ConnectionState::Closing)
            .unwrap()
            .transition_to(ConnectionState::Closed)
            .unwrap();
        assert_eq!(state, ConnectionState::Closed);
    }

    #[test]
    fn supports_server_receive_path_and_reset() {
        let state = ConnectionState::Idle
            .transition_to(ConnectionState::HelloReceived)
            .unwrap()
            .transition_to(ConnectionState::Authenticated)
            .unwrap()
            .transition_to(ConnectionState::Established)
            .unwrap()
            .transition_to(ConnectionState::Closed)
            .unwrap()
            .transition_to(ConnectionState::Idle)
            .unwrap();
        assert_eq!(state, ConnectionState::Idle);
    }

    #[test]
    fn rejects_skipping_authentication() {
        assert!(ConnectionState::HelloSent
            .transition_to(ConnectionState::Established)
            .is_err());
    }
}
