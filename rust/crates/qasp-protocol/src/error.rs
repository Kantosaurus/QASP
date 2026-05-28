#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum QaspErrorCode {
    VersionMismatch = 0x01,
    SuiteMismatch = 0x02,
    AuthFailed = 0x03,
    KemFailed = 0x04,
    TokenExpired = 0x05,
    TokenRevoked = 0x06,
    PermissionDenied = 0x07,
    RateLimited = 0x08,
    ResourceUnavailable = 0x09,
    BudgetExhausted = 0x0A,
    ReconciliationFailed = 0x0B,
    ChannelClosed = 0x0C,
    InternalError = 0xFF,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ProtocolErrorKind {
    HandshakeVersion,
    HandshakeSuite,
    HandshakeAuthentication,
    HandshakeKem,
    HandshakeUpgradeRequired,
    HandshakeTimeout,
    Other,
}

pub fn error_code_for_kind(kind: ProtocolErrorKind) -> QaspErrorCode {
    match kind {
        ProtocolErrorKind::HandshakeVersion => QaspErrorCode::VersionMismatch,
        ProtocolErrorKind::HandshakeSuite | ProtocolErrorKind::HandshakeUpgradeRequired => {
            QaspErrorCode::SuiteMismatch
        }
        ProtocolErrorKind::HandshakeAuthentication => QaspErrorCode::AuthFailed,
        ProtocolErrorKind::HandshakeKem => QaspErrorCode::KemFailed,
        ProtocolErrorKind::HandshakeTimeout | ProtocolErrorKind::Other => {
            QaspErrorCode::InternalError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{error_code_for_kind, ProtocolErrorKind, QaspErrorCode};

    #[test]
    fn wire_code_values_are_stable() {
        assert_eq!(QaspErrorCode::VersionMismatch as u8, 0x01);
        assert_eq!(QaspErrorCode::ChannelClosed as u8, 0x0C);
        assert_eq!(QaspErrorCode::InternalError as u8, 0xFF);
    }

    #[test]
    fn maps_handshake_failure_categories() {
        assert_eq!(
            error_code_for_kind(ProtocolErrorKind::HandshakeVersion),
            QaspErrorCode::VersionMismatch
        );
        assert_eq!(
            error_code_for_kind(ProtocolErrorKind::HandshakeUpgradeRequired),
            QaspErrorCode::SuiteMismatch
        );
        assert_eq!(
            error_code_for_kind(ProtocolErrorKind::HandshakeAuthentication),
            QaspErrorCode::AuthFailed
        );
        assert_eq!(
            error_code_for_kind(ProtocolErrorKind::HandshakeKem),
            QaspErrorCode::KemFailed
        );
        assert_eq!(
            error_code_for_kind(ProtocolErrorKind::HandshakeTimeout),
            QaspErrorCode::InternalError
        );
    }
}
