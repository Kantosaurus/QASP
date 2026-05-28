use core::fmt;

/// Registered QASP wire message identifiers currently represented in the
/// implementation surface.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MessageType {
    ClientHello = 0x01,
    ServerHello = 0x02,
    ClientAuth = 0x03,
    ApplicationData = 0x04,
    TokenRevocation = 0x05,
    RevocationNotice = 0x06,
    ResourceRequest = 0x07,
    ResourceGrant = 0x08,
    MeterAck = 0x09,
    ResourceSuspend = 0x0A,
    ResourceDeny = 0x0B,
    ResourceRelease = 0x0C,
    DisputeOpen = 0x0D,
    DisputeEvidence = 0x0E,
    DisputeVerdict = 0x0F,
    MeterReport = 0x10,
    ChannelOpen = 0x11,
    ChannelClose = 0x12,
    PriceRequest = 0x13,
    Alert = 0x14,
    PriceOffer = 0x15,
    PriceAccept = 0x16,
    DelegationRequest = 0x17,
    DelegationGrant = 0x18,
    ReconciliationRequest = 0x19,
    ReconciliationResponse = 0x1A,
    OcspRequest = 0x1B,
    OcspResponse = 0x1C,
    AgentMessage = 0x1D,
    AgentMessageAck = 0x1E,
    RelaySessionRequest = 0x20,
    RelaySessionGrant = 0x21,
    RelaySessionDeny = 0x22,
    RelaySessionNotify = 0x23,
    RelaySessionAccept = 0x24,
    RelayData = 0x25,
    RelaySessionClose = 0x26,
}

/// All currently registered message types, ordered by their wire identifier.
pub const ALL_MESSAGE_TYPES: [MessageType; 37] = [
    MessageType::ClientHello,
    MessageType::ServerHello,
    MessageType::ClientAuth,
    MessageType::ApplicationData,
    MessageType::TokenRevocation,
    MessageType::RevocationNotice,
    MessageType::ResourceRequest,
    MessageType::ResourceGrant,
    MessageType::MeterAck,
    MessageType::ResourceSuspend,
    MessageType::ResourceDeny,
    MessageType::ResourceRelease,
    MessageType::DisputeOpen,
    MessageType::DisputeEvidence,
    MessageType::DisputeVerdict,
    MessageType::MeterReport,
    MessageType::ChannelOpen,
    MessageType::ChannelClose,
    MessageType::PriceRequest,
    MessageType::Alert,
    MessageType::PriceOffer,
    MessageType::PriceAccept,
    MessageType::DelegationRequest,
    MessageType::DelegationGrant,
    MessageType::ReconciliationRequest,
    MessageType::ReconciliationResponse,
    MessageType::OcspRequest,
    MessageType::OcspResponse,
    MessageType::AgentMessage,
    MessageType::AgentMessageAck,
    MessageType::RelaySessionRequest,
    MessageType::RelaySessionGrant,
    MessageType::RelaySessionDeny,
    MessageType::RelaySessionNotify,
    MessageType::RelaySessionAccept,
    MessageType::RelayData,
    MessageType::RelaySessionClose,
];

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct UnknownMessageType(pub u8);

impl fmt::Display for UnknownMessageType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown QASP message type: 0x{:02x}", self.0)
    }
}

impl std::error::Error for UnknownMessageType {}

impl TryFrom<u8> for MessageType {
    type Error = UnknownMessageType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let message_type = match value {
            0x01 => Self::ClientHello,
            0x02 => Self::ServerHello,
            0x03 => Self::ClientAuth,
            0x04 => Self::ApplicationData,
            0x05 => Self::TokenRevocation,
            0x06 => Self::RevocationNotice,
            0x07 => Self::ResourceRequest,
            0x08 => Self::ResourceGrant,
            0x09 => Self::MeterAck,
            0x0A => Self::ResourceSuspend,
            0x0B => Self::ResourceDeny,
            0x0C => Self::ResourceRelease,
            0x0D => Self::DisputeOpen,
            0x0E => Self::DisputeEvidence,
            0x0F => Self::DisputeVerdict,
            0x10 => Self::MeterReport,
            0x11 => Self::ChannelOpen,
            0x12 => Self::ChannelClose,
            0x13 => Self::PriceRequest,
            0x14 => Self::Alert,
            0x15 => Self::PriceOffer,
            0x16 => Self::PriceAccept,
            0x17 => Self::DelegationRequest,
            0x18 => Self::DelegationGrant,
            0x19 => Self::ReconciliationRequest,
            0x1A => Self::ReconciliationResponse,
            0x1B => Self::OcspRequest,
            0x1C => Self::OcspResponse,
            0x1D => Self::AgentMessage,
            0x1E => Self::AgentMessageAck,
            0x20 => Self::RelaySessionRequest,
            0x21 => Self::RelaySessionGrant,
            0x22 => Self::RelaySessionDeny,
            0x23 => Self::RelaySessionNotify,
            0x24 => Self::RelaySessionAccept,
            0x25 => Self::RelayData,
            0x26 => Self::RelaySessionClose,
            _ => return Err(UnknownMessageType(value)),
        };
        Ok(message_type)
    }
}

impl From<MessageType> for u8 {
    fn from(message_type: MessageType) -> Self {
        message_type as u8
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageType, ALL_MESSAGE_TYPES};

    #[test]
    fn every_registered_type_round_trips() {
        for message_type in ALL_MESSAGE_TYPES {
            let byte = u8::from(message_type);
            assert_eq!(MessageType::try_from(byte), Ok(message_type));
        }
    }

    #[test]
    fn unassigned_and_unknown_codes_are_rejected() {
        assert!(MessageType::try_from(0x00).is_err());
        assert!(MessageType::try_from(0x1F).is_err());
        assert!(MessageType::try_from(0xFF).is_err());
    }

    #[test]
    fn relay_type_values_are_stable() {
        assert_eq!(u8::from(MessageType::RelaySessionRequest), 0x20);
        assert_eq!(u8::from(MessageType::RelaySessionClose), 0x26);
    }
}
