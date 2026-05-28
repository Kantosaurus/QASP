use crate::message_type::{MessageType, UnknownMessageType};
use core::fmt;

pub const FRAME_MAGIC: [u8; 2] = [0x51, 0x41];
pub const FRAME_VERSION: u8 = 0x01;
pub const HEADER_SIZE: usize = 8;
pub const HMAC_SIZE: usize = 48;

/// A parsed QASP frame header. Payload serialization and authentication are
/// intentionally owned by later migration slices.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FrameHeader {
    pub magic: [u8; 2],
    pub version: u8,
    pub message_type: MessageType,
    pub payload_length: u32,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrameError {
    IncompleteHeader { actual: usize },
    InvalidMagic { actual: [u8; 2] },
    UnsupportedVersion { actual: u8 },
    UnknownMessageType { actual: u8 },
    FrameLengthOverflow,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteHeader { actual } => write!(
                formatter,
                "insufficient data for QASP header: need {}, got {}",
                HEADER_SIZE, actual
            ),
            Self::InvalidMagic { actual } => write!(
                formatter,
                "invalid QASP frame magic: expected {:?}, got {:?}",
                FRAME_MAGIC, actual
            ),
            Self::UnsupportedVersion { actual } => write!(
                formatter,
                "unsupported QASP frame version: expected {}, got {}",
                FRAME_VERSION, actual
            ),
            Self::UnknownMessageType { actual } => {
                write!(formatter, "unknown QASP message type: 0x{:02x}", actual)
            }
            Self::FrameLengthOverflow => formatter.write_str("QASP frame length overflow"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<UnknownMessageType> for FrameError {
    fn from(error: UnknownMessageType) -> Self {
        Self::UnknownMessageType { actual: error.0 }
    }
}

impl FrameHeader {
    pub fn new(message_type: MessageType, payload_length: u32) -> Self {
        Self {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            message_type,
            payload_length,
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < HEADER_SIZE {
            return Err(FrameError::IncompleteHeader { actual: data.len() });
        }

        let magic = [data[0], data[1]];
        if magic != FRAME_MAGIC {
            return Err(FrameError::InvalidMagic { actual: magic });
        }
        if data[2] != FRAME_VERSION {
            return Err(FrameError::UnsupportedVersion { actual: data[2] });
        }

        let message_type = MessageType::try_from(data[3])?;
        let payload_length = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        Ok(Self {
            magic,
            version: data[2],
            message_type,
            payload_length,
        })
    }

    pub fn to_bytes(self) -> [u8; HEADER_SIZE] {
        let payload_length = self.payload_length.to_be_bytes();
        [
            self.magic[0],
            self.magic[1],
            self.version,
            self.message_type.into(),
            payload_length[0],
            payload_length[1],
            payload_length[2],
            payload_length[3],
        ]
    }

    pub fn total_authenticated_frame_length(self) -> Result<usize, FrameError> {
        HEADER_SIZE
            .checked_add(self.payload_length as usize)
            .and_then(|size| size.checked_add(HMAC_SIZE))
            .ok_or(FrameError::FrameLengthOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameError, FrameHeader, FRAME_MAGIC, FRAME_VERSION, HEADER_SIZE, HMAC_SIZE};
    use crate::MessageType;

    #[test]
    fn header_round_trips() {
        let header = FrameHeader::new(MessageType::ClientHello, 1024);
        let bytes = header.to_bytes();
        assert_eq!(FrameHeader::from_bytes(&bytes), Ok(header));
    }

    #[test]
    fn header_has_expected_wire_layout() {
        let bytes = FrameHeader::new(MessageType::ApplicationData, 0x0102_0304).to_bytes();
        assert_eq!(&bytes[0..2], &FRAME_MAGIC);
        assert_eq!(bytes[2], FRAME_VERSION);
        assert_eq!(bytes[3], 0x04);
        assert_eq!(&bytes[4..8], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(
            FrameHeader::from_bytes(&[0u8; HEADER_SIZE - 1]),
            Err(FrameError::IncompleteHeader {
                actual: HEADER_SIZE - 1
            })
        );
    }

    #[test]
    fn invalid_magic_version_and_type_are_rejected() {
        let mut bytes = FrameHeader::new(MessageType::Alert, 0).to_bytes();
        bytes[0] = 0;
        assert!(matches!(
            FrameHeader::from_bytes(&bytes),
            Err(FrameError::InvalidMagic { .. })
        ));

        let mut bytes = FrameHeader::new(MessageType::Alert, 0).to_bytes();
        bytes[2] = 99;
        assert_eq!(
            FrameHeader::from_bytes(&bytes),
            Err(FrameError::UnsupportedVersion { actual: 99 })
        );

        let mut bytes = FrameHeader::new(MessageType::Alert, 0).to_bytes();
        bytes[3] = 0x1F;
        assert_eq!(
            FrameHeader::from_bytes(&bytes),
            Err(FrameError::UnknownMessageType { actual: 0x1F })
        );
    }

    #[test]
    fn authenticated_length_reserves_hmac_bytes() {
        let header = FrameHeader::new(MessageType::ApplicationData, 10);
        assert_eq!(
            header.total_authenticated_frame_length().unwrap(),
            HEADER_SIZE + 10 + HMAC_SIZE
        );
    }
}
