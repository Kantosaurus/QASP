#![forbid(unsafe_code)]

//! Wire-level identifiers and framing primitives for QASP.
//!
//! This initial crate deliberately stops before payload serialization and
//! frame authentication. Those depend on the canonical signed encoding and
//! cryptographic choices for the new Rust authority.

pub mod frame;
pub mod message_type;

pub use frame::{FrameError, FrameHeader, FRAME_MAGIC, FRAME_VERSION, HEADER_SIZE, HMAC_SIZE};
pub use message_type::MessageType;
