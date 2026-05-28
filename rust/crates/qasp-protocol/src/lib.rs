#![forbid(unsafe_code)]

//! Foundational protocol types for QASP.

pub mod error;
pub mod state;

pub use error::{error_code_for_kind, ProtocolErrorKind, QaspErrorCode};
pub use state::ConnectionState;
