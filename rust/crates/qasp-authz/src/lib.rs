#![forbid(unsafe_code)]

//! Authorization primitives for QASP.

pub mod arm;

pub use arm::{intersect_uris, is_attenuation, parse_uri, uri_matches, ArmUri, ArmUriError};
