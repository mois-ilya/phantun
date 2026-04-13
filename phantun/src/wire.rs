//! Shared wire helpers for client/server binaries.
//!
//! Pulls the XOR envelope encode/classify hot-path code and the heartbeat
//! cadence constants into one place so client.rs and server.rs stay in sync.

use crate::xor;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

/// Size of the random filler in each heartbeat packet (before envelope overhead).
/// Combined on-wire size is `HEARTBEAT_SIZE + xor::OVERHEAD`.
pub const HEARTBEAT_SIZE: usize = 1200;

/// Cadence at which heartbeats are emitted while a tunnel is up.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(600);

/// Encode outgoing payload. Returns a borrowed slice when no key is set
/// (zero-alloc hot path) and an owned encoded buffer otherwise.
pub fn encode_payload<'a>(key: &Option<Arc<Vec<u8>>>, payload: &'a [u8]) -> Cow<'a, [u8]> {
    match key {
        Some(k) => Cow::Owned(xor::encode(k, payload)),
        None => Cow::Borrowed(payload),
    }
}

/// Classification of an incoming TCP payload, for the recv hot path.
pub enum Incoming<'a> {
    /// Decoded data to forward on to UDP (borrowed when no key, owned when decoded).
    Data(Cow<'a, [u8]>),
    /// Valid heartbeat — discard silently.
    Heartbeat,
    /// Decode failed (bad marker / too short / wrong key).
    DecodeFailed,
}

/// Classify an incoming payload. With no key, always `Incoming::Data` (zero-alloc).
pub fn classify_incoming<'a>(key: &Option<Arc<Vec<u8>>>, data: &'a [u8]) -> Incoming<'a> {
    match key {
        Some(k) => match xor::decode(k, data) {
            Some(xor::DecodedMessage::Data(v)) => Incoming::Data(Cow::Owned(v)),
            Some(xor::DecodedMessage::Heartbeat) => Incoming::Heartbeat,
            None => Incoming::DecodeFailed,
        },
        None => Incoming::Data(Cow::Borrowed(data)),
    }
}
