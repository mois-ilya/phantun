//! XOR payload obfuscation with fixed-overhead envelope and heartbeat support.
//!
//! Packet wire format (before XOR):
//!   `[IV: 8 bytes] [marker: 1 byte: 'b' = data | 'h' = heartbeat] [payload-or-filler]`
//!
//! All bytes are XOR'd with the key (cycling).
//! The marker byte allows the receiver to verify decryption used the correct key
//! AND to distinguish data packets from heartbeat filler.
//!
//! Overhead is a constant 9 bytes. Heartbeats use a fixed 1200-byte random filler so
//! that on-wire packet sizes collapse into two buckets (data ≈ UDP payload + 9,
//! heartbeat ≈ 1209), mimicking udp2raw's size pattern for DPI resistance.
//!
//! **Known limitation:** the marker byte is only 1 byte, so with a random IV a wrong
//! key yields `'b'` or `'h'` with probability 2/256 ≈ 0.78%. Those packets will be
//! accepted — Data frames with a corrupt payload get forwarded to UDP, Heartbeat
//! frames are silently dropped. A magic/HMAC could close this, but is intentionally
//! omitted to match udp2raw's lightweight envelope.

use rand::{RngCore, random};

const OVERHEAD: usize = 9; // 8 IV + 1 marker
const MARKER_DATA: u8 = b'b';
const MARKER_HEARTBEAT: u8 = b'h';

/// Decoded message variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedMessage {
    /// Real data payload.
    Data(Vec<u8>),
    /// Heartbeat filler (discard on receive).
    Heartbeat,
}

fn xor_apply(key: &[u8], data: &mut [u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn encode_with_marker(key: &[u8], marker: u8, body: &[u8]) -> Vec<u8> {
    let iv: [u8; 8] = random();
    let mut buf = Vec::with_capacity(OVERHEAD + body.len());
    buf.extend_from_slice(&iv);
    buf.push(marker);
    buf.extend_from_slice(body);
    xor_apply(key, &mut buf);
    buf
}

/// Encode a data payload (marker 'b').
pub fn encode(key: &[u8], payload: &[u8]) -> Vec<u8> {
    encode_with_marker(key, MARKER_DATA, payload)
}

/// Encode a heartbeat packet (marker 'h') containing `size` bytes of random filler.
pub fn encode_heartbeat(key: &[u8], size: usize) -> Vec<u8> {
    let iv: [u8; 8] = random();
    let mut buf = vec![0u8; OVERHEAD + size];
    buf[..8].copy_from_slice(&iv);
    buf[8] = MARKER_HEARTBEAT;
    if size > 0 {
        rand::rng().fill_bytes(&mut buf[OVERHEAD..]);
    }
    xor_apply(key, &mut buf);
    buf
}

/// Decode a packet: decrypt envelope and classify as Data or Heartbeat.
/// Returns None if the buffer is too short or the marker byte is unknown
/// (e.g., wrong key or corrupted data).
///
/// Hot path: only allocates for `Data` (a single `Vec` containing the decrypted
/// payload). `Heartbeat` and rejection paths allocate nothing.
pub fn decode(key: &[u8], data: &[u8]) -> Option<DecodedMessage> {
    if data.len() < OVERHEAD {
        return None;
    }
    // Classify by XOR'ing just the marker byte first — avoids any allocation
    // for heartbeat/reject paths (heartbeat runs every 600ms).
    let marker = data[8] ^ key[8 % key.len()];
    match marker {
        MARKER_HEARTBEAT => Some(DecodedMessage::Heartbeat),
        MARKER_DATA => {
            let mut payload = data[OVERHEAD..].to_vec();
            // Apply XOR starting at stream offset OVERHEAD.
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[(OVERHEAD + i) % key.len()];
            }
            Some(DecodedMessage::Data(payload))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"test-key-123";

    #[test]
    fn test_encode_decode_data_roundtrip() {
        let payload = b"hello, phantun world";
        let encoded = encode(KEY, payload);
        let decoded = decode(KEY, &encoded).expect("decode succeeds");
        assert_eq!(decoded, DecodedMessage::Data(payload.to_vec()));
    }

    #[test]
    fn test_encode_decode_empty_payload() {
        let encoded = encode(KEY, b"");
        assert_eq!(encoded.len(), OVERHEAD);
        let decoded = decode(KEY, &encoded).expect("decode succeeds");
        assert_eq!(decoded, DecodedMessage::Data(Vec::new()));
    }

    #[test]
    fn test_encode_heartbeat_decodes_as_heartbeat() {
        let encoded = encode_heartbeat(KEY, 1200);
        assert_eq!(encoded.len(), OVERHEAD + 1200);
        let decoded = decode(KEY, &encoded).expect("decode succeeds");
        assert_eq!(decoded, DecodedMessage::Heartbeat);
    }

    #[test]
    fn test_encode_heartbeat_zero_size() {
        let encoded = encode_heartbeat(KEY, 0);
        assert_eq!(encoded.len(), OVERHEAD);
        let decoded = decode(KEY, &encoded).expect("decode succeeds");
        assert_eq!(decoded, DecodedMessage::Heartbeat);
    }

    #[test]
    fn test_decode_wrong_key_returns_none() {
        // With random IV + 1-byte marker, a wrong key almost certainly yields
        // a marker byte that is not 'b' or 'h'. Run many trials to make the
        // test statistically robust: probability of false accept per trial is
        // 2/256, so 200 trials gives ~0 chance of all accepting.
        let payload = b"secret";
        let wrong_key: &[u8] = b"another-key";
        let mut rejections = 0;
        for _ in 0..200 {
            let encoded = encode(KEY, payload);
            if decode(wrong_key, &encoded).is_none() {
                rejections += 1;
            }
        }
        // Expect vast majority to reject. Allow a small slack for the 2/256 collisions.
        assert!(rejections > 180, "expected >180 rejections, got {rejections}");
    }

    #[test]
    fn test_decode_too_short_returns_none() {
        assert!(decode(KEY, &[]).is_none());
        assert!(decode(KEY, &[0u8; 1]).is_none());
        assert!(decode(KEY, &[0u8; 8]).is_none());
    }

    #[test]
    fn test_decode_exact_overhead_length_with_crafted_marker() {
        // Boundary: buf.len() == OVERHEAD (9). Zero-length body.
        // Craft an envelope with an unknown marker and verify rejection.
        let mut buf = vec![0u8; OVERHEAD];
        buf[8] = b'z';
        xor_apply(KEY, &mut buf);
        assert_eq!(buf.len(), OVERHEAD);
        assert!(decode(KEY, &buf).is_none());

        // Same boundary, but with a valid Heartbeat marker → accepted.
        let encoded = encode_heartbeat(KEY, 0);
        assert_eq!(encoded.len(), OVERHEAD);
        assert_eq!(decode(KEY, &encoded), Some(DecodedMessage::Heartbeat));
    }

    #[test]
    fn test_encode_produces_distinct_outputs_for_same_input() {
        // IV must be random — encoding the same payload twice must yield
        // different ciphertexts (otherwise IV randomness is broken).
        let payload = b"identical payload";
        let a = encode(KEY, payload);
        let b = encode(KEY, payload);
        assert_ne!(a, b, "encode must produce distinct outputs (random IV)");
    }

    #[test]
    fn test_encode_heartbeat_produces_distinct_outputs() {
        let a = encode_heartbeat(KEY, 1200);
        let b = encode_heartbeat(KEY, 1200);
        assert_ne!(a, b, "encode_heartbeat must produce distinct outputs");
    }

    #[test]
    fn test_encode_heartbeat_filler_is_random() {
        // Decrypt two heartbeats and verify their filler bodies differ and
        // are not all-zero. Catches regressions where filler was left as
        // default-zero bytes (marker-only packet).
        const SIZE: usize = 1200;

        fn decrypt_filler(buf: &[u8]) -> Vec<u8> {
            let mut copy = buf.to_vec();
            xor_apply(KEY, &mut copy);
            copy[OVERHEAD..].to_vec()
        }

        let a = decrypt_filler(&encode_heartbeat(KEY, SIZE));
        let b = decrypt_filler(&encode_heartbeat(KEY, SIZE));

        assert_eq!(a.len(), SIZE);
        assert_eq!(b.len(), SIZE);
        assert_ne!(a, b, "heartbeat filler must be random, not constant");
        assert!(
            a.iter().any(|&x| x != 0),
            "heartbeat filler must not be all-zero"
        );
    }

    #[test]
    fn test_decode_unknown_marker_returns_none() {
        // Build an envelope with a deliberately wrong marker byte, then XOR-encrypt.
        let mut buf = vec![0u8; OVERHEAD];
        // IV = zeros is fine for this test.
        buf[8] = b'x'; // unknown marker
        xor_apply(KEY, &mut buf);
        assert!(decode(KEY, &buf).is_none());
    }

    #[test]
    fn test_overhead_is_nine_bytes() {
        let encoded = encode(KEY, b"");
        assert_eq!(encoded.len(), 9);
    }
}
