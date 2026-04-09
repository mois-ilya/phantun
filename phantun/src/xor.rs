/// XOR payload obfuscation with variable-length padding.
///
/// Packet wire format (before XOR):
///   [IV: 8 bytes] [pad_len: 2 bytes LE] [random_padding: pad_len bytes] ['b': 1 byte] [payload]
///
/// All bytes are XOR'd with the key (cycling).
/// The 'b' marker allows the receiver to verify decryption used the correct key.
/// Variable padding hides fixed-size WireGuard handshake packets from size-based DPI.

use rand::random;

fn xor_apply(key: &[u8], data: &mut [u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// Encode payload: wrap in XOR envelope with random padding and encrypt.
///
/// `max_pad` — upper bound for random padding length (0 = no padding).
/// Caller should set max_pad = min(128, MAX_PACKET_LEN - OVERHEAD - payload.len())
/// to ensure the encoded packet fits in the receive buffer.
pub fn encode(key: &[u8], payload: &[u8], max_pad: u16) -> Vec<u8> {
    let iv: [u8; 8] = random();
    let pad_len: u16 = if max_pad > 0 {
        random::<u16>() % (max_pad + 1)
    } else {
        0
    };
    let mut buf = Vec::with_capacity(11 + pad_len as usize + payload.len());
    buf.extend_from_slice(&iv);
    buf.extend_from_slice(&pad_len.to_le_bytes());
    for _ in 0..pad_len {
        buf.push(random());
    }
    buf.push(b'b');
    buf.extend_from_slice(payload);
    xor_apply(key, &mut buf);
    buf
}

/// Decode payload: decrypt and unwrap XOR envelope.
/// Returns None if packet is too short, padding overflows, or marker byte is wrong.
pub fn decode(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    // minimum: 8 (IV) + 2 (pad_len) + 0 (padding) + 1 ('b') = 11 bytes
    if data.len() < 11 {
        return None;
    }
    let mut buf = data.to_vec();
    xor_apply(key, &mut buf);
    let pad_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let marker_pos = 10 + pad_len;
    if marker_pos >= buf.len() {
        return None;
    }
    if buf[marker_pos] != b'b' {
        return None;
    }
    Some(buf[marker_pos + 1..].to_vec())
}
