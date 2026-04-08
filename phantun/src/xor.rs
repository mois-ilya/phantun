/// XOR payload obfuscation matching udp2raw's `--cipher-mode xor` format.
///
/// Packet wire format (before XOR):
///   [IV: 8 bytes] [padding: 8 bytes] ['b': 1 byte] [payload]
///
/// All bytes are XOR'd with the key (cycling).
/// The 'b' marker allows the receiver to verify decryption used the correct key.

use rand::random;

fn xor_apply(key: &[u8], data: &mut [u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// Encode payload: wrap in udp2raw XOR envelope and encrypt.
pub fn encode(key: &[u8], payload: &[u8]) -> Vec<u8> {
    let iv: [u8; 8] = random();
    let padding: [u8; 8] = random();
    let mut buf = Vec::with_capacity(17 + payload.len());
    buf.extend_from_slice(&iv);
    buf.extend_from_slice(&padding);
    buf.push(b'b');
    buf.extend_from_slice(payload);
    xor_apply(key, &mut buf);
    buf
}

/// Decode payload: decrypt and unwrap udp2raw XOR envelope.
/// Returns None if packet is too short or marker byte is wrong (bad key or corrupt packet).
pub fn decode(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 17 {
        return None;
    }
    let mut buf = data.to_vec();
    xor_apply(key, &mut buf);
    if buf[16] != b'b' {
        return None;
    }
    Some(buf[17..].to_vec())
}
