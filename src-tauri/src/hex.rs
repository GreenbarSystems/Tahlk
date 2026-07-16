//! Lowercase hex encode/decode, dependency-free.
//!
//! Exists because `lock.rs` and `db_key.rs` each carried a byte-identical
//! private `to_hex` (down to the lookup table). Both feed hex into places
//! where a new crate dependency isn't worth it: the SQLCipher
//! `PRAGMA key = "x'HEX'"` blob and the PIN hash's stored
//! `iterations:salt_hex:hash_hex` format.
//!
//! NOT the only hex decoder in the crate, deliberately: `audio_crypto.rs`'s
//! `dek_hex_to_bytes` is fixed-size and error-returning by contract (it must
//! reject a wrong-length DEK loudly), whereas [`from_hex`] is variable-length
//! and returns `Option`. Merging them would force one caller to accept the
//! other's error semantics for no gain.

/// Encode bytes as lowercase hex.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a lowercase-or-uppercase hex string. `None` on odd length or any
/// non-hex byte — callers treat that as "stored value is corrupt/tampered"
/// rather than erroring, so the shape is `Option`, not `Result`.
pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both relocated verbatim from lock.rs's test module alongside the
    // functions they cover. Assertions unchanged.

    #[test]
    fn hex_roundtrip() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        let hex = to_hex(&bytes);
        assert_eq!(hex, "000fa5ff");
        assert_eq!(from_hex(&hex).unwrap(), bytes.to_vec());
    }

    #[test]
    fn from_hex_rejects_odd_length_and_non_hex() {
        assert!(from_hex("abc").is_none()); // odd length
        assert!(from_hex("zz").is_none()); // non-hex chars
        assert!(from_hex("").unwrap().is_empty());
    }
}
