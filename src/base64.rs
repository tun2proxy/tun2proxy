//! Minimal RFC 4648 base64 (standard alphabet, `=` padding), replacing `base64easy`.
//!
//! `decode` is strict like `base64::engine::general_purpose::STANDARD`: input length must be a
//! multiple of 4, padding is required and only allowed at the end, no whitespace, and the unused
//! trailing bits of the last symbol must be zero.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode<T: AsRef<[u8]>>(input: T) -> String {
    let input = input.as_ref();
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

fn sextet(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, String> {
    let input = input.as_ref();
    if input.len() % 4 != 0 {
        return Err("invalid base64 length".into());
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let chunks = input.len() / 4;
    for (i, chunk) in input.chunks(4).enumerate() {
        let last = i + 1 == chunks;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return Err("invalid base64 padding".into());
        }
        let mut n = 0u32;
        for (j, &c) in chunk[..4 - pad].iter().enumerate() {
            let v = sextet(c).ok_or_else(|| format!("invalid base64 byte at offset {}", i * 4 + j))?;
            n |= v << (18 - 6 * j);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = 3 - pad;
        // Non-canonical encodings (non-zero unused bits) are rejected.
        if bytes[keep..].iter().any(|&b| b != 0) {
            return Err("invalid base64 trailing bits".into());
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    // RFC 4648 section 10 test vectors.
    const VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc4648_encode() {
        for (plain, b64) in VECTORS {
            assert_eq!(encode(plain), *b64, "encode {plain:?}");
        }
    }

    #[test]
    fn rfc4648_decode() {
        for (plain, b64) in VECTORS {
            assert_eq!(decode(b64).unwrap(), plain.as_bytes(), "decode {b64:?}");
        }
    }

    #[test]
    fn standard_alphabet_uses_plus_and_slash() {
        assert_eq!(encode([0xfb, 0xff, 0xbf]), "+/+/");
        assert_eq!(decode("+/+/").unwrap(), vec![0xfb, 0xff, 0xbf]);
    }

    #[test]
    fn roundtrip_all_lengths_and_bytes() {
        let data: Vec<u8> = (0..=255u8).collect();
        for len in 0..data.len() {
            let e = encode(&data[..len]);
            assert_eq!(e.len(), len.div_ceil(3) * 4);
            assert_eq!(decode(&e).unwrap(), &data[..len]);
        }
    }

    #[test]
    fn basic_auth_example() {
        // RFC 7617 section 2 example.
        assert_eq!(encode("Aladdin:open sesame"), "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in ["Zg", "Zg=", "Z===", "Zg==Zg==", "Zm9v YmFy", "Zm9-", "Zh==", "Zm9=", "=Zg="] {
            assert!(decode(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
