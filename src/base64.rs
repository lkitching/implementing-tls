use std::fmt::{self, Write};
use std::collections::HashMap;
use crate::base64::Base64Error::InvalidLength;

pub struct Base64 {
    chars: Vec<Base64Char>
}

static CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        for c in self.chars.iter() {
            match c {
                Base64Char::Padding => { f.write_char('=')?; },
                Base64Char::U6(b) => {
                    let c = CHARS.as_bytes()[*b as usize] as char;
                    f.write_char(c)?;
                }
            }
        }
        Ok(())
    }
}

enum Base64Char {
    Padding,
    U6(u8)
}

pub fn encode(bytes: &[u8]) -> Base64 {
    let output_chunks = if bytes.len() % 3 == 0 { bytes.len() / 3 } else { bytes.len() / 3 + 1 };
    let mut result: Vec<Base64Char> = Vec::with_capacity(output_chunks * 4);

    let mut chunks = bytes.chunks_exact(3);

    while let Some(c) = chunks.next() {
        result.push(Base64Char::U6((c[0] & 0xfc) >> 2));
        result.push(Base64Char::U6(((c[0] & 0x03) << 4) | ((c[1] & 0xf0) >> 4)));
        result.push(Base64Char::U6(((c[1] & 0x0f) << 2) | ((c[2] & 0xc0) >> 6)));
        result.push(Base64Char::U6(c[2] & 0x3f));
    }

    let rem = chunks.remainder();
    match rem.len() {
        0 => {},
        1 => {
            result.push(Base64Char::U6((rem[0] & 0xfc) >> 2));
            result.push(Base64Char::U6((rem[0] & 0x03) << 4));
            result.push(Base64Char::Padding);
            result.push(Base64Char::Padding);
        },
        _ => {
            result.push(Base64Char::U6((rem[0] & 0xfc) >> 2));
            result.push(Base64Char::U6(((rem[0] & 0x03) << 4) | ((rem[1] & 0xf0) >> 4)));
            result.push(Base64Char::U6((rem[1] & 0x0f) << 2));
            result.push(Base64Char::Padding);
        }
    }

    Base64 { chars: result }
}

fn get_char_lookup() -> HashMap<u8, u8> {
    CHARS.as_bytes().iter().enumerate().map(|(idx, byte)| (*byte, idx as u8)).collect()
}

pub fn encode_string(bytes: &[u8]) -> String {
    let encoded = encode(bytes);
    format!("{}", encoded)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    InvalidLength,
    InvalidChar(char, usize),
    ExpectedEnd(usize)
}

fn decode_byte(bytes: &[u8], index: usize, mapping: &HashMap<u8, u8>) -> Result<u8, Base64Error> {
    let b = bytes[index];

    match mapping.get(&b) {
        None => Err(Base64Error::InvalidChar(b as char, index)),
        Some(m) => Ok(*m)
    }
}

pub fn decode(s: &str) -> Result<Vec<u8>, Base64Error> {
    // TODO: Use chars()? Slice should contain only ASCII to be valid anyway
    let bytes = s.as_bytes();

    // TODO: cache?
    let lookup = get_char_lookup();

    if bytes.len() % 4 != 0 {
        return Err(InvalidLength);
    }

    // each 4-char chunk encodes up to 3 bytes
    let mut result = Vec::with_capacity((bytes.len() / 4) * 3);
    let mut expect_end = false;

    for i in (0..bytes.len()).step_by(4) {
        if expect_end {
            return Err(Base64Error::ExpectedEnd(i));
        }

        // first 2 bytes in the segment must be mapped characters
        let s1 = decode_byte(bytes, i, &lookup)?;
        let s2 = decode_byte(bytes, i + 1, &lookup)?;

        // b1 is s1 | upper 2 bits of s2
        let b1 = (s1 << 2) | ((s2 & 0x30) >> 4);
        result.push(b1);

        let c3 = bytes[i + 2];
        let s3o = if c3 as char == '=' {
            // expect this to be the last segment
            // NOTE: next char should also be an '=' if this flag is set this iteration
            expect_end = true;
            None
        } else {
            let s3 = decode_byte(bytes, i + 2, &lookup)?;

            // b2 is low 4 bits of s2 | high 4 bits of s3
            let b2 = ((s2 & 0x0F) << 4) | ((s3 & 0x3C) >> 2);
            result.push(b2);
            Some(s3)
        };

        // b2 is lower 4 bits of s2 |
        let c4 = bytes[i + 3];
        if c4 as char == '=' {
        } else if expect_end {
            return Err(Base64Error::InvalidChar(c4 as char, i + 3));
        } else {
            let s3 = s3o.unwrap();
            let s4 = decode_byte(bytes, i + 3, &lookup)?;

            // b3 is lower 2 bits of s3 | s4
            let b3 = ((s3 & 0x03) << 6) | (s4 & 0x3F);
            result.push(b3);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_test() {
        let bytes = Vec::new();
        let encoded = encode_string(&bytes);

        assert_eq!("", encoded);

        let decoded = decode(encoded.as_str()).expect("Failed to decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn single_byte_test() {
        let bytes = "a".as_bytes();
        let encoded = encode_string(bytes);

        assert_eq!("YQ==", encoded);

        let decoded = decode(encoded.as_str()).expect("Failed to decode");
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn two_bytes_test() {
        let bytes = "th".as_bytes();
        let encoded = encode_string(bytes);

        assert_eq!("dGg=", encoded);

        let decoded = decode(encoded.as_str()).expect("Failed to decode");
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn three_bytes_test() {
        let bytes = "qui".as_bytes();
        let encoded = encode_string(bytes);

        assert_eq!("cXVp", encoded);

        let decoded = decode(encoded.as_str()).expect("Failed to decode");
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn invalid_length_test() {
        let s = "dGhlcXVpY2t";
        let result = decode(s);

        assert_eq!(Err(Base64Error::InvalidLength), result);
    }

    #[test]
    fn invalid_character_test() {
        let s = "dGhlcX!pY2ti";
        let result = decode(s);

        assert_eq!(Err(Base64Error::InvalidChar('!', 6)), result);
    }

    #[test]
    fn invalid_padding_test() {
        let s = "dGhlcXVpYw=a";
        let result = decode(s);

        assert_eq!(Err(Base64Error::InvalidChar('a', 11)), result);
    }

    #[test]
    fn invalid_end_test() {
        let s = "dGhlcXVpYw==xyzz";
        let result = decode(s);

        assert_eq!(Err(Base64Error::ExpectedEnd(12)), result);
    }
}