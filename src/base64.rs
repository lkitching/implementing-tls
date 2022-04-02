use std::fmt::{self, Write};

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