use std::io::{BufRead};
use crate::base64;

// TODO: return Result
pub fn decode<R: BufRead>(mut r: R) -> Vec<u8> {
    {
        // first line should be header
        let mut header = String::new();
        let bytes_read = r.read_line(&mut header).expect("Failed to read header line");

        if !header.starts_with("-----BEGIN") {
            panic!("Invalid PEM header");
        }
    }

    let mut result = Vec::new();

    for line in r.lines().take_while(|line| line.is_ok() && !line.as_ref().unwrap().starts_with("-----END")) {
        let bytes = base64::decode(line.unwrap().as_str()).expect("Invalid base64");
        result.extend_from_slice(&bytes);
    }

    result
}