use std::{env, process, fs};
use std::io::{self, Read, Cursor, BufRead};

use implementing_tls::{asn1, base64};

// TODO: move into pem namespace?
// TODO: return Result
fn pem_decode<R: BufRead>(mut r: R) -> Vec<u8> {
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

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} [-der|-pem] <certificate file>", args[0]);
        process::exit(1);
    }

    let mut f = fs::File::open(args[2].as_str()).expect("Failed to open certificate file");
    let mut bytes = Vec::new();
    let bytes_read = f.read_to_end(&mut bytes).expect("Failed to read certficate file");

    let cert = match args[1].as_str() {
        "-der" => {
            asn1::parse(&bytes[..]).expect("Failed to parse ASN1")
        },
        "-pem" => {
            let cert_bytes = pem_decode(&bytes[..]);
            asn1::parse(&cert_bytes[..]).expect("Failed to parse ASN1")
        },
        _ => {
            eprintln!("Expected -der or -pem format");
            process::exit(2);
        }
    };

    asn1::pretty_print(&cert);
}