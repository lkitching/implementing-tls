use std::{env, process, fs};
use std::io::{self, Read, Cursor, BufRead};

use implementing_tls::{asn1, base64, pem, files};

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} [-der|-pem] <certificate file>", args[0]);
        process::exit(1);
    }

    let format = files::parse_certificate_file_format_option(args[1].as_str()).expect("Invalid file format");
    match files::decode_certificate_file(args[2].as_str(), format) {
        Ok(bytes) => {
            let cert = asn1::parse(&bytes[..]).expect("Failed to parse ASN1");
            asn1::pretty_print(&cert);
        },
        Err(e) => {
            eprintln!("Failed to decode certificate: {}", e);
            process::exit(2);
        }
    }
}