use std::{env, process};

use implementing_tls::{files, x509};

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} [-pem|-der] [certificate file]", args[0]);
        process::exit(1);
    }

    let format = files::parse_certificate_file_format_option(args[1].as_str()).expect("Invalid file format");
    match files::decode_certificate_file(args[2].as_str(), format) {
        Ok(bytes) => {
            let cert = x509::parse(&bytes[..]).expect("Failed to parse certificate");
            x509::pretty_print(&cert);

            match x509::verify_self_signed_certificate(&cert) {
                Ok(_) => {
                    println!("Certificate self-signature is valid!")
                },
                Err(e) => {
                    eprintln!("Could not verify self-signed certificate");
                    process::exit(3)
                }

            }
        },
        Err(e) => {
            eprintln!("Failed to decode certificate: {}", e);
            process::exit(2);
        }
    }
}