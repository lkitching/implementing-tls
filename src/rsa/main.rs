use std::{env, process};

use implementing_tls::{hex};
use implementing_tls::rsa::{self, TEST_PUBLIC_KEY, TEST_PRIVATE_KEY, TEST_MODULUS};
use implementing_tls::huge::{Huge};


enum Operation { Encrypt,  Decrypt }

fn invalid_usage(prog_name: &str) -> ! {
    eprintln!("Usage: {} [-e|-d] [<modulus> <exponent>] <data>", prog_name);
    process::exit(1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    let prog_name = args[0].as_str();
    let op = match args.get(1).map(|s| s.as_str()) {
        None => { invalid_usage(prog_name) },
        Some("-e") => {
            Operation::Encrypt
        },
        Some("-d") => {
            Operation::Decrypt
        },
        _ => {
            eprintln!("Invalid operation - expected -e or -d");
            invalid_usage(prog_name);
        }
    };

    let (key, data) = match args.len() {
        5 => {
            let modulus = hex::read_bytes(args[2].as_str()).expect("Invalid modulus");
            let exponent = hex::read_bytes(args[3].as_str()).expect("Invalid exponent");
            let data = hex::read_bytes(args[4].as_str()).expect("Invalid hex data");
            let key = rsa::RSAKey::new(Huge::from_bytes(&modulus), Huge::from_bytes(&exponent));
            (key, data)
        },
        3 => {
            let exponent: Vec<u8> = match op {
                Operation::Encrypt => TEST_PUBLIC_KEY.to_vec(),
                Operation::Decrypt => TEST_PRIVATE_KEY.to_vec()
            };

            let key = rsa::RSAKey::new(Huge::from_bytes(&TEST_MODULUS), Huge::from_bytes(&exponent));
            let data = hex::read_bytes(args[2].as_str()).expect("Invalid hex data");
            (key, data)
        },
        _ => {
            invalid_usage(prog_name);
        }
    };

    let result = match op {
        Operation::Encrypt => rsa::rsa_encrypt(&key, &data),
        Operation::Decrypt => rsa::rsa_decrypt(&key, &data)
    };

    hex::show_hex(&result);
}