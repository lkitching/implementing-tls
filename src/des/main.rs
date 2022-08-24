use std::{io, process};

use clap::{arg, Command};

use implementing_tls::des;
use implementing_tls::hex;

pub fn main() {
    let matches = Command::new("des")
        .arg(arg!([mode] "encrypt|decrypt").required(true))
        .arg(arg!([key] "The key to encrypt with").required(true))
        .arg(arg!([iv] "The Initial Vector to use for CBC mode").required(true))
        .arg(arg!([input] "The plaintext to encrypt or ciphertext to decrypt").required(true))
        .get_matches();

    let key = hex::read_bytes(matches.value_of("key").unwrap()).expect("Invalid key");
    let iv = hex::read_bytes(matches.value_of("iv").unwrap()).expect("Invalid IV");
    let input = hex::read_bytes(matches.value_of("input").unwrap()).expect("Invalid input");

    match matches.value_of("mode").unwrap() {
        "encrypt" => {
            let mut hw = hex::HexWriter::new(io::stdout());

            let result = if key.len() == 24 {
                //des::des3_encrypt(&input, &iv, &key)
                des::des_encrypt_process(des::TripleDesEncryptBlockOperation {}, &input, &iv, &key, &mut hw)
            } else {
                //des::des_encrypt(&input, &iv, &key)
                des::des_encrypt_process(des::DesEncryptBlockOperation {}, &input, &iv, &key, &mut hw)
            };

            if let Err(e) = result {
                println!("Failed to encrypt: {}", e);
                process::exit(1);
            }
        },
        "decrypt" => {
            let mut hw = hex::HexWriter::new(io::stdout());

            let result = if key.len() == 24 {
                //des::des3_decrypt(&input, &iv, &key)
                des::des_decrypt_process(des::TripleDesDecryptBlockOperation {}, &input, &iv, &key, &mut hw)
            } else {
                //des::des_decrypt(&input, &iv, &key)
                des::des_decrypt_process(des::DesDecryptBlockOperation {}, &input, &iv, &key, &mut hw)
            };

            if let Err(e) = result {
                println!("Failed to decrypt: {}", e);
                process::exit(1);
            }
        },
        _ => {
            eprintln!("Invalid mode - expected encrypt or decrypt");
            process::exit(1);
        }
    }
}