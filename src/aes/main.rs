use std::{io, process};
use clap::{arg, Command};

use implementing_tls::{hex, block, padding, aes};

pub fn main() {
    let matches = Command::new("aes")
        .arg(arg!([mode] "encrypt|decrypt").required(true))
        .arg(arg!([key] "The key to encrypt with").required(true))
        .arg(arg!([iv] "The Initial Vector to use for CBC mode").required(true))
        .arg(arg!([input] "The plaintext to encrypt or ciphertext to decrypt").required(true))
        .get_matches();

    let key = hex::read_bytes(matches.value_of("key").unwrap()).expect("Invalid key");
    let iv = hex::read_bytes(matches.value_of("iv").unwrap()).expect("Invalid IV");
    let input = hex::read_bytes(matches.value_of("input").unwrap()).expect("Invalid input");

    let mut writer = hex::HexWriter::new(io::stdout());

    match matches.value_of("mode").unwrap() {
        "encrypt" => {
            let mode = block::CBCEncryptMode::new(aes::AesEncryptBlockOperation {}, &iv);
            let c = io::Cursor::new(input);
            let r = padding::Pkcs5PaddingReader::new(c, aes::AES_BLOCK_SIZE);

            let mut encryptor = block::BlockOperationReader::new(mode, r, &key, aes::AES_BLOCK_SIZE);

            let result = io::copy(&mut encryptor, &mut writer);
            if let Err(e) = result {
                eprintln!("Failed to encrypt: {}", e);
                process::exit(1);
            }
        },
        "decrypt" => {
            let mode = block::CBCDecryptMode::new(aes::AesDecryptBlockOperation {}, &iv);
            let ciphertext_reader = io::Cursor::new(input);
            let decryptor = block::BlockOperationReader::new(mode, ciphertext_reader, &key, aes::AES_BLOCK_SIZE);
            let mut plaintext_reader = padding::Pkcs5PaddingUnreader::new(decryptor, aes::AES_BLOCK_SIZE);

            let result = io::copy(&mut plaintext_reader, &mut writer);
            if let Err(e) = result {
                eprintln!("Failed to decrypt: {}", e);
                process::exit(1);
            }
        },
        _ => {
            eprintln!("Invalid mode - expected encrypt or decrypt");
            process::exit(1);
        }
    }
}