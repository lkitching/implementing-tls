use std::process;

use clap::{arg, Command};

use implementing_tls::des;

fn show_hex(bytes: &[u8]) {
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();
}

fn parse_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 == 0 {
        let mut result = Vec::with_capacity(hex_str.len() / 2);
        let mut i = 0;
        while i < hex_str.len() {
            let byte_str = &hex_str[i .. i + 2];
            let b = u8::from_str_radix(byte_str, 16).map_err(|_| format!("Invalid byte {}", byte_str))?;
            result.push(b);
            i += 2;
        }
        Ok(result)
    } else {
        Err("Expected even number of hex characters".to_owned())
    }
}

fn read_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.starts_with("0x") {
        parse_hex(&s[2..])
    } else {
        Ok(s.bytes().collect())
    }
}

pub fn main() {
    let matches = Command::new("des")
        .arg(arg!([mode] "encrypt|decrypt").required(true))
        .arg(arg!([key] "The key to encrypt with").required(true))
        .arg(arg!([iv] "The Initial Vector to use for CBC mode").required(true))
        .arg(arg!([input] "The plaintext to encrypt or ciphertext to decrypt").required(true))
        .get_matches();

    let key = read_bytes(matches.value_of("key").unwrap()).expect("Invalid key");
    let iv = read_bytes(matches.value_of("iv").unwrap()).expect("Invalid IV");
    let input = read_bytes(matches.value_of("input").unwrap()).expect("Invalid input");

    match matches.value_of("mode").unwrap() {
        "encrypt" => {
            let ciphertext = if key.len() == 24 {
                des::des3_encrypt(&input, &iv, &key)
            } else {
                des::des_encrypt(&input, &iv, &key)
            };

            show_hex(&ciphertext);
        },
        "decrypt" => {
            let plaintext = if key.len() == 24 {
                des::des3_decrypt(&input, &iv, &key)
            } else {
                des::des_decrypt(&input, &iv, &key)
            };

            show_hex(&plaintext);
        },
        _ => {
            eprintln!("Invalid mode - expected encrypt or decrypt");
            process::exit(1);
        }
    }

}