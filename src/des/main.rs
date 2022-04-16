use clap::{arg, Command};

use implementing_tls::des;

pub fn main() {
    let matches = Command::new("des")
        .arg(arg!([key] "The key to encrypt with").required(true))
        .arg(arg!([iv] "The Initial Vector to use for CBC mode").required(true))
        .arg(arg!([plaintext] "The plaintext to encrypt").required(true))
        .get_matches();

    let key = matches.value_of("key").unwrap();
    let iv = matches.value_of("iv").unwrap();
    let plaintext = matches.value_of("plaintext").unwrap();

    let ciphertext = des::des_encrypt(plaintext.as_bytes(), iv.as_bytes(), key.as_bytes());

    for b in ciphertext.iter() {
        print!("{:x}", b);
    }
    println!();
}