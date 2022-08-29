use std::{io, process};

use clap::{arg, Command};

use implementing_tls::{rc4, hex};

pub fn main() {
    let matches = Command::new("rc4")
        .arg(arg!([key] "The key to encrypt with").required(true))
        .arg(arg!([input] "The plaintext to encrypt or ciphertext to decrypt").required(true))
        .get_matches();

    let key = hex::read_bytes(matches.value_of("key").unwrap()).expect("Invalid key");
    let input = hex::read_bytes(matches.value_of("input").unwrap()).expect("Invalid input");

    let mut state = rc4::Rc4State::new();
    let output = state.operate(&input, &key);

    hex::show_hex(&output);
}