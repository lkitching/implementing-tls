use std::{env, process, io};

use implementing_tls::{md5, hex, sha};
use implementing_tls::hash::{HashAlgorithm, hash};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} [-sha1|-md5] input", args[0]);
        process::exit(1);
    }

    let bytes = args[2].as_bytes();
    let mut c = io::Cursor::new(bytes.to_vec());

    let hash_bytes = match args[1].as_str() {
        "-md5" => {
            hash(&mut c, &md5::MD5HashAlgorithm {}).expect("Failed to calculate MD5 hash")
        },
        "-sha1" => {
            hash(&mut c, &sha::SHA1HashAlgorithm{}).expect("Failed to calculate SHA1 hash")
        },
        "-sha256" => {
            hash(&mut c, &sha::SHA256HashAlgorithm {}).expect("Failed to calculate SHA256 hash")
        }
        _ => {
            eprintln!("Invalid hash function {}", args[1]);
            process::exit(1);
        }
    };

    hex::show_hex(&hash_bytes);
}