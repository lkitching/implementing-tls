use std::{env, process};

use implementing_tls::{md5, hex, sha};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} [-sha1|-md5] input", args[0]);
        process::exit(1);
    }

    let bytes = args[2].as_bytes();

    let hash_bytes = match args[1].as_str() {
        "-md5" => {
            let md5_result = md5::md5_hash(bytes);
            md5::md5_hash_bytes(md5_result).to_vec()
        },
        "-sha1" => {
            let sha1_result = sha::sha1_hash(bytes);
            sha::sha1_hash_bytes(sha1_result).to_vec()
        }
        _ => {
            eprintln!("Invalid hash function {}", args[1]);
            process::exit(1);
        }
    };

    hex::show_hex(&hash_bytes);
}