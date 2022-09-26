use std::env;

use implementing_tls::{md5, hex};

fn main() {
    let args: Vec<String> = env::args().collect();
    let bytes = args[1].as_bytes();
    let md5_result = md5::md5_hash(bytes);
    let md5_bytes = md5::md5_hash_bytes(md5_result);

    hex::show_hex(&md5_bytes);
}