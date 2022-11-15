use std::io::Cursor;

use implementing_tls::dsa::{DSAParams, DSASignature, sign, verify};
use implementing_tls::huge::*;
use implementing_tls::{hash, sha, hex};

const PRIVATE_KEY: [u8; 20] = [
    0x53, 0x61, 0xae, 0x4f, 0x6f, 0x25, 0x98, 0xde, 0xc4, 0xbf, 0x0b, 0xbe, 0x09,
    0x5f, 0xdf, 0x90, 0x2f, 0x4c, 0x8e, 0x09
];

const PUBLIC_KEY: [u8; 64] = [
    0x1b, 0x91, 0x4c, 0xa9, 0x73, 0xdc, 0x06, 0x0d, 0x21, 0xc6, 0xff, 0xab, 0xf6,
    0xad, 0xf4, 0x11, 0x97, 0xaf, 0x23, 0x48, 0x50, 0xa8, 0xf3, 0xdb, 0x2e, 0xe6,
    0x27, 0x8c, 0x40, 0x4c, 0xb3, 0xc8, 0xfe, 0x79, 0x7e, 0x89, 0x48, 0x90, 0x27,
    0x92, 0x6f, 0x5b, 0xc5, 0xe6, 0x8f, 0x91, 0x4c, 0xe9, 0x4f, 0xed, 0x0d, 0x3c,
    0x17, 0x09, 0xeb, 0x97, 0xac, 0x29, 0x77, 0xd5, 0x19, 0xe7, 0x4d, 0x17
];

const P: [u8; 65] = [
    0x00, 0x9c, 0x4c, 0xaa, 0x76, 0x31, 0x2e, 0x71, 0x4d, 0x31, 0xd6, 0xe4, 0xd7,
    0xe9, 0xa7, 0x29, 0x7b, 0x7f, 0x05, 0xee, 0xfd, 0xca, 0x35, 0x14, 0x1e, 0x9f,
    0xe5, 0xc0, 0x2a, 0xe0, 0x12, 0xd9, 0xc4, 0xc0, 0xde, 0xcc, 0x66, 0x96, 0x2f,
    0xf1, 0x8f, 0x1a, 0xe1, 0xe8, 0xbf, 0xc2, 0x29, 0x0d, 0x27, 0x07, 0x48, 0xb9,
    0x71, 0x04, 0xec, 0xc7, 0xf4, 0x16, 0x2e, 0x50, 0x8d, 0x67, 0x14, 0x84, 0x7b
];

const Q: [u8; 21] = [
    0x00, 0xac, 0x6f, 0xc1, 0x37, 0xef, 0x16, 0x74, 0x52, 0x6a, 0xeb, 0xc5, 0xf8,
    0xf2, 0x1f, 0x53, 0xf4, 0x0f, 0xe0, 0x51, 0x5f
];

const G: [u8; 64] = [
    0x7d, 0xcd, 0x66, 0x81, 0x61, 0x52, 0x21, 0x10, 0xf7, 0xa0, 0x83, 0x4c, 0x5f,
    0xc8, 0x84, 0xca, 0xe8, 0x8a, 0x9b, 0x9f, 0x19, 0x14, 0x8c, 0x7d, 0xd0, 0xee,
    0x33, 0xce, 0xb4, 0x57, 0x2d, 0x5e, 0x78, 0x3f, 0x06, 0xd7, 0xb3, 0xd6, 0x40,
    0x70, 0x2e, 0xb6, 0x12, 0x3f, 0x4a, 0x61, 0x38, 0xae, 0x72, 0x12, 0xfb, 0x77,
    0xde, 0x53, 0xb3, 0xa1, 0x99, 0xd8, 0xa8, 0x19, 0x96, 0xf7, 0x7f, 0x99
];

pub fn main() {
    let params = DSAParams {
        g: Huge::from_bytes(&G[..]),
        p: Huge::from_bytes(&P[..]),
        q: Huge::from_bytes(&Q[..])
    };
    let private_key = Huge::from_bytes(&PRIVATE_KEY[..]);
    let public_key = Huge::from_bytes(&PUBLIC_KEY[..]);

    let msg = "abc123".as_bytes();
    let mut c = Cursor::new(msg);
    let msg_hash = hash::hash(&mut c, &sha::SHA1HashAlgorithm {}).expect("Failed to hash message");

    let signature = sign(&params, &private_key, &msg_hash[..]);

    println!("DSA signature of abc123 is: r: {}, s: {}",
             hex::format_hex(signature.r.bytes()),
             hex::format_hex(signature.s.bytes()));

    if verify(&params, &public_key, &msg_hash[..], &signature) {
        println!("Verified!");
    } else {
        println!("Verification failed :(");
    }
}