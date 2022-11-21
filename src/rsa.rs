use crate::huge::{Huge, DivResult};
use crate::hex;

pub struct RSAKey {
    pub modulus: Huge,
    pub exponent: Huge
}

impl RSAKey {
    pub fn new(modulus: Huge, exponent: Huge) -> Self {
        RSAKey { modulus, exponent }
    }
}

pub fn rsa_compute(m: Huge, e: Huge, n: Huge) -> Huge {
    m.mod_pow(e, n)
}

pub fn rsa_encrypt(key: &RSAKey, input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let modulus_len = key.modulus.len();
    let mut input= input;

    let mut bytes_remaining = input.len();

    while bytes_remaining > 0 {
        let block_size = if bytes_remaining < modulus_len - 11 {
            bytes_remaining
        } else {
            modulus_len - 11
        };

        let mut padded_block = vec![0u8; modulus_len];
        padded_block[(modulus_len - block_size)..].copy_from_slice(&input[0 .. block_size]);
        //set block type
        padded_block[1] = 0x02;

        for i in 2..(modulus_len - block_size - 1) {
            // TODO: make these random
            padded_block[i] = i as u8;
        }

        // construct a Huge instance from the padded block
        let m = Huge::from_bytes(&padded_block);

        // encrypt message and write to output
        let c = rsa_compute(m, key.exponent.clone(), key.modulus.clone());
        output.extend_from_slice(c.bytes());

        bytes_remaining -= block_size;
        input = &input[block_size ..];
    }

    output
}

pub fn rsa_decrypt(private_key: &RSAKey, ciphertext: &[u8]) -> Vec<u8> {
    let modulus_len = private_key.modulus.len();
    if ciphertext.len() % modulus_len != 0 {
        panic!("Error - input must be an even multiple of key modulus {} (got {})", modulus_len, ciphertext.len());
    }

    let mut output = Vec::new();

    for block in ciphertext.chunks_exact(modulus_len) {
        let c = Huge::from_bytes(block);
        let m = c.mod_pow(private_key.exponent.clone(), private_key.modulus.clone());

        let mut padded_block = vec![0; modulus_len];
        m.unload(&mut padded_block[..]);

        if padded_block[1] > 0x02 {
            panic!("Decryption error or unrecognised block type");
        }

        // find next 0 byte after the padding type byte - this signifies the start of the data
        let mut i = 2;
        while padded_block[i] != 0 {
            i += 1;
        }

        output.extend_from_slice(&padded_block[i+1..]);
    }

    output
}

pub const TEST_MODULUS: [u8; 64] = [
    0xC4, 0xF8, 0xE9, 0xE1, 0x5D, 0xCA, 0xDF, 0x2B,
    0x96, 0xC7, 0x63, 0xD9, 0x81, 0x00, 0x6A, 0x64,
    0x4F, 0xFB, 0x44, 0x15, 0x03, 0x0A, 0x16, 0xED,
    0x12, 0x83, 0x88, 0x33, 0x40, 0xF2, 0xAA, 0x0E,
    0x2B, 0xE2, 0xBE, 0x8F, 0xA6, 0x01, 0x50, 0xB9,
    0x04, 0x69, 0x65, 0x83, 0x7C, 0x3E, 0x7D, 0x15,
    0x1B, 0x7D, 0xE2, 0x37, 0xEB, 0xB9, 0x57, 0xC2,
    0x06, 0x63, 0x89, 0x82, 0x50, 0x70, 0x3B, 0x3F
];

pub const TEST_PRIVATE_KEY: [u8; 63] = [
    0x8a, 0x7e, 0x79, 0xf3, 0xfb, 0xfe, 0xa8, 0xeb,
    0xfd, 0x18, 0x35, 0x1c, 0xb9, 0x97, 0x91, 0x36,
    0xf7, 0x05, 0xb4, 0xd9, 0x11, 0x4a, 0x06, 0xd4,
    0xaa, 0x2f, 0xd1, 0x94, 0x38, 0x16, 0x67, 0x7a,
    0x53, 0x74, 0x66, 0x18, 0x46, 0xa3, 0x0c, 0x45,
    0xb3, 0x0a, 0x02, 0x4b, 0x4d, 0x22, 0xb1, 0x5a,
    0xb3, 0x23, 0x62, 0x2b, 0x2d, 0xe4, 0x7b, 0xa2,
    0x91, 0x15, 0xf0, 0x6e, 0xe4, 0x2c, 0x41
];

pub const TEST_PUBLIC_KEY: [u8; 3] = [0x01, 0x00, 0x01];

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn book_test() {
        let e = Huge::from(79u8);
        let d = Huge::from(1019usize);
        let n = Huge::from(3337usize);

        let m = Huge::from(688usize);

        let c = rsa_compute(m.clone(), e, n.clone());
        assert_eq!(c, Huge::from(1570usize));

        // decrypt with different exponent
        let pt = rsa_compute(c, d, n);
        assert_eq!(pt, m);
    }

    #[test]
    fn book_encrypt_test() {
        let plaintext = "abc".as_bytes();
        let modulus = Huge::from_bytes(TEST_MODULUS.as_slice());
        let exponent = Huge::from_bytes(TEST_PUBLIC_KEY.as_slice());
        let key = RSAKey::new(modulus, exponent);

        let expected = "0x40f73315d3f74703904e51e1c72686801de06a55417110e56280f1f8471a3802406d2110011e1f387f7b4c43258b0a1eedc558a3aac5aa2d20cf5e0d65d80db3";
        let expected_bytes = hex::read_bytes(expected).expect("Invalid hex");

        let ciphertext = rsa_encrypt(&key, plaintext);

        assert_eq!(expected_bytes, ciphertext);
    }

    // NOTE: slow!
    // #[test]
    // fn book_decrypt_test() {
    //     let ciphertext_hex = "0x40f73315d3f74703904e51e1c72686801de06a55417110e56280f1f8471a3802406d2110011e1f387f7b4c43258b0a1eedc558a3aac5aa2d20cf5e0d65d80db3";
    //     let ciphertext = hex::read_bytes(ciphertext_hex).expect("Invalid hex");
    //
    //     let modulus = Huge::from_bytes(TEST_MODULUS.as_slice());
    //     let exponent = Huge::from_bytes(TEST_PRIVATE_KEY.as_slice());
    //     let private_key = RSAKey::new(modulus, exponent);
    //
    //     let expected = "abc".as_bytes();
    //     let plaintext = rsa_decrypt(&private_key, &ciphertext);
    //
    //     assert_eq!(expected, plaintext);
    // }
}