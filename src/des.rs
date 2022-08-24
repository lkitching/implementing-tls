use std::io;

use super::padding;
use super::block::{self, BlockOperation};
use super::util::{xor};

fn get_bit(arr: &[u8], bit: usize) -> bool {
    arr[bit / 8] & (0x80 >> (bit % 8)) > 0
}

fn set_bit(arr: &mut [u8], bit: usize) {
    arr[bit / 8] |= (0x80 >> (bit % 8));
}

fn clear_bit(arr: &mut [u8], bit: usize) {
    arr[bit / 8] &= !(0x80 >> (bit % 8));
}

// target must contain len bytes, and permuate_table len * 8 entries
// src can be shorter since it is only indexed by the entires in permute_table. The expansion
// function depends on this behaviour.
// WARNING: indexes in the permute_table are 1-based instead of 0-based
// This is how they are defined within the specification
fn permute(target: &mut [u8], src: &[u8], permute_table: &[usize], len: usize) {
    for i in 0 .. len * 8 {
        if get_bit(src, permute_table[i] - 1) {
            set_bit(target, i);
        } else {
            clear_bit(target, i);
        }
    }
}

// initial permutation table
static IP_TABLE: [usize; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
];

// final permutation table
// This inverts the initial permutation
static FP_TABLE: [usize; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
];

static PC1_TABLE: [usize; 56] = [
    57, 49, 41, 33, 25, 17,  9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7,
    62, 54, 46, 38, 30, 22, 14, 6,
    61, 53, 45, 37, 29, 21, 13, 5,
    28, 20, 12,  4
];

static PC2_TABLE: [usize; 48] = [
    14, 17, 11, 24,  1,  5,
    3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
];

// rotate the key left - the key is split into two 28-bit halves and each is
// rotated independently. This means byte 3 has to be handled specially.
fn rotate_left(key: &mut [u8]) {
    let carry_left = (key[0] & 0x80) >> 3;

    key[0] = (key[0] << 1) | ((key[1] & 0x80) >> 7);
    key[1] = (key[1] << 1) | ((key[2] & 0x80) >> 7);
    key[2] = (key[2] << 1) | ((key[3] & 0x80) >> 7);

    let carry_right = (key[3] & 0x08) >> 3;
    key[3] = (((key[3] << 1) | ((key[4] & 0x80) >> 7)) & !0x10) | carry_left;

    key[4] = (key[4] << 1) | ((key[5] & 0x80) >> 7);
    key[5] = (key[5] << 1) | ((key[6] & 0x80) >> 7);
    key[6] = (key[6] << 1) | carry_right;
}

// rotate the key right - the key is split into two 28-bit halves and each is
// rotated independently. This means byte 3 has to be handled specially.
fn rotate_right(key: &mut[u8]) {
    let carry_right = ( key[ 6 ] & 0x01 ) << 3;

    key[6] = ( key[6] >> 1 ) | ( ( key[5] & 0x01 ) << 7 );
    key[5] = ( key[5] >> 1 ) | ( ( key[4] & 0x01 ) << 7 );
    key[4] = ( key[4] >> 1 ) | ( ( key[3] & 0x01 ) << 7 );

    let carry_left = ( key[3] & 0x10 ) << 3;
    key[3] = ( ( ( key[3] >> 1 ) |
        ( ( key[2] & 0x01 ) << 7 ) ) & !0x08 ) | carry_right;

    key[2] = ( key[2] >> 1 ) | ( ( key[1] & 0x01 ) << 7 );
    key[1] = ( key[1] >> 1 ) | ( ( key[0] & 0x01 ) << 7 );
    key[0] = ( key[0] >> 1 ) | carry_left;
}

// expansion table
// half of the input block is expanded from 32 to 48 bits so it can be xor'd with the current
// key
static EXPANSION_TABLE: [usize; 48] = [
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
];

static SBOX: [[u8; 64]; 8] = [
    [14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
     3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
     4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
     15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13],

    [15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
     9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
     0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
     5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9],

    [10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
     1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
     13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
     11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12],

    [7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
     1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
     10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
     15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14],

    [2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
     8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
     4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
     15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3],

    [12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
     0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
     9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
     7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13],

    [4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
     3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
     1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
     10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12],

    [13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
     10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
     7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
     0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11]
];

static P_TABLE: [usize; 32] = [
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
];

const DES_BLOCK_SIZE: usize = 8;
const PC1_KEY_SIZE: usize = 7;
const EXPANSION_BLOCK_SIZE: usize = 6;
const SUBKEY_SIZE: usize = 6;

#[derive(Clone, Copy)]
pub enum KeySchedule {
    Encryption,
    Decryption
}

fn des_block_operate(plaintext: &[u8], ciphertext: &mut[u8], key: &[u8], schedule: KeySchedule) {
    let mut ip_block: [u8; DES_BLOCK_SIZE] = [0; DES_BLOCK_SIZE];
    let mut expansion_block: [u8; EXPANSION_BLOCK_SIZE] = [0; EXPANSION_BLOCK_SIZE];
    let mut pc1_key: [u8; PC1_KEY_SIZE] = [0; PC1_KEY_SIZE];
    let mut subkey: [u8; SUBKEY_SIZE] = [0; SUBKEY_SIZE];
    let mut substitution_block: [u8; DES_BLOCK_SIZE / 2] = [0; DES_BLOCK_SIZE / 2];
    let mut pbox_target: [u8; DES_BLOCK_SIZE / 2] = [0; DES_BLOCK_SIZE / 2];
    let mut recomb_box: [u8; DES_BLOCK_SIZE / 2] = [0; DES_BLOCK_SIZE / 2];

    // initial input permutation
    permute(&mut ip_block, plaintext, IP_TABLE.as_slice(), DES_BLOCK_SIZE);

    // TODO: extract key schedule into separate trait
    // initial key permutation
    permute(&mut pc1_key, key, PC1_TABLE.as_slice(), PC1_KEY_SIZE);

    for round in 0 .. 16 {
        // expand the right half (bytes 5..8) of the input block to 48 bits
        permute(&mut expansion_block, &ip_block[4..], EXPANSION_TABLE.as_slice(), 6);

        if let KeySchedule::Encryption = schedule {
            // "key mixing"
            // rotate both halves of the input key
            // key is rotated once in rounds 1, 2, 9 and 16 and twice in the other rounds
            rotate_left(&mut pc1_key);
            if !(round <= 1 || round == 8 || round == 15) {
                rotate_left(&mut pc1_key);
            }
        }

        // permute key again according to second permutation table
        permute(&mut subkey, &pc1_key, &PC2_TABLE, SUBKEY_SIZE);

        if let KeySchedule::Decryption = schedule {
            // key is rotated once in rounds 1, 2, 9 and 16 and twice in other rounds
            // NOTE: decryption key schedule is in reverse order so 'round 1' is round 16, 'round 2' round 15 etc.
            rotate_right(&mut pc1_key);
            if !(round >= 14 || round == 7 || round == 0) {
                rotate_right(&mut pc1_key);
            }
        }

        // subkey now contains scheduled key for this round

        // XOR scheduled key with expanded right half of input block
        xor(&mut expansion_block, &subkey, SUBKEY_SIZE);


        // Each 6 bits of the input are mapped to 4 bits in the output
        // Each 6 bit segment is used to index into the sbox table
        // This reduces the 48-bit intermediate array into 32-bits

        // clear left-hand 32-bits before substitution
        for i in 0 .. DES_BLOCK_SIZE / 2 {
            substitution_block[i] = 0;
        }

        // NOTE: copied from the example C
        substitution_block[ 0 ] =
            SBOX[ 0 ][((expansion_block[ 0 ] & 0xFC ) >> 2) as usize] << 4;
        substitution_block[ 0 ] |=
            SBOX[ 1 ][(( expansion_block[ 0 ] & 0x03 ) << 4 |
                ( expansion_block[ 1 ] & 0xF0 ) >> 4) as usize ];
        substitution_block[ 1 ] =
            SBOX[ 2 ][(( expansion_block[ 1 ] & 0x0F ) << 2 |
                ( expansion_block[ 2 ] & 0xC0 ) >> 6) as usize ] << 4;
        substitution_block[ 1 ] |=
            SBOX[ 3 ][(expansion_block[ 2 ] & 0x3F) as usize];
        substitution_block[ 2 ] =
            SBOX[ 4 ][((expansion_block[ 3 ] & 0xFC ) >> 2) as usize] << 4;
        substitution_block[ 2 ] |=
            SBOX[ 5 ][((expansion_block[ 3 ] & 0x03 ) << 4 |
                (expansion_block[ 4 ] & 0xF0 ) >> 4) as usize];
        substitution_block[ 3 ] =
            SBOX[ 6 ][(( expansion_block[ 4 ] & 0x0F ) << 2 |
                ( expansion_block[ 5 ] & 0xC0 ) >> 6) as usize] << 4;
        substitution_block[ 3 ] |=
            SBOX[ 7 ][(expansion_block[ 5 ] & 0x3F ) as usize];

        // permutation
        permute(&mut pbox_target, &substitution_block, &P_TABLE, DES_BLOCK_SIZE / 2);

        // recombination
        // XOR the pbox with left half then switch sides
        for i in 0 .. DES_BLOCK_SIZE / 2 {
            recomb_box[i] = ip_block[i];
        }

        for i in 0 .. DES_BLOCK_SIZE / 2 {
            ip_block[i] = ip_block[i + 4];
        }

        xor(&mut recomb_box, &pbox_target, DES_BLOCK_SIZE / 2);

        for i in 0 .. DES_BLOCK_SIZE / 2 {
            ip_block[i + 4] = recomb_box[i];
        }
    }

    // swap for last time
    for i in 0 .. DES_BLOCK_SIZE / 2 {
        recomb_box[i] = ip_block[i];
    }

    for i in 0 .. DES_BLOCK_SIZE / 2 {
        ip_block[i] = ip_block[i + 4];
    }

    for i in 0 .. DES_BLOCK_SIZE / 2 {
        ip_block[i + 4] = recomb_box[i];
    }

    // final permutation
    // this undoes the initial permutation
    permute(ciphertext, &ip_block, &FP_TABLE, DES_BLOCK_SIZE);
}

pub struct DesEncryptBlockOperation {}
impl BlockOperation for DesEncryptBlockOperation {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]) {
        des_block_operate(input, output, &key, KeySchedule::Encryption)
    }
}

pub struct TripleDesEncryptBlockOperation {}
impl BlockOperation for TripleDesEncryptBlockOperation {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]) {
        let mut buf = vec![0; DES_BLOCK_SIZE];

        // encrypt with key1
        des_block_operate(input, output, &key[0 .. DES_BLOCK_SIZE], KeySchedule::Encryption);

        // decrypt with key2
        des_block_operate(output, &mut buf, &key[DES_BLOCK_SIZE .. DES_BLOCK_SIZE * 2], KeySchedule::Decryption);

        // encrypt with key3
        // NOTE: final result written to output slice
        des_block_operate(&buf, output, &key[DES_BLOCK_SIZE * 2 .. DES_BLOCK_SIZE * 3], KeySchedule::Encryption);
    }
}

pub struct DesDecryptBlockOperation {}
impl BlockOperation for DesDecryptBlockOperation {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]) {
        des_block_operate(input, output, key, KeySchedule::Decryption);
    }
}

pub struct TripleDesDecryptBlockOperation {}
impl BlockOperation for TripleDesDecryptBlockOperation {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]) {
        let mut buf = vec![0; DES_BLOCK_SIZE];

        // decrypt with key 3
        des_block_operate(input, output, &key[DES_BLOCK_SIZE * 2 .. ], KeySchedule::Decryption);

        // encrypt with key 2
        des_block_operate(output, &mut buf, &key[DES_BLOCK_SIZE .. DES_BLOCK_SIZE * 2], KeySchedule::Encryption);

        // decrypt with key1
        // NOTE: final output is written to output slice
        des_block_operate(&buf, output, &key[0 .. DES_BLOCK_SIZE], KeySchedule::Decryption);
    }
}

pub fn des_encrypt_process<O: BlockOperation, W: io::Write>(encrypt_op: O, input: &[u8], iv: &[u8], key: &[u8], writer: &mut W) -> io::Result<u64> {
    let mode = block::CBCEncryptMode::new(encrypt_op, iv);
    let c = io::Cursor::new(input);
    let r = padding::Pkcs5PaddingReader::new(c, DES_BLOCK_SIZE);

    let mut encryptor = block::BlockOperationReader::new(mode, r, key, DES_BLOCK_SIZE);

    io::copy(&mut encryptor, writer)
}

pub fn des_decrypt_process<O: BlockOperation, W: io::Write>(block_decrypt_op: O, ciphertext: &[u8], iv: &[u8], key: &[u8], writer: &mut W) -> io::Result<u64> {
    let mode = block::CBCDecryptMode::new(block_decrypt_op, iv);

    let ciphertext_reader = io::Cursor::new(ciphertext);
    let decryptor = block::BlockOperationReader::new(mode, ciphertext_reader, key, DES_BLOCK_SIZE);
    let mut plaintext_reader = padding::Pkcs5PaddingUnreader::new(decryptor, DES_BLOCK_SIZE);

    io::copy(&mut plaintext_reader, writer)
}

pub fn des_encrypt(input: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ciphertext_buf = Vec::new();
    des_encrypt_process(DesEncryptBlockOperation {}, input, iv, key, &mut ciphertext_buf).expect("Failed to encrypt with DES");
    ciphertext_buf
}

pub fn des3_encrypt(input: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ciphertext_buf = Vec::new();
    des_encrypt_process(TripleDesEncryptBlockOperation {}, input, iv, key, &mut ciphertext_buf).expect("Failed to encrypt DES3");
    ciphertext_buf
}

pub fn des_decrypt(ciphertext: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let mut plaintext_buf = Vec::new();
    des_decrypt_process(DesDecryptBlockOperation {}, ciphertext, iv, key, &mut plaintext_buf);
    plaintext_buf
}

pub fn des3_decrypt(ciphertext: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let mut plaintext_buf = Vec::new();
    des_decrypt_process(TripleDesDecryptBlockOperation {}, ciphertext, iv, key, &mut plaintext_buf);
    plaintext_buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn des_book_example() {
        let plaintext = "abcdefgh";
        let iv = "initialz";
        let key = "password";
        let ciphertext = des_encrypt(plaintext.as_bytes(), iv.as_bytes(), key.as_bytes());

        let expected = hex::decode("71828547387b18e5081deb10cf46df1d").expect("Failed to parse hex");

        assert_eq!(expected, ciphertext, "Unexpected ciphertext");
    }

    #[test]
    fn des_empty_plaintext() {
        let plaintext = "";
        let iv = "initialz";
        let key = "password";
        let ciphertext = des_encrypt(plaintext.as_bytes(), iv.as_bytes(), key.as_bytes());

        let expected = hex::decode("101008ed149b97b9").expect("Failed to parse hex");

        assert_eq!(expected, ciphertext, "Unexpected ciphertext");
    }

    #[test]
    fn des_decrypt_recovers_plaintext() {
        let plaintext = "testing fairly long message spanning multiple blocks";
        let iv = "initvect";
        let key = "password";
        let ciphertext = des_encrypt(plaintext.as_bytes(), iv.as_bytes(), key.as_bytes());

        let decrypted = des_decrypt(&ciphertext, iv.as_bytes(), key.as_bytes());

        assert_eq!(plaintext.as_bytes(), decrypted, "Failed to recover plaintext");
    }

    #[test]
    fn des3_book_example() {
        let plaintext = "abcdefgh";
        let iv = "initialz";
        let key = "twentyfourcharacterinput";
        let ciphertext = des3_encrypt(plaintext.as_bytes(), iv.as_bytes(), key.as_bytes());

        let expected = hex::decode("c0c48bc47e87ce17a84d7058fe4962c8").expect("Failed to parse hex");

        assert_eq!(expected, ciphertext, "Unexpected ciphertext");
    }

    #[test]
    fn des3_empty_plaintext() {
        let plaintext = "";
        let iv ="initialz";
        let key = "twentyfourcharacterinput";
        let ciphertext = des3_encrypt(plaintext.as_bytes(), iv.as_bytes(), key.as_bytes());

        let expected = hex::decode("828bceae48b22612").expect("Failed to parse hex");

        assert_eq!(expected, ciphertext, "Unexpected ciphertext");
    }

    #[test]
    fn des3_decrypt_recovers_plaintext() {
        let plaintext = "example plaintext which is reasonably long";
        let iv = "initvect";
        let key = "tripledesexamplekey12345";
        let ciphertext = des3_encrypt(plaintext.as_bytes(), iv.as_bytes(), key.as_bytes());

        let decrypted = des3_decrypt(&ciphertext, iv.as_bytes(), key.as_bytes());

        assert_eq!(plaintext.as_bytes(), decrypted, "Failed to recover plaintext");
    }
}