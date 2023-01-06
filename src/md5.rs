use std::convert::{TryInto};
use std::num::Wrapping;
use crate::hash::{HashAlgorithm, HashState};

#[allow(non_snake_case)]
fn F(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[allow(non_snake_case)]
fn G(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

#[allow(non_snake_case)]
fn H(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[allow(non_snake_case)]
fn I(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

const BASE_T: f64 = 4294967296.0;

const MD5_INITIAL_HASH: [u32; 4] = [
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476
];

const MD5_BLOCK_SIZE: usize = 64;
const MD5_INPUT_BLOCK_SIZE: usize = 56;
const MD5_RESULT_SIZE: usize = 4;

#[allow(non_snake_case)]
fn ROUND(f: fn (u32, u32, u32) -> u32, a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: usize, i: u8, x: &[u32]) {
    let mut tmp = Wrapping(*a) + Wrapping(f(b, c, d)) + Wrapping(x[k]) + Wrapping(((i as f64).sin().abs() * BASE_T) as u32);

    // rotate left by s bits
    tmp = (tmp << s) | (tmp >> (32 - s));

    tmp += b;
    *a = tmp.0;
}

fn md5_block_operate(input: &[u8], hash: &mut [u32]) {
    assert_eq!(64, input.len(), "Expected input block length of 64 bytes");

    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];

    // divide input bytes into 16 4-byte chunks and load as a little-endian u32
    let mut x: [u32; 16] = [0; 16];
    for j in 0..x.len() {
        let offset = j * 4;
        let le_bytes = &input[offset..offset + 4];
        x[j] = u32::from_le_bytes(le_bytes.try_into().unwrap());
    }

    // Round 1
    ROUND( F, &mut a, b, c, d, 0, 7, 1, &x );
    ROUND( F, &mut d, a, b, c, 1, 12, 2, &x);
    ROUND( F, &mut c, d, a, b, 2, 17, 3, &x);
    ROUND( F, &mut b, c, d, a, 3, 22, 4, &x);
    ROUND( F, &mut a, b, c, d, 4, 7, 5, &x);
    ROUND( F, &mut d, a, b, c, 5, 12, 6, &x);
    ROUND( F, &mut c, d, a, b, 6, 17, 7, &x);
    ROUND( F, &mut b, c, d, a, 7, 22, 8, &x);
    ROUND( F, &mut a, b, c, d, 8, 7, 9, &x);
    ROUND( F, &mut d, a, b, c, 9, 12, 10, &x);
    ROUND( F, &mut c, d, a, b, 10, 17, 11, &x);
    ROUND( F, &mut b, c, d, a, 11, 22, 12, &x);
    ROUND( F, &mut a, b, c, d, 12, 7, 13, &x);
    ROUND( F, &mut d, a, b, c, 13, 12, 14, &x);
    ROUND( F, &mut c, d, a, b, 14, 17, 15, &x);
    ROUND( F, &mut b, c, d, a, 15, 22, 16, &x);

    // Round 2
    ROUND( G, &mut a, b, c, d, 1, 5, 17, &x);
    ROUND( G, &mut d, a, b, c, 6, 9, 18, &x);
    ROUND( G, &mut c, d, a, b, 11, 14, 19, &x);
    ROUND( G, &mut b, c, d, a, 0, 20, 20, &x);
    ROUND( G, &mut a, b, c, d, 5, 5, 21, &x);
    ROUND( G, &mut d, a, b, c, 10, 9, 22, &x);
    ROUND( G, &mut c, d, a, b, 15, 14, 23, &x);
    ROUND( G, &mut b, c, d, a, 4, 20, 24, &x);
    ROUND( G, &mut a, b, c, d, 9, 5, 25, &x);
    ROUND( G, &mut d, a, b, c, 14, 9, 26, &x);
    ROUND( G, &mut c, d, a, b, 3, 14, 27, &x);
    ROUND( G, &mut b, c, d, a, 8, 20, 28, &x);
    ROUND( G, &mut a, b, c, d, 13, 5, 29, &x);
    ROUND( G, &mut d, a, b, c, 2, 9, 30, &x);
    ROUND( G, &mut c, d, a, b, 7, 14, 31, &x);
    ROUND( G, &mut b, c, d, a, 12, 20, 32, &x);

    // Round 3
    ROUND( H, &mut a, b, c, d, 5, 4, 33, &x);
    ROUND( H, &mut d, a, b, c, 8, 11, 34, &x);
    ROUND( H, &mut c, d, a, b, 11, 16, 35, &x);
    ROUND( H, &mut b, c, d, a, 14, 23, 36, &x);
    ROUND( H, &mut a, b, c, d, 1, 4, 37, &x);
    ROUND( H, &mut d, a, b, c, 4, 11, 38, &x);
    ROUND( H, &mut c, d, a, b, 7, 16, 39, &x);
    ROUND( H, &mut b, c, d, a, 10, 23, 40, &x);
    ROUND( H, &mut a, b, c, d, 13, 4, 41, &x);
    ROUND( H, &mut d, a, b, c, 0, 11, 42, &x);
    ROUND( H, &mut c, d, a, b, 3, 16, 43, &x);
    ROUND( H, &mut b, c, d, a, 6, 23, 44, &x);
    ROUND( H, &mut a, b, c, d, 9, 4, 45, &x);
    ROUND( H, &mut d, a, b, c, 12, 11, 46, &x);
    ROUND( H, &mut c, d, a, b, 15, 16, 47, &x);
    ROUND( H, &mut b, c, d, a, 2, 23, 48, &x);

    // Round 4
    ROUND( I, &mut a, b, c, d, 0, 6, 49, &x);
    ROUND( I, &mut d, a, b, c, 7, 10, 50, &x);
    ROUND( I, &mut c, d, a, b, 14, 15, 51, &x);
    ROUND( I, &mut b, c, d, a, 5, 21, 52, &x);
    ROUND( I, &mut a, b, c, d, 12, 6, 53, &x);
    ROUND( I, &mut d, a, b, c, 3, 10, 54, &x);
    ROUND( I, &mut c, d, a, b, 10, 15, 55, &x);
    ROUND( I, &mut b, c, d, a, 1, 21, 56, &x);
    ROUND( I, &mut a, b, c, d, 8, 6, 57, &x);
    ROUND( I, &mut d, a, b, c, 15, 10, 58, &x);
    ROUND( I, &mut c, d, a, b, 6, 15, 59, &x);
    ROUND( I, &mut b, c, d, a, 13, 21, 60, &x);
    ROUND( I, &mut a, b, c, d, 4, 6, 61, &x);
    ROUND( I, &mut d, a, b, c, 11, 10, 62, &x);
    ROUND( I, &mut c, d, a, b, 2, 15, 63, &x);
    ROUND( I, &mut b, c, d, a, 9, 21, 64, &x);

    hash[0] = (Wrapping(hash[0]) + Wrapping(a)).0;
    hash[1] = (Wrapping(hash[1]) + Wrapping(b)).0;
    hash[2] = (Wrapping(hash[2]) + Wrapping(c)).0;
    hash[3] = (Wrapping(hash[3]) + Wrapping(d)).0;
}

const S: [[u8; 4]; 4] = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21]
];

fn md5_block_operate_alternate(input: &[u8], hash: &mut [u32; MD5_RESULT_SIZE]) {
    let mut tmp_hash: [Wrapping<u32>; 4] = hash.map(|i| Wrapping(i));

    let mut x: [u32; 16] = [0; 16];
    let mut x_i;

    for j in 0 .. x.len() {
        x[j] = (input[(j * 4) + 3] as u32) << 24 |
            (input[(j * 4) + 2] as u32) << 16 |
            (input[(j * 4) + 1] as u32) << 8 |
            input[(j * 4)] as u32;
    }

    for i in 0..64 {
        let a = 3 - ((i + 3) % 4);
        let b = 3 - ((i + 2) % 4);
        let c = 3 - ((i + 1) % 4);
        let d = 3 - i % 4;

        if i < 16 {
            tmp_hash[a] += F(tmp_hash[b].0, tmp_hash[c].0, tmp_hash[d].0);
            x_i = i;
        } else if i < 32 {
            tmp_hash[a] += G(tmp_hash[b].0, tmp_hash[c].0, tmp_hash[d].0);
            x_i = (1 + ((i - 16) * 5)) % 16;
        } else if i < 48 {
            tmp_hash[a] += H(tmp_hash[b].0, tmp_hash[c].0, tmp_hash[d].0);
            x_i = (5 + ((i - 32) * 3)) % 16;
        } else {
            tmp_hash[a] += I(tmp_hash[b].0, tmp_hash[c].0, tmp_hash[d].0);
            x_i = ((i - 48) * 7) % 16;
        }

        let s_i = S[i / 16 as usize][i % 4 as usize] as usize;
        tmp_hash[a] += Wrapping(x[x_i]) + Wrapping((BASE_T * ((i + 1) as f64).sin().abs()) as u32);

        // rotate left by s_i bits
        tmp_hash[a] = (tmp_hash[a] << s_i) | (tmp_hash[a] >> (32 - s_i));
        tmp_hash[a] += tmp_hash[b];
    }

    hash[0] = (tmp_hash[0] + Wrapping(hash[0])).0;
    hash[1] = (tmp_hash[1] + Wrapping(hash[1])).0;
    hash[2] = (tmp_hash[2] + Wrapping(hash[2])).0;
    hash[3] = (tmp_hash[3] + Wrapping(hash[3])).0;
}

pub fn md5_hash(input: &[u8]) -> [u32; MD5_RESULT_SIZE] {
    let mut hash = MD5_INITIAL_HASH.clone();
    let length_in_bits = input.len() * 8;
    let block_op: fn (&[u8], &mut [u32; MD5_RESULT_SIZE]) = md5_block_operate_alternate;

    let mut remaining = input.len();
    let mut block_start = 0;
    let mut consumed_all = false;

    while remaining >= MD5_INPUT_BLOCK_SIZE {
        // special handling for blocks between 56 and 64 bytes
        // Last 8 bytes are reserved for the length so there is insufficient room for
        // the length and not enough data to fill the block
        if remaining < MD5_BLOCK_SIZE {
            // copy all of remaining data to the block
            // add a single 1 bit (0x80 byte) after the input followed by 0 bits to the end of the
            // block
            let mut padded_block = [0; MD5_BLOCK_SIZE];
            &mut padded_block[0..remaining].copy_from_slice(&input[block_start..]);
            padded_block[remaining] = 0x80;
            block_op(&padded_block, &mut hash);

            block_start += remaining;
            remaining = 0;
            consumed_all = true;
            break;
        } else {
            block_op(&input[block_start..block_start + MD5_BLOCK_SIZE], &mut hash);
            block_start += MD5_BLOCK_SIZE;
            remaining -= MD5_BLOCK_SIZE;
        }
    }

    // there's always at least one padded block at the end containing the length of the message
    // copy any remaining data into the last block
    let mut padded_block = [0; MD5_BLOCK_SIZE];
    if ! consumed_all {
        assert!(remaining <= MD5_INPUT_BLOCK_SIZE);
        padded_block[0..remaining].copy_from_slice(&input[block_start..]);
        padded_block[remaining] = 0x80;
    }

    // add length to end of last block
    // NOTE: md5 allows for 64 bits of length but this implementation can only handle 32 bit
    // leave the upper 4 bytes as 0
    padded_block[MD5_BLOCK_SIZE - 5] = ((length_in_bits & 0xFF000000) >> 24) as u8;
    padded_block[MD5_BLOCK_SIZE - 6] = ((length_in_bits & 0x00FF0000) >> 16) as u8;
    padded_block[MD5_BLOCK_SIZE - 7] = ((length_in_bits & 0x0000FF00) >> 8) as u8;
    padded_block[MD5_BLOCK_SIZE - 8] = (length_in_bits & 0x000000FF) as u8;

    block_op(&padded_block, &mut hash);

    hash
}

pub struct MD5HashAlgorithm {}

impl HashAlgorithm for MD5HashAlgorithm {
    fn output_length_bytes(&self) -> usize { 16 }

    fn initialise(&self) -> HashState {
        HashState::new(MD5_INITIAL_HASH.as_slice())
    }

    fn block_size(&self) -> usize {
        MD5_BLOCK_SIZE
    }

    fn input_block_size(&self) -> usize {
        MD5_INPUT_BLOCK_SIZE
    }

    fn block_operate(&self, block: &[u8], state: &mut HashState) {
        md5_block_operate(block, state.as_mut_slice());
    }

    fn finalise(&self, final_block: &mut [u8], input_len_bytes: usize, mut state: HashState) -> Vec<u8> {
        let length_in_bits = input_len_bytes * 8;

        // add length to end of last block
        // NOTE: md5 allows for 64 bits of length but this implementation can only handle 32 bit
        // leave the upper 4 bytes as 0
        final_block[MD5_BLOCK_SIZE - 5] = ((length_in_bits & 0xFF000000) >> 24) as u8;
        final_block[MD5_BLOCK_SIZE - 6] = ((length_in_bits & 0x00FF0000) >> 16) as u8;
        final_block[MD5_BLOCK_SIZE - 7] = ((length_in_bits & 0x0000FF00) >> 8) as u8;
        final_block[MD5_BLOCK_SIZE - 8] = (length_in_bits & 0x000000FF) as u8;

        md5_block_operate(final_block, state.as_mut_slice());

        state.get_le_bytes()
        // let hash_bytes = md5_hash_bytes(state.as_slice());
        // hash_bytes.to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex;
    use crate::hash::{hash};

    use std::io;

    #[test]
    fn empty_test() {
        let result = md5_hash(&[]);
        let bytes = HashState::new(&result).get_le_bytes();

        let expected = hex::read_bytes("0xd41d8cd98f00b204e9800998ecf8427e").expect("Failed to parse hex");
        assert_eq!(&expected, bytes.as_slice());
    }

    #[test]
    fn trait_empty_test() {
        let alg = MD5HashAlgorithm {};
        let mut source = io::Cursor::new(&[]);

        let hash_bytes = hash(&mut source, &alg).expect("Failed to generate hash");
        let expected = hex::read_bytes("0xd41d8cd98f00b204e9800998ecf8427e").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }

    #[test]
    fn book_test() {
        let result = md5_hash("abc".as_bytes());
        let bytes = HashState::new(&result).get_le_bytes();

        let expected = hex::read_bytes("0x900150983cd24fb0d6963f7d28e17f72").expect("Failed to parse hex");
        assert_eq!(&expected, bytes.as_slice());
    }

    #[test]
    fn trait_book_test() {
        let alg = MD5HashAlgorithm {};
        let mut source = io::Cursor::new("abc".as_bytes());

        let hash_bytes = hash(&mut source, &alg).expect("Failed to generate hash");
        let expected = hex::read_bytes("0x900150983cd24fb0d6963f7d28e17f72").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }
}