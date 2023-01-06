use std::num::Wrapping;

use crate::hash::{HashAlgorithm, HashState};

const SHA1_RESULT_SIZE: usize = 5;
const SHA1_INPUT_BLOCK_SIZE: usize = 56;
const SHA1_BLOCK_SIZE: usize = 64;

const K: [u32; 4] = [
    0x5a827999, // 0 <= t <= 19
    0x6ed9eba1, // 20 <= t <= 39
    0x8f1bbcdc, // 40 <= t <= 59
    0xca62c1d6 // 60 <= t <= 79
];

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn parity(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sha1_block_operate(block: &[u8], hash: &mut [u32]) {
    assert_eq!(SHA1_RESULT_SIZE, hash.len(), "Unexpected state length");

    let mut W: [u32; 80] = [0; 80];
    for t in 0..80 {
        // first 16 blocks of W are the original 16 blocks of the input
        if t < 16 {
            W[t] = (block[t * 4] as u32) << 24 |
                (block[t * 4 + 1] as u32) << 16 |
                (block[t * 4 + 2] as u32) << 8 |
                block[t * 4 + 3] as u32;
        } else {
            W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];

            // rotate left one bit
            W[t] = (W[t] << 1 | (W[t] & 0x80000000) >> 31);
        }
    }

    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];
    let mut e = hash[4];

    for t in 0..80 {
        let mut T = Wrapping(a << 5 | a >> 27) + Wrapping(e) + Wrapping(K[(t / 20) as usize]) + Wrapping(W[t]);

        if t <= 19 {
            T += ch(b, c, d);
        } else if t <= 39 {
            T += parity(b, c, d);
        } else if t <= 59 {
            T += maj(b, c, d);
        } else {
            T += parity(b, c, d);
        }

        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = T.0;
    }

    hash[0] = (Wrapping(hash[0]) + Wrapping(a)).0;
    hash[1] = (Wrapping(hash[1]) + Wrapping(b)).0;
    hash[2] = (Wrapping(hash[2]) + Wrapping(c)).0;
    hash[3] = (Wrapping(hash[3]) + Wrapping(d)).0;
    hash[4] = (Wrapping(hash[4]) + Wrapping(e)).0;
}

const SHA1_INITIAL_HASH: [u32; SHA1_RESULT_SIZE] = [
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0
];

pub fn sha1_hash(input: &[u8]) -> [u32; SHA1_RESULT_SIZE] {
    let mut hash = SHA1_INITIAL_HASH.clone();
    let mut remaining = input;
    let mut consumed_all = false;
    let length_in_bits = input.len() * 8;

    while remaining.len() >= SHA1_INPUT_BLOCK_SIZE {
        if remaining.len() < SHA1_BLOCK_SIZE {
            // not enough space to include length at the end of the block
            // add an 0x80 byte after the input followed by a sequence of 0s
            // require an additional empty block containing the length
            let mut padded_block: [u8; SHA1_BLOCK_SIZE] = [0; SHA1_BLOCK_SIZE];
            &mut padded_block[0..remaining.len()].copy_from_slice(&remaining);
            padded_block[remaining.len()] = 0x80;

            sha1_block_operate(&padded_block, &mut hash);

            consumed_all = true;
            remaining = &remaining[remaining.len() - 1 ..];
        } else {
            // process full block
            sha1_block_operate(&remaining[0..SHA1_BLOCK_SIZE], &mut hash);
            remaining = &remaining[SHA1_BLOCK_SIZE..];
        }
    }

    // add final block containing the length at the end
    let mut padded_block = [0; SHA1_BLOCK_SIZE];

    // copy any un-processed input in final block
    if ! consumed_all {
        padded_block[0 .. remaining.len()].copy_from_slice(&remaining);
        padded_block[remaining.len()] = 0x80;
    }

    padded_block[SHA1_BLOCK_SIZE - 4] = ((length_in_bits & 0xFF000000) >> 24) as u8;
    padded_block[SHA1_BLOCK_SIZE - 3] = ((length_in_bits & 0x00FF0000) >> 16) as u8;;
    padded_block[SHA1_BLOCK_SIZE - 2] = ((length_in_bits & 0x0000FF00) >> 8) as u8;
    padded_block[SHA1_BLOCK_SIZE - 1] = (length_in_bits & 0x000000FF) as u8;

    sha1_block_operate(&padded_block, &mut hash);

    hash
}

fn write_final_block_length(final_block: &mut [u8], input_len_bytes: usize) {
    let length_in_bits = input_len_bytes * 8;

    // set length at end of final block
    final_block[SHA1_BLOCK_SIZE - 4] = ((length_in_bits & 0xFF000000) >> 24) as u8;
    final_block[SHA1_BLOCK_SIZE - 3] = ((length_in_bits & 0x00FF0000) >> 16) as u8;;
    final_block[SHA1_BLOCK_SIZE - 2] = ((length_in_bits & 0x0000FF00) >> 8) as u8;
    final_block[SHA1_BLOCK_SIZE - 1] = (length_in_bits & 0x000000FF) as u8;
}

pub struct SHA1HashAlgorithm {}

impl HashAlgorithm for SHA1HashAlgorithm {
    fn output_length_bytes(&self) -> usize { 20 }

    fn initialise(&self) -> HashState {
        HashState::new(SHA1_INITIAL_HASH.as_slice())
    }

    fn block_size(&self) -> usize {
        SHA1_BLOCK_SIZE
    }

    fn input_block_size(&self) -> usize {
        SHA1_INPUT_BLOCK_SIZE
    }

    fn block_operate(&self, block: &[u8], state: &mut HashState) {
        sha1_block_operate(block, state.as_mut_slice());
    }

    fn finalise(&self, final_block: &mut [u8], input_len_bytes: usize, mut state: HashState) -> Vec<u8> {
        write_final_block_length(final_block, input_len_bytes);

        sha1_block_operate(&final_block, state.as_mut_slice());

        state.get_be_bytes()
    }
}

const SHA256_INITIAL_HASH: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn shr(x: u32, n: usize) -> u32 {
    x >> n
}

fn sigma_rot(x: u32, i: bool) -> u32 {
    rotr(x, if i { 6 } else { 2 }) ^ rotr(x, if i { 11 } else { 13 }) ^ rotr(x, if i { 25 } else { 22 })
}

fn sigma_shr(x: u32, i: bool) -> u32 {
    rotr(x, if i { 17 } else { 7 }) ^ rotr(x, if i { 19 } else { 18 }) ^ shr(x, if i { 10 } else { 3 })
}

fn sha256_block_operate(block: &[u8], state: &mut [u32]) {
    assert_eq!(8, state.len(), "Unexpected state length");

    let mut W: [u32; 64] = [0; 64];

    for t in 0..W.len() {
        // first 16 elements of W are loaded as little-endian from the input block
        if t <= 15 {
            W[t] = (block[t * 4] as u32) << 24 |
                (block[t * 4 + 1] as u32) << 16 |
                (block[t * 4 + 2] as u32) << 8 |
                (block[t * 4 + 3] as u32);
        } else {
            W[t] = (Wrapping(sigma_shr(W[t - 2], true)) + Wrapping(W[t - 7]) + Wrapping(sigma_shr(W[t - 15], false)) + Wrapping(W[t - 16])).0;
        }
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for t in 0..W.len() {
        let T1 = Wrapping(h) + Wrapping(sigma_rot(e, true)) + Wrapping(ch(e, f, g)) + Wrapping(SHA256_K[t]) + Wrapping(W[t]);
        let T2 = Wrapping(sigma_rot(a, false)) + Wrapping(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = (Wrapping(d) + T1).0;
        d = c;
        c = b;
        b = a;
        a = (T1 + T2).0;
    }

    state[0] = (Wrapping(a) + Wrapping(state[0])).0;
    state[1] = (Wrapping(b) + Wrapping(state[1])).0;
    state[2] = (Wrapping(c) + Wrapping(state[2])).0;
    state[3] = (Wrapping(d) + Wrapping(state[3])).0;
    state[4] = (Wrapping(e) + Wrapping(state[4])).0;
    state[5] = (Wrapping(f) + Wrapping(state[5])).0;
    state[6] = (Wrapping(g) + Wrapping(state[6])).0;
    state[7] = (Wrapping(h) + Wrapping(state[7])).0;
}

pub struct SHA256HashAlgorithm {}

impl HashAlgorithm for SHA256HashAlgorithm {
    fn output_length_bytes(&self) -> usize { 32 }

    fn initialise(&self) -> HashState {
        HashState::new(SHA256_INITIAL_HASH.as_slice())
    }

    fn block_size(&self) -> usize {
        SHA1_BLOCK_SIZE
    }

    fn input_block_size(&self) -> usize {
        SHA1_INPUT_BLOCK_SIZE
    }

    fn block_operate(&self, block: &[u8], state: &mut HashState) {
        sha256_block_operate(block, state.as_mut_slice());
    }

    fn finalise(&self, final_block: &mut [u8], input_len_bytes: usize, mut state: HashState) -> Vec<u8> {
        write_final_block_length(final_block, input_len_bytes);

        sha256_block_operate(&final_block, state.as_mut_slice());

        state.get_be_bytes()
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::hash::{hash};
    use crate::hex;

    use std::io;

    #[test]
    fn empty_test() {
        let hash = sha1_hash(&[]);
        let hash_bytes = HashState::new(&hash).get_be_bytes();
        let expected = hex::read_bytes("0xda39a3ee5e6b4b0d3255bfef95601890afd80709").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }

    #[test]
    fn book_test() {
        let hash = sha1_hash("abc".as_bytes());
        let hash_bytes = HashState::new(&hash).get_be_bytes();
        let expected = hex::read_bytes("0xa9993e364706816aba3e25717850c26c9cd0d89d").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }

    #[test]
    fn trait_empty_test() {
        let alg = SHA1HashAlgorithm {};
        let mut source = io::Cursor::new(&[]);
        let hash_bytes = hash(&mut source, &alg).expect("Failed to generate hash");

        let expected = hex::read_bytes("0xda39a3ee5e6b4b0d3255bfef95601890afd80709").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }

    #[test]
    fn trait_book_test() {
        let alg = SHA1HashAlgorithm {};
        let input_bytes = "abc".as_bytes();
        let mut source = io::Cursor::new(input_bytes);

        let hash_bytes = hash(&mut source, &alg).expect("Failed to generate hash");
        let expected = hex::read_bytes("0xa9993e364706816aba3e25717850c26c9cd0d89d").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }

    #[test]
    fn sha256_empty_test() {
        let alg = SHA256HashAlgorithm {};
        let mut source = io::Cursor::new(&[]);
        let hash_bytes = hash(&mut source, &alg).expect("Failed to generate hash");

        let expected = hex::read_bytes("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }

    #[test]
    fn sha256_non_empty_test() {
        let alg = SHA256HashAlgorithm {};
        let mut source = io::Cursor::new("thequickbrownfoxjumpedoverthelazydog");
        let hash_bytes = hash(&mut source, &alg).expect("Failed to generate hash");

        let expected = hex::read_bytes("0x38717b5161c2e817020a0933e1836dd0127bdef59732d77daca20ccfbf61a7ae").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }
}