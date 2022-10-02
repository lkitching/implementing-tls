use std::num::Wrapping;

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

fn sha1_block_operate(block: &[u8], hash: &mut [u32; SHA1_RESULT_SIZE]) {
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

pub fn sha1_hash_bytes(hash: [u32; SHA1_RESULT_SIZE]) -> [u8; 20] {
    let mut bytes: [u8; 20] = [0; 20];

    for i in 0..SHA1_RESULT_SIZE {
        let be_bytes = hash[i].to_be_bytes();
        let offset = i * 4;
        bytes[offset..offset + 4].copy_from_slice(&be_bytes);
    }

    bytes
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex;

    #[test]
    fn empty_test() {
        let hash = sha1_hash(&[]);
        let hash_bytes = sha1_hash_bytes(hash);
        let expected = hex::read_bytes("0xda39a3ee5e6b4b0d3255bfef95601890afd80709").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }

    #[test]
    fn book_test() {
        let hash = sha1_hash("abc".as_bytes());
        let hash_bytes = sha1_hash_bytes(hash);
        let expected = hex::read_bytes("0xa9993e364706816aba3e25717850c26c9cd0d89d").expect("Failed to parse hex");

        assert_eq!(&expected, &hash_bytes);
    }
}