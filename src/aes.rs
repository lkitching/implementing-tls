use std::ops;

use crate::block::{BlockOperation};
use crate::hex;

pub const AES_BLOCK_SIZE: usize = 16;

fn rot_word(w: &mut [u8]) {
    let tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

static SBOX: [[u8; 16]; 16] = [
    [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 ],
    [ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 ],
    [ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 ],
    [ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 ],
    [ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 ],
    [ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf ],
    [ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 ],
    [ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 ],
    [ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 ],
    [ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb ],
    [ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 ],
    [ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 ],
    [ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a ],
    [ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e ],
    [ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf ],
    [ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]
];

struct KeySchedule {
    bytes: Vec<u8>
}

impl ops::Index<usize> for KeySchedule {
    type Output = [u8];

    fn index(&self, round: usize) -> &Self::Output {
        let idx = round * 16;
        &self.bytes[idx .. idx + 16]
    }
}

struct State {
    matrix: [u8; AES_BLOCK_SIZE]
}

impl State {
    fn from_block(block: &[u8]) -> Self {
        assert!(block.len() >= AES_BLOCK_SIZE);
        let mut matrix: [u8; AES_BLOCK_SIZE] = [0; AES_BLOCK_SIZE];
        matrix.clone_from_slice(&block[..AES_BLOCK_SIZE]);
        Self { matrix }
    }

    fn write_to(&self, output: &mut [u8]) {
        assert!(output.len() >= AES_BLOCK_SIZE);
        output[.. AES_BLOCK_SIZE].clone_from_slice(&self.matrix);
    }

    fn dump(&self) {
        println!("STATE:");
        for r in 0..4 {
            let rv = vec![self.matrix[r], self.matrix[r+4], self.matrix[r+8], self.matrix[r+12]];
            hex::show_hex(&rv);
        }
    }
}

impl ops::Index<(usize, usize)> for State {
    type Output = u8;

    fn index(&self, (r, c): (usize, usize)) -> &Self::Output {
        // NOTE: bytes stored in column-major order
        // e.g. column 0 is stored in indexes 0..3, column 1 in 4..7 etc.
        &self.matrix[r + 4 * c]
    }
}

impl ops::IndexMut<(usize, usize)> for State {
    fn index_mut(&mut self, (r, c): (usize, usize)) -> &mut Self::Output {
        &mut self.matrix[r + 4 * c]
    }
}

fn sub_word(w: &mut [u8]) {
    for i in 0..4 {
        // use upper and lower 4 bits of corresponding byte to index into SBOX table
        w[i] = SBOX[((w[i] & 0xF0) >> 4) as usize][(w[i] & 0x0F) as usize];
    }
}

fn add_round_key(state: &mut State, round_key: &[u8]) {
    for c in 0..4 {
        for r in 0..4 {
            let key_index = c * 4 + r;
            state[(r, c)] ^= round_key[key_index];
        }
    }
}

fn sub_bytes(state: &mut State) {
    for r in 0..4 {
        for c in 0..4 {
            let coords = (r, c);
            let sb = state[coords];
            state[coords] = SBOX[((sb & 0xF0) >> 4) as usize][(sb & 0x0F) as usize];
        }
    }
}

fn compute_key_schedule(key: &[u8]) -> KeySchedule {
    // key is logically split into 4-byte words
    let key_words = key.len() >> 2;
    let mut round_constant: u8 = 0x01;

    // each round requires 16 bytes of key material
    // there's also an extra key permutation at the end so require (num_rounds + 1) * 16 bytes in total
    let num_rounds = key_words + 6;

    // total number of words in the key material
    let key_material_words = (num_rounds + 1) * 4;
    let mut key_bytes = Vec::with_capacity(key_material_words * 4);

    // first copy entire key into key schedule buffer
    key_bytes.extend_from_slice(key);

    // key material is generated one 'key word' (i.e. 4-byte word) at a time
    // each round requires 4 of these for a total of 16 bytes
    // each word is a permutation of the previous word
    // normally it is the XOR of the word one 'key-length' previous in the buffer
    // every 4 iterations the previous word is transformed by rotating and substitution before being
    // XOR'd with the round constant
    let mut word_index = key_words;
    while word_index < key_material_words {
        // index of the first byte of the current word in the key buffer
        let key_buf_index = word_index * 4;

        // copy previous 4-byte word into key buffer
        key_bytes.extend_from_within(((word_index - 1) * 4) .. );

        {
            // slice for the current word being calculated
            let word_slice = &mut key_bytes[key_buf_index ..];

            if word_index % key_words == 0 {
                rot_word(word_slice);
                sub_word(word_slice);

                if word_index % 36 == 0 {
                    // XOR round constant with 0x1b if it would overflow
                    round_constant = 0x1b;
                }

                key_bytes[key_buf_index] ^= round_constant;
                round_constant = round_constant << 1;
            } else if key_words > 6 && word_index % key_words == 4 {
                sub_word(word_slice);
            }
        }

        // XOR current word with corresponding word key-length bytes previous
        {
            let prev_word_index = word_index - key_words;
            let prev_buf_index = prev_word_index * 4;
            key_bytes[key_buf_index] ^= key_bytes[prev_buf_index];
            key_bytes[key_buf_index + 1] ^= key_bytes[prev_buf_index + 1];
            key_bytes[key_buf_index + 2] ^= key_bytes[prev_buf_index + 2];
            key_bytes[key_buf_index + 3] ^= key_bytes[prev_buf_index + 3];
        }

        word_index += 1;
    }

    assert_eq!(key_bytes.len(), key_bytes.capacity(), "Failed to derive expected number of key bytes");
    KeySchedule { bytes: key_bytes }
}

fn shift_rows(state: &mut State) {
    let mut tmp = state[(1, 0)];
    // shift row 1 right by 1
    state[(1, 0)] = state[(1, 1)];
    state[(1, 1)] = state[(1, 2)];
    state[(1, 2)] = state[(1, 3)];
    state[(1, 3)] = tmp;

    // shift row 2 right by 2
    tmp = state[(2, 0)];
    state[(2, 0)] = state[(2, 2)];
    state[(2, 2)] = tmp;
    tmp = state[(2, 1)];
    state[(2, 1)] = state[(2, 3)];
    state[(2, 3)] = tmp;

    tmp = state[(3, 3)];
    state[(3, 3)] = state[(3, 2)];
    state[(3, 2)] = state[(3, 1)];
    state[(3, 1)] = state[(3, 0)];
    state[(3, 0)] = tmp;
}

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (if (x & 0x80) > 0 { 0x1b } else { 0x00 })
}

fn dot(x: u8, y: u8) -> u8 {
    let mut product = 0;
    let mut x = x;

    let mut mask = 0x01;
    while mask != 0 {
        if y & mask > 0 {
           product ^= x;
        }
        x = xtime(x);
        mask = mask << 1;
    }

    product
}

fn mix_columns(state: &mut State) {
    for c in 0..4 {
        let t = [
            dot(2, state[(0, c)]) ^ dot(3, state[(1, c)]) ^ state[(2, c)] ^ state[(3, c)],
            state[(0, c)] ^ dot(2, state[(1, c)]) ^ dot(3, state[(2, c)]) ^ state[(3, c)],
            state[(0, c)] ^ state[(1, c)] ^ dot(2, state[(2, c)]) ^ dot(3, state[(3, c)]),
            dot(3, state[(0, c)]) ^ state[(1, c)] ^ state[(2, c)] ^ dot(2, state[(3, c)])
        ];

        // TODO: create set_column method?
        state[(0, c)] = t[0];
        state[(1, c)] = t[1];
        state[(2, c)] = t[2];
        state[(3, c)] = t[3];
    }
}

pub struct AesEncryptBlockOperation {}
impl BlockOperation for AesEncryptBlockOperation {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]) {
        // initialise state from input block
        let mut state = State::from_block(input);

        // TODO: create iterator thing for state co-ordinates?
        // TODO: add types for row/column indexes?

        // calculate number of rounds
        // each round requires 16 bytes of key material
        let num_rounds = (key.len() >> 2) + 6;

        let key_schedule = compute_key_schedule(key);

        add_round_key(&mut state, &key_schedule[0]);

        for round in 0..num_rounds {
            sub_bytes(&mut state);
            shift_rows(&mut state);

            if round < (num_rounds - 1) {
                mix_columns(&mut state);
            }

            add_round_key(&mut state, &key_schedule[round + 1])
        }

        // write state to output block
        state.write_to(output);
    }
}

fn inv_shift_rows(state: &mut State) {
    let mut tmp = state[(1, 2)];
    state[(1, 2)] = state[(1, 1)];
    state[(1, 1)] = state[(1, 0)];
    state[(1, 0)] = state[(1, 3)];
    state[(1, 3)] = tmp;

    tmp = state[(2, 0)];
    state[(2, 0)] = state[(2, 2)];
    state[(2, 2)] = tmp;
    tmp = state[(2, 1)];
    state[(2, 1)] = state[(2, 3)];
    state[(2, 3)] = tmp;

    tmp = state[(3, 0)];
    state[(3, 0)] = state[(3, 1)];
    state[(3, 1)] = state[(3, 2)];
    state[(3, 2)] = state[(3, 3)];
    state[(3, 3)] = tmp;
}

static INV_SBOX: [[u8; 16]; 16] = [
    [ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb ],
    [ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb ],
    [ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e ],
    [ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 ],
    [ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 ],
    [ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 ],
    [ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 ],
    [ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b ],
    [ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 ],
    [ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e ],
    [ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ],
    [ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 ],
    [ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f ],
    [ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef ],
    [ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 ],
    [ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d ]
];

fn inv_sub_bytes(state: &mut State) {
    for r in 0..4 {
        for c in 0..4 {
            let coords = (r, c);
            let sb = state[coords];
            state[coords] = INV_SBOX[((sb & 0xF0) >> 4) as usize][(sb & 0x0F) as usize];
        }
    }
}

fn inv_mix_columns(state: &mut State) {
    for c in 0..4 {
        let t = [
            dot( 0x0e, state[(0, c)]) ^ dot( 0x0b, state[(1, c)]) ^ dot( 0x0d, state[(2, c)]) ^ dot( 0x09, state[(3, c)]),
            dot( 0x09, state[(0, c)]) ^ dot( 0x0e, state[(1, c)]) ^ dot( 0x0b, state[(2, c)]) ^ dot( 0x0d, state[(3, c)]),
            dot( 0x0d, state[(0, c)]) ^ dot( 0x09, state[(1, c)]) ^ dot( 0x0e, state[(2, c)]) ^ dot( 0x0b, state[(3, c)]),
            dot( 0x0b, state[(0, c)]) ^ dot( 0x0d, state[(1, c)]) ^ dot( 0x09, state[(2, c)]) ^ dot( 0x0e, state[(3, c)])
        ];

        state[(0, c)] = t[0];
        state[(1, c)] = t[1];
        state[(2, c)] = t[2];
        state[(3, c)] = t[3];
    }
}

pub struct AesDecryptBlockOperation {}
impl BlockOperation for AesDecryptBlockOperation {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]) {
        let mut state = State::from_block(input);

        let num_rounds = (key.len() >> 2) + 6;
        let key_schedule = compute_key_schedule(key);

        // iterate generated key schedule in reverse
        // NOTE: there are num_rounds + 1 keys in the generated key schedule
        // so last key is at index num_rounds
        add_round_key(&mut state, &key_schedule[num_rounds]);

        let mut round = num_rounds;
        while round > 0 {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &key_schedule[round - 1]);

            if round > 1 {
                inv_mix_columns(&mut state);
            }

            round -= 1;
        }

        state.write_to(output);
    }
}

#[cfg(test)]
mod test {
    use std::io;
    use super::*;
    use crate::{hex, block, padding};

    fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mode = block::CBCEncryptMode::new(AesEncryptBlockOperation {}, &iv);
        let c = io::Cursor::new(plaintext);
        let r = padding::Pkcs5PaddingReader::new(c, AES_BLOCK_SIZE);

        let mut encryptor = block::BlockOperationReader::new(mode, r, &key, AES_BLOCK_SIZE);

        let mut buf = Vec::new();
        let result = io::copy(&mut encryptor, &mut buf);
        result.expect("Failed to encrypt");
        buf
    }

    // #[test]
    // fn encrypt_test() {
    //     let key = hex::read_bytes("deadbeefcafebabedeadbeefcafebabe").expect("Failed to parse key");
    //     let iv = hex::read_bytes("12345678901234567890123456789012").expect("Failed to parse IV");
    //     let plaintext = "thequickbrownfox".as_bytes();
    //
    //     let expected = hex::read_bytes("792d552dce4821cd8a1268407b74b98505f4f60932175f1e9f1ebfafbcef3241").expect("Failed to parse ciphertext");
    //     let result = encrypt(&key, &iv, plaintext);
    //
    //     assert_eq!(result, expected);
    // }

    #[test]
    fn dot_test() {
        assert_eq!(dot(0x02, 0x6c), 0xd8);
        assert_eq!(dot(0x03, 0x97), 0xa2);
        assert_eq!(dot(0x02, 0x97), 0x35);
        assert_eq!(dot(0x03, 0x2e), 0x72);
        assert_eq!(dot(0x02, 0x2e), 0x5c);
        assert_eq!(dot(0x03, 0x48), 0xd8);
        assert_eq!(dot(0x03, 0x6c), 0xb4);
        // dot(02, 48) = 90
        // dot(02, 15) = 2a
        // dot(03, 84) = 97
        // dot(02, 84) = 13
        // dot(03, 6e) = b2
        // dot(02, 6e) = dc
        // dot(03, 8e) = 89
        // dot(03, 15) = 3f
        // dot(02, 8e) = 07
        // dot(02, 1c) = 38
        // dot(03, e1) = 38
        // dot(02, e1) = d9
        // dot(03, 5d) = e7
        // dot(02, 5d) = ba
        // dot(03, ec) = 2f
        // dot(03, 1c) = 24
        // dot(02, ec) = c3
        // dot(02, 89) = 09
        // dot(03, a1) = f8
        // dot(02, a1) = 59
        // dot(03, 55) = ff
        // dot(02, 55) = aa
        // dot(03, 91) = a8
        // dot(03, 89) = 80
        // dot(02, 91) = 39
    }
}
