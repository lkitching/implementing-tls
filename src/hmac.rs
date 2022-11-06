use std::io::{Cursor, Read};

use crate::hash::{hash, HashAlgorithm};

pub fn hmac<R: Read, H: HashAlgorithm>(key: &[u8], source: R, alg: &H) -> Vec<u8> {
    let key_vec = if key.len() > alg.block_size() {
        let mut c = Cursor::new(key);
        hash(&mut c, alg).expect("Failed to hash")
    } else {
        key.to_vec()
    };

    let mut input_pad_block = vec![0x36u8; alg.block_size()];
    for i in 0..key_vec.len() {
        input_pad_block[i] ^= key_vec[i];
    }

    let h1 = {
        let pad_cursor = Cursor::new(&input_pad_block);
        let mut r = pad_cursor.chain(source);

        hash(&mut r, alg).expect("Failed to calculate hash")
    };

    let mut output_pad_block = vec![0x5cu8; alg.block_size()];
    for i in 0..key_vec.len() {
        output_pad_block[i] ^= key_vec[i];
    }

    {
        let pad_cursor = Cursor::new(&output_pad_block);
        let hash_cursor = Cursor::new(&h1);
        let mut r = pad_cursor.chain(hash_cursor);

        hash(&mut r, alg).expect("Failed to calculate hash")
    }
}

#[cfg(test)]
pub mod test {
    use crate::md5::{MD5HashAlgorithm};
    use crate::hex::{read_bytes};
    use super::*;

    #[test]
    fn book_test() {
        let alg = MD5HashAlgorithm {};
        let key = "Jefe".as_bytes();
        let text = "what do ya want for nothing?".as_bytes();
        let text_cursor = Cursor::new(text);

        let result = hmac(key, text_cursor, &alg);
        let expected = read_bytes("0x750c783e6ab0b503eaa86e310a5db738").expect("Failed to parse hex");

        assert_eq!(expected, result);
    }
}