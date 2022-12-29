use std::cmp;

use crate::hash::{HashAlgorithm, hash};
use crate::{util, md5, sha};
use crate::hmac::{hmac};

fn p_hash<H: HashAlgorithm>(secret: &[u8], seed: &[u8], alg: &H, output_buf: &mut [u8]) {
    let hash_len = alg.output_length_bytes();

    // calculate initial HMAC and append seed to buffer
    let mut a = hmac(secret, seed, alg);
    a.extend_from_slice(seed);

    let mut remaining = output_buf.len();
    let mut offset = 0;

    while remaining > 0 {
        let hmac_bytes = hmac(secret, a.as_slice(), alg);
        let adv = cmp::min(remaining, hash_len);

        // copy bytes from previous HMAC result into output buffer
        // advance offset of next write and reduce the number of remaining bytes
        output_buf[offset..(offset+adv)].copy_from_slice(&hmac_bytes[0..adv]);
        offset += adv;
        remaining -= adv;

        // set A for next iteration
        // A(i) = HMAC(secret, A(i - i))
        let next_a = hmac(secret, &a[0..hash_len], alg);
        &a[0..hash_len].copy_from_slice(&next_a[0..hash_len]);
    }
}

pub fn prf(secret: &[u8], label: &[u8], seed: &[u8], output_buf: &mut [u8]) {
    let concat: Vec<u8> = [label, seed].concat();
    let half_secret_len = (secret.len() / 2) + (secret.len() % 2);

    // calculate p_hash for MD5 into output buffer
    p_hash(&secret[0..half_secret_len], concat.as_slice(), &md5::MD5HashAlgorithm {}, output_buf);

    // calculate p_hash for SHA-1 into temp buffer
    let mut sha1_bytes = vec![0; output_buf.len()];
    p_hash(&secret[(secret.len() / 2) ..], concat.as_slice(), &sha::SHA1HashAlgorithm {}, sha1_bytes.as_mut_slice());

    util::xor(output_buf, sha1_bytes.as_slice(), sha1_bytes.len());
}

pub fn prf_bytes(secret: &[u8], label: &[u8], seed: &[u8], n: usize) -> Vec<u8> {
    let mut buf = vec![0; n];
    prf(secret, label, seed, &mut buf);
    buf
}

#[cfg(test)]
mod test {
    use super::prf;
    use crate::hex::read_bytes;

    #[test]
    fn book_test() {
        let secret = "secret".as_bytes();
        let label = "label".as_bytes();
        let seed = "seed".as_bytes();

        let mut result: [u8; 20] = [0; 20];
        prf(secret, label, seed, result.as_mut_slice());

        let expected = read_bytes("0xb5baf4722b91851a8816d22ebd8c1d8cc2e94d55").expect("Failed to parse hex");

        assert_eq!(expected, result);
    }

    #[test]
    fn longer_test() {
        let secret = "opensesame".as_bytes();
        let label = "test".as_bytes();
        let seed = "abcdef".as_bytes();

        let mut result: [u8; 40] = [0; 40];
        prf(secret, label, seed, result.as_mut_slice());

        let expected = read_bytes("0x03a600bd99977bb0c2359ec4bce94c7633a882572e2a82968d3c66081b7982f5647deebf78bce3c5").expect("Failed to parse hex");

        assert_eq!(expected, result);
    }
}

