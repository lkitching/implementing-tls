pub fn xor(target: &mut [u8], src: &[u8], len: usize) {
    let mut i = 0;
    while i < len {
        target[i] ^= src[i];
        i += 1;
    }
}
