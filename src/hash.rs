use std::io;

pub trait HashAlgorithm {
    type State;
    fn initialise(&self) -> Self::State;
    fn block_size(&self) -> usize;
    fn input_block_size(&self) -> usize;
    fn block_operate(&self, block: &[u8], state: &mut Self::State);
    fn finalise(&self, final_block: &mut [u8], input_len_bytes: usize, state: Self::State) -> Vec<u8>;
}

pub fn hash<R: io::Read, H: HashAlgorithm>(source: &mut R, alg: &H) -> io::Result<Vec<u8>> {
    let mut hash_state = alg.initialise();
    let mut buf = vec![0u8; alg.block_size()];
    let mut total_bytes_read = 0;

    // indicates any remaining data to be written to the final block
    // NOTE: any operation which does not write the final 0x80 byte indicating the end of the
    // data should return Some here
    let mut remaining: Option<Vec<u8>>;

    loop {
        let mut last_read = source.read(&mut buf)?;
        total_bytes_read += last_read;

        if last_read == 0 {
            // input is multiple of block size
            // NOTE: end-of-data marker byte not written here
            remaining = Some(vec![]);
            break;
        } else if last_read < alg.input_block_size() {
            // partial block
            // can fit length at the end so copy to padded block
            remaining = Some(buf[0..last_read].to_vec());
            break;
        } else if last_read < alg.block_size() {
            // not enough space to include length at the end of the block
            // add an 0x80 byte after the input followed by a sequence of 0s
            // require an additional empty block containing the length
            let mut padded_block = vec![0u8; alg.block_size()];
            &mut padded_block[0..last_read].copy_from_slice(&buf[0..last_read]);
            padded_block[last_read] = 0x80;

            alg.block_operate(&padded_block, &mut hash_state);
            remaining = None;
            break;
        } else {
            assert_eq!(last_read, alg.block_size());
            // read full block
            // update hash state and continue
            alg.block_operate(&buf, &mut hash_state);
        }
    }

    // add final block containing the length at the end
    let mut padded_block = vec![0u8; alg.block_size()];

    // copy any un-processed input in final block
    if let Some(partial) = remaining {
        assert!(partial.len() <= alg.input_block_size());
        padded_block[0 .. partial.len()].copy_from_slice(&partial);
        padded_block[partial.len()] = 0x80;
    }

    let hash_bytes = alg.finalise(&mut padded_block, total_bytes_read, hash_state);
    Ok(hash_bytes)
}

