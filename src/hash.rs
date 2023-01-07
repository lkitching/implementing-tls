use std::io;
use std::cmp::{Ordering};

#[derive(Clone)]
pub struct HashState {
    state: Vec<u32>
}

impl HashState {
    pub fn new(initial: &[u32]) -> Self {
        Self { state: initial.to_vec() }
    }

    pub fn as_slice(&self) -> &[u32] {
        self.state.as_slice()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u32] {
        self.state.as_mut_slice()
    }

    pub fn get_be_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.state.len() * 4];

        for i in 0..self.state.len() {
            let be_bytes = self.state[i].to_be_bytes();
            let offset = i * 4;
            bytes[offset..offset + 4].copy_from_slice(&be_bytes);
        }

        bytes
    }

    pub fn get_le_bytes(&self) -> Vec<u8> {
        let mut output = vec![0; self.state.len() * 4];

        for i in 0..self.state.len() {
            let le_bytes = self.state[i].to_le_bytes();
            let offset = i * 4;
            output[offset..offset + 4].copy_from_slice(&le_bytes);
        }

        output
    }
}

pub trait HashAlgorithm {
    fn output_length_bytes(&self) -> usize;
    fn initialise(&self) -> HashState;
    fn block_size(&self) -> usize;
    fn input_block_size(&self) -> usize;
    fn block_operate(&self, block: &[u8], state: &mut HashState);
    fn finalise(&self, final_block: &mut [u8], input_len_bytes: usize, state: HashState) -> Vec<u8>;
}

#[derive(Clone)]
pub struct BlockBuffer {
    buf: Vec<u8>,
    position: usize,
    total_bytes: usize
}

enum BufferResult {
    Partial,
    Filled(Vec<u8>)
}

impl BlockBuffer {
    fn new(size: usize) -> Self {
        Self {
            buf: vec![0; size],
            position: 0,
            total_bytes: 0
        }
    }

    fn buffer_full(&mut self) -> Vec<u8> {
        self.position = 0;
        let buf_len = self.buf.len();
        std::mem::replace(&mut self.buf, vec![0; buf_len])
    }

    fn update<'a, 'b>(&'a mut self, bytes: &'b [u8]) -> (BufferResult, &'b [u8]) {
        let capacity = self.buf.len() - self.position;

        match capacity.cmp(&bytes.len()) {
            Ordering::Less => {
                // consume as many bytes required to fill buffer
                &mut self.buf[self.position..].copy_from_slice(&bytes[0..capacity]);
                self.total_bytes += capacity;
                let block = self.buffer_full();
                (BufferResult::Filled(block), &bytes[capacity..])
            },
            Ordering::Equal => {
                // consume all bytes and fill buffer
                &mut self.buf[self.position..].copy_from_slice(&bytes);
                self.total_bytes += bytes.len();
                let block = self.buffer_full();
                (BufferResult::Filled(block), &[])
            },
            Ordering::Greater => {
                // consume all bytes - buffer still has space capacity
                let next_pos = self.position + bytes.len();
                &mut self.buf[self.position..next_pos].copy_from_slice(&bytes);
                self.total_bytes += bytes.len();
                self.position = next_pos;
                (BufferResult::Partial, &[])
            }
        }
    }

    fn consume(self) -> (Vec<u8>, usize, usize) {
        (self.buf, self.position, self.total_bytes)
    }
}

#[derive(Clone)]
pub struct Digest<H> {
    alg: H,
    state: HashState,
    buf: BlockBuffer
}

impl <H: HashAlgorithm> Digest<H> {
    pub fn new(alg: H) -> Self {
        let state = alg.initialise();
        let buf = BlockBuffer::new(alg.block_size());
        Self { alg, state, buf }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        let mut remaining = bytes;
        while ! remaining.is_empty() {
            let (result, left) = self.buf.update(remaining);
            remaining = left;
            if let BufferResult::Filled(block) = result {
                self.alg.block_operate(&block, &mut self.state)
            }
        }
    }

    pub fn finalise(mut self) -> Vec<u8> {
        let (mut buf, position, bytes_written) = self.buf.consume();

        // set remaining space in buffer to [0x80, 0...]
        buf[position] = 0x80;
        for idx in (position + 1)..buf.len() {
            buf[idx] = 0;
        }

        // see if there is space at the end of the current buffer to contain the length
        if position < self.alg.input_block_size() {
            // enough space to fit length
            self.alg.finalise(buf.as_mut_slice(), bytes_written, self.state)
        } else {
            // not enough space to fit length at the end of the current block
            // update with current padded block and then finalise with block containing 0s
            self.alg.block_operate(buf.as_slice(), &mut self.state);

            let mut padding = vec![0u8; self.alg.block_size()];
            self.alg.finalise(padding.as_mut_slice(), bytes_written, self.state)

        }
    }
}

pub fn hash_digest<R: io::Read, H: HashAlgorithm>(source: &mut R, alg: H) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; alg.block_size()];
    let mut digest = Digest::new(alg);

    loop {
        let last_read = source.read(buf.as_mut_slice())?;
        if last_read == 0 {
            break;
        } else {
            digest.update(&buf[0..last_read]);
        }
    }

    Ok(digest.finalise())
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
