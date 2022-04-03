use std::io::{self, Read};

use super::util::{xor};

pub trait BlockOperation {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]);
}

pub struct BlockOperationReader<O: BlockOperation, R: Read> {
    reader: R,
    block_op: O,
    key: Vec<u8>,
    block_size: usize
}

impl <O: BlockOperation, R: Read> BlockOperationReader<O, R> {
    pub fn new(block_op: O, reader: R, key: &[u8], block_size: usize) -> Self {
        Self { block_op, reader, block_size, key: key.to_vec() }
    }
}

impl <O: BlockOperation, R: Read> Read for BlockOperationReader<O, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() < self.block_size {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Buffer length must be at least block size"));
        }

        // try read from inner reader into temp buffer
        let mut temp = vec![0; self.block_size];
        let bytes_read = self.reader.read(&mut temp)?;

        if bytes_read == 0 {
            // end of inner reader
            return Ok(0);
        } else if bytes_read == self.block_size {
            // perform block operation and write to output
            self.block_op.block_operate(&temp, &mut buf[0 .. self.block_size], &self.key);
            Ok(self.block_size)
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Expected to read entire block"))
        }
    }
}

pub struct CBCEncryptMode<O: BlockOperation> {
    block_op: O,
    previous_ciphertext_block: Vec<u8>
}

impl <O: BlockOperation> CBCEncryptMode<O> {
    pub fn new(block_op: O, iv: &[u8]) -> Self {
        CBCEncryptMode {
            block_op,
            previous_ciphertext_block: iv.to_vec()
        }
    }
}

impl <O: BlockOperation> BlockOperation for CBCEncryptMode<O> {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]) {
        // TODO: check block size

        // copy input buf
        let mut buf = vec![0; input.len()];
        buf.clone_from_slice(input);

        // XOR input with previous ciphertext
        xor(&mut buf, &self.previous_ciphertext_block, output.len());

        // encrypt
        self.block_op.block_operate(&buf, output, key);

        // store ciphertext for next operation
        self.previous_ciphertext_block.clone_from_slice(output);
    }
}

pub struct CBCDecryptMode<O: BlockOperation> {
    block_op: O,
    previous_ciphertext_block: Vec<u8>
}

impl <O: BlockOperation> CBCDecryptMode<O> {
    pub fn new(block_op: O, iv: &[u8]) -> Self {
        CBCDecryptMode { block_op, previous_ciphertext_block: iv.to_vec() }
    }
}

impl <O: BlockOperation> BlockOperation for CBCDecryptMode<O> {
    fn block_operate(&mut self, input: &[u8], output: &mut [u8], key: &[u8]) {
        // decrypt current block
        self.block_op.block_operate(input, output, key);

        // XOR with previous ciphertext
        xor(output, &self.previous_ciphertext_block, output.len());

        // save previous ciphertext block
        self.previous_ciphertext_block.clone_from_slice(input);
    }
}
