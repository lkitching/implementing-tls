use std::io::{self, Read};

pub struct Pkcs5PaddingReader<R : Read> {
    reader: R,
    done: bool,
    block_size: usize
}

impl <R: Read> Pkcs5PaddingReader<R> {
    pub fn new(r: R, block_size: usize) -> Self {
        Self { reader: r, done: false, block_size}
    }
}

impl <R : Read> Read for Pkcs5PaddingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() != self.block_size {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Buffer size must match block size"));
        }

        if self.done {
            return Ok(0);
        }

        let bytes_read = self.reader.read(buf)?;
        if bytes_read < self.block_size {
            // reached end of reader
            // not enough bytes to fill last block so calculate size of padding
            // NOTE: at least one byte must remain at the end of buf
            buf[bytes_read] = 0x80;
            for i in (bytes_read + 1) .. buf.len() {
                buf[i] = 0;
            }

            self.done = true;
            return Ok(self.block_size);
        } else {
            return Ok(bytes_read);
        }
    }
}

pub struct Pkcs5PaddingUnreader<R: Read> {
    reader: R,
    block_size: usize,
    state: PaddingReaderState
}

impl <R: Read> Pkcs5PaddingUnreader<R> {
    pub fn new(reader: R, block_size: usize) -> Self {
        Pkcs5PaddingUnreader { reader, block_size, state: PaddingReaderState::NotStarted }
    }
}

enum PaddingReaderState {
    NotStarted,
    Reading(Vec<u8>),
    Done
}

impl <R: Read> Read for Pkcs5PaddingUnreader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (next_state, result) = match &mut self.state {
            PaddingReaderState::NotStarted => {
                let mut first_block = vec![0; self.block_size];

                // read first block - must exist!
                let first_block_bytes = self.reader.read(&mut first_block)?;
                if first_block_bytes == self.block_size {
                    let mut second_block = vec![0; self.block_size];

                    // try to read second block
                    let second_block_bytes = self.reader.read(&mut second_block)?;
                    if second_block_bytes == 0 {
                        // only one block - remove padding and write data to output
                        let data = remove_padding(&first_block);
                        buf[0 .. data.len()].clone_from_slice(data);
                        (PaddingReaderState::Done, Ok(data.len()))
                    } else if second_block_bytes == self.block_size {
                        // multiple blocks in output
                        // write first block to buf and save next block
                        buf[0 .. first_block.len()].clone_from_slice(&first_block);
                        (PaddingReaderState::Reading(second_block), Ok(self.block_size))
                    } else {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to read block from inner reader"));
                    }
                } else {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected at least one block from inner reader"));
                }
            },
            PaddingReaderState::Reading(previous_plaintext_block) => {
                // try to read next block of plaintext
                let mut next_block = vec![0; self.block_size];
                let bytes_read = self.reader.read(&mut next_block)?;

                if bytes_read == 0 {
                    // previous block was last block
                    // strip padding and write to output buffer
                    let data = remove_padding(previous_plaintext_block);
                    buf[0 .. data.len()].clone_from_slice(data);

                    (PaddingReaderState::Done, Ok(data.len()))
                } else if bytes_read == self.block_size {
                    // read entire block
                    // write previous block to output update previous block
                    buf[0 .. bytes_read].clone_from_slice(&previous_plaintext_block);
                    (PaddingReaderState::Reading(next_block), Ok(self.block_size))
                } else {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected to read full block from inner reader"));
                }
            },
            PaddingReaderState::Done => {
                return Ok(0);
            }
        };

        self.state = next_state;
        result
    }
}

fn remove_padding(plaintext: &[u8]) -> &[u8] {
    // padding should always exist
    if plaintext.len() == 0 {
        panic!("Invalid padding - plaintext is empty after decryption");
    }

    // scan backwards from the end of the plaintext to find start of the padding
    let mut pi = plaintext.len() - 1;
    while pi > 0 && plaintext[pi] == 0x00 {
        pi -= 1;
    }

    if plaintext[pi] != 0x80 {
        panic!("Invalid padding - expected 0x80 at index {} but found {:#02x}", pi, plaintext[pi]);
    }

    // pi current points at the start of the padding
    // this index is the length of the plaintext with the padding removed
    &plaintext[0 .. pi]
}
