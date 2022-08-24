use std::io;

pub struct HexWriter<W> {
    inner: W
}

impl <W> HexWriter<W> {
    pub fn new(inner: W) -> Self {
        HexWriter { inner }
    }
}

impl <W: io::Write> io::Write for HexWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut s = String::with_capacity(buf.len());
        for b in buf.iter() {
            s.push_str(&format!("{:02x}", b));
        }

        let mut bytes_written = 0;
        let to_write = s.as_bytes();
        while bytes_written < to_write.len() {
            let w = self.inner.write(&to_write[bytes_written..])?;
            bytes_written += w;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn parse_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 == 0 {
        let mut result = Vec::with_capacity(hex_str.len() / 2);
        let mut i = 0;
        while i < hex_str.len() {
            let byte_str = &hex_str[i .. i + 2];
            let b = u8::from_str_radix(byte_str, 16).map_err(|_| format!("Invalid byte {}", byte_str))?;
            result.push(b);
            i += 2;
        }
        Ok(result)
    } else {
        Err("Expected even number of hex characters".to_owned())
    }
}

pub fn read_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.starts_with("0x") {
        parse_hex(&s[2..])
    } else {
        Ok(s.bytes().collect())
    }
}

pub fn show_hex(bytes: &[u8]) {
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();
}