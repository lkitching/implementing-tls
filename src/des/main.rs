use std::{io, process};

use clap::{arg, Command};

use implementing_tls::des;

fn show_hex(bytes: &[u8]) {
    for b in bytes.iter() {
        print!("{:02x}", b);
    }
    println!();
}

struct HexWriter<W> {
    inner: W
}

impl <W> HexWriter<W> {
    fn new(inner: W) -> Self {
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

fn read_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.starts_with("0x") {
        parse_hex(&s[2..])
    } else {
        Ok(s.bytes().collect())
    }
}

pub fn main() {
    let matches = Command::new("des")
        .arg(arg!([mode] "encrypt|decrypt").required(true))
        .arg(arg!([key] "The key to encrypt with").required(true))
        .arg(arg!([iv] "The Initial Vector to use for CBC mode").required(true))
        .arg(arg!([input] "The plaintext to encrypt or ciphertext to decrypt").required(true))
        .get_matches();

    let key = read_bytes(matches.value_of("key").unwrap()).expect("Invalid key");
    let iv = read_bytes(matches.value_of("iv").unwrap()).expect("Invalid IV");
    let input = read_bytes(matches.value_of("input").unwrap()).expect("Invalid input");

    match matches.value_of("mode").unwrap() {
        "encrypt" => {
            let mut hw = HexWriter::new(io::stdout());

            let result = if key.len() == 24 {
                //des::des3_encrypt(&input, &iv, &key)
                des::des_encrypt_process(des::TripleDesEncryptBlockOperation {}, &input, &iv, &key, &mut hw)
            } else {
                //des::des_encrypt(&input, &iv, &key)
                des::des_encrypt_process(des::DesEncryptBlockOperation {}, &input, &iv, &key, &mut hw)
            };

            if let Err(e) = result {
                println!("Failed to encrypt: {}", e);
                process::exit(1);
            }
        },
        "decrypt" => {
            let plaintext = if key.len() == 24 {
                des::des3_decrypt(&input, &iv, &key)
            } else {
                des::des_decrypt(&input, &iv, &key)
            };

            show_hex(&plaintext);
        },
        _ => {
            eprintln!("Invalid mode - expected encrypt or decrypt");
            process::exit(1);
        }
    }

}