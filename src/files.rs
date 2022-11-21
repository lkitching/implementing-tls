use std::str::{FromStr};
use std::io::{Read};
use std::fs::{File};
use std::path::{Path};

use crate::pem;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateFileFormat {
    PEM,
    DER
}

impl FromStr for CertificateFileFormat {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pem" => Ok(CertificateFileFormat::PEM),
            "der" => Ok(CertificateFileFormat::DER),
            _ => Err(())
        }
    }
}

pub fn parse_certificate_file_format_option(opt: &str) -> Result<CertificateFileFormat, ()> {
    if opt.starts_with("-") {
        opt[1..].parse()
    } else {
        Err(())
    }
}

pub fn decode_certificate_file<P: AsRef<Path>>(path: P, format: CertificateFileFormat) -> Result<Vec<u8>, String> {
    let mut f = File::open(path).map_err(|e| format!("File not found: {}", e))?;

    let mut bytes = Vec::new();
    let bytes_read = f.read_to_end(&mut bytes).map_err(|e| format!("Failed to read certificate file: {}", e))?;

    match format {
        CertificateFileFormat::DER => Ok(bytes),
        CertificateFileFormat::PEM => {
            Ok(pem::decode(&bytes[..]))
        }
    }
}