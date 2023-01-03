use std::io::{self, Read, Write, ErrorKind};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug, Display, Formatter};
use std::net::{TcpStream};

use chrono::{DateTime, Utc};
use num_enum::{TryFromPrimitive};

use crate::x509::{self, SignedX509Certificate, PublicKeyInfo};
use crate::prf::{prf, prf_bytes};
use crate::rsa::{self, RSAKey};
use crate::dh::{DHKey};
use crate::huge::{Huge};
use crate::hash::{self, HashAlgorithm};
use crate::md5::{MD5HashAlgorithm};
use crate::sha::{SHA1HashAlgorithm};

trait BinaryLength {
    fn binary_len(&self) -> usize;
}

trait FixedBinaryLength {
    fn fixed_binary_len() -> usize;
}

impl <T: FixedBinaryLength> BinaryLength for T {
    fn binary_len(&self) -> usize {
        T::fixed_binary_len()
    }
}

trait BinarySerialisable : BinaryLength {
    fn write_to(&self, buf: &mut [u8]);
    fn write_to_vec(&self) -> Vec<u8> {
        let mut v = vec![0; self.binary_len()];
        self.write_to(v.as_mut_slice());
        v
    }
}

// TODO: merge with BinarySerialisable?
enum BinaryReadError {
    ValueOutOfRange,
    BufferTooSmall,
    BufferTooLarge,
    UnknownType
}

trait BinaryReadable {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized;
    fn read_all_from(buf: &[u8]) -> Result<Self, BinaryReadError> where Self: Sized {
        let (result, remaining) = Self::read_from(buf)?;
        if remaining.is_empty() {
            Ok(result)
        } else {
            Err(BinaryReadError::BufferTooLarge)
        }
    }
}

impl FixedBinaryLength for u8 {
    fn fixed_binary_len() -> usize { 1 }
}

impl BinarySerialisable for u8 {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0] = *self;
    }
}

impl BinaryReadable for u8 {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        if buf.len() < 1 {
            Err(BinaryReadError::BufferTooSmall)
        } else {
            Ok((buf[0], &buf[1..]))
        }
    }
}

impl FixedBinaryLength for u16 {
    fn fixed_binary_len() -> usize { 2 }
}

impl BinarySerialisable for u16 {
    fn write_to(&self, buf: &mut [u8]) {
        let bytes = self.to_be_bytes();

        buf.copy_from_slice(bytes.as_slice());
    }
}

impl BinaryReadable for u16 {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let bytes: [u8; 2] = buf.try_into().map_err(|_| BinaryReadError::BufferTooSmall)?;
        let value = u16::from_be_bytes(bytes);
        Ok((value, &buf[2..]))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
enum CompressionMethods {
    None = 0
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u16)]
#[allow(non_camel_case_types)]
enum CipherSuiteIdentifier {
    TLS_NULL_WITH_NULL_NULL               = 0x0000,
    TLS_RSA_WITH_NULL_MD5                 = 0x0001,
    TLS_RSA_WITH_NULL_SHA                 = 0x0002,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5        = 0x0003,
    TLS_RSA_WITH_RC4_128_MD5              = 0x0004,
    TLS_RSA_WITH_RC4_128_SHA              = 0x0005,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5    = 0x0006,
    TLS_RSA_WITH_IDEA_CBC_SHA             = 0x0007,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA     = 0x0008,
    TLS_RSA_WITH_DES_CBC_SHA              = 0x0009,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA         = 0x000A,
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  = 0x000B,
    TLS_DH_DSS_WITH_DES_CBC_SHA           = 0x000C,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = 0x000D,
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x000E,
    TLS_DH_RSA_WITH_DES_CBC_SHA           = 0x000F,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = 0x0010,
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
    TLS_DHE_DSS_WITH_DES_CBC_SHA          = 0x0012,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = 0x0013,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
    TLS_DHE_RSA_WITH_DES_CBC_SHA          = 0x0015,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = 0x0016,
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5    = 0x0017,
    TLS_DH_anon_WITH_RC4_128_MD5          = 0x0018,
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
    TLS_DH_anon_WITH_DES_CBC_SHA          = 0x001A,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = 0x001B,

    // 1C & 1D were used by SSLv3 to describe Fortezza suites
    // End of list of algorithms defined by RFC 2246

    // These are all defined in RFC 4346 (v1.1), not 2246 (v1.0)
    //
    TLS_KRB5_WITH_DES_CBC_SHA           = 0x001E,
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA      = 0x001F,
    TLS_KRB5_WITH_RC4_128_SHA           = 0x0020,
    TLS_KRB5_WITH_IDEA_CBC_SHA          = 0x0021,
    TLS_KRB5_WITH_DES_CBC_MD5           = 0x0022,
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5      = 0x0023,
    TLS_KRB5_WITH_RC4_128_MD5           = 0x0024,
    TLS_KRB5_WITH_IDEA_CBC_MD5          = 0x0025,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027,
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA     = 0x0028,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A,
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5     = 0x002B,

    // WARNING: the following are undefined i.e. do not correspond to a suite
    // The values of this type are used to index the CIPHER_SUITES array so we need to define
    // the values
    TLS_UNDEF_1 = 0x002C,
    TLS_UNDEF_2 = 0x002D,
    TLS_UNDEF_3 = 0x002E,

    // TLS_AES ciphersuites - RFC 3268
    TLS_RSA_WITH_AES_128_CBC_SHA      = 0x002F,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA   = 0x0030,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA   = 0x0031,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = 0x0033,
    TLS_DH_anon_WITH_AES_128_CBC_SHA  = 0x0034,
    TLS_RSA_WITH_AES_256_CBC_SHA      = 0x0035,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA   = 0x0036,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA   = 0x0037,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA  = 0x0038,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = 0x0039,
    TLS_DH_anon_WITH_AES_256_CBC_SHA  = 0x003A,
}

impl CipherSuiteIdentifier {
    pub fn key_exchange_method(&self) -> KeyExchangeMethod {
        match self {
            Self::TLS_NULL_WITH_NULL_NULL => {
                KeyExchangeMethod::None
            },
            Self::TLS_RSA_WITH_NULL_MD5 |
            Self::TLS_RSA_WITH_NULL_SHA |
            Self::TLS_RSA_EXPORT_WITH_RC4_40_MD5 |
            Self::TLS_RSA_WITH_RC4_128_MD5 |
            Self::TLS_RSA_WITH_RC4_128_SHA |
            Self::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 |
            Self::TLS_RSA_WITH_IDEA_CBC_SHA |
            Self::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA |
            Self::TLS_RSA_WITH_DES_CBC_SHA |
            Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA |
            Self::TLS_RSA_WITH_AES_128_CBC_SHA |
            Self::TLS_RSA_WITH_AES_256_CBC_SHA => {
                KeyExchangeMethod::RSA
            },
            _ => {
                KeyExchangeMethod::DH
            }
        }
    }
}

impl FixedBinaryLength for CipherSuiteIdentifier {
    fn fixed_binary_len() -> usize { u16::fixed_binary_len() }
}

impl BinarySerialisable for CipherSuiteIdentifier {
    fn write_to(&self, buf: &mut [u8]) {
        let s = *self as u16;
        s.write_to(buf);
    }
}

fn read_into<T, U>(buf: &[u8]) -> Result<(U, &[u8]), BinaryReadError>
    where T: BinaryReadable,
          U: TryFrom<T> {
    let (t, buf) = T::read_from(buf)?;
    let u = U::try_from(t).map_err(|_| BinaryReadError::ValueOutOfRange)?;
    Ok((u, buf))
}

impl BinaryReadable for CipherSuiteIdentifier {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        read_into::<u16, CipherSuiteIdentifier>(buf)
    }
}

struct CipherSuite {
    id: CipherSuiteIdentifier,
    block_size: usize,
    hash_size: usize,
    key_size: usize,
    iv_size: usize
}

// TODO: get hash algorithm from id and move to method
const MD5_BYTE_SIZE: usize = 16;
const SHA1_BYTE_SIZE: usize = 20;

const CIPHER_SUITES: [CipherSuite; 57] = [
    CipherSuite { id: CipherSuiteIdentifier::TLS_NULL_WITH_NULL_NULL, block_size: 0, hash_size: 0, key_size: 0, iv_size: 0, },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_NULL_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_NULL_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_EXPORT_WITH_RC4_40_MD5, block_size: 0, hash_size: 0, key_size: 5, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_RC4_128_MD5, block_size: 0, hash_size: 0, key_size: 16, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_RC4_128_SHA, block_size: 0, hash_size: 0, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_IDEA_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_DES_CBC_SHA, block_size: 8, hash_size: 8, key_size: 8, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_3DES_EDE_CBC_SHA, block_size: 8, hash_size: 8, key_size: 24, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, block_size: 8, hash_size: 8, key_size: 24, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_WITH_DES_CBC_SHA, block_size: 8, hash_size: 8, key_size: 8, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_RC4_128_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_RC4_128_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_IDEA_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_DES_CBC_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_3DES_EDE_CBC_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_RC4_128_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_IDEA_CBC_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_RC4_40_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_RC4_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },

    // XXX are these three defined?
    CipherSuite { id: CipherSuiteIdentifier::TLS_UNDEF_1, block_size: 0, hash_size: 0, key_size: 0, iv_size: 0 },
    CipherSuite { id: CipherSuiteIdentifier::TLS_UNDEF_2, block_size: 0, hash_size: 0, key_size: 0, iv_size: 0 },
    CipherSuite { id: CipherSuiteIdentifier::TLS_UNDEF_3, block_size: 0, hash_size: 0, key_size: 0, iv_size: 0 },

    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
];

fn get_cipher_suite(suite_id: CipherSuiteIdentifier) -> &'static CipherSuite {
    &CIPHER_SUITES[suite_id as usize]
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct ProtocolVersion {
    major: u8,
    minor: u8
}

impl BinaryReadable for ProtocolVersion {
    fn read_from(buf: &[u8]) -> Result<(ProtocolVersion, &[u8]), BinaryReadError> {
        if buf.len() < 2 {
            Err(BinaryReadError::BufferTooSmall)
        } else {
            let version = ProtocolVersion {
                major: buf[0],
                minor: buf[1]
            };
            Ok((version, &buf[2..]))
        }
    }
}

impl FixedBinaryLength for ProtocolVersion {
    fn fixed_binary_len() -> usize { 2 }
}

impl BinarySerialisable for ProtocolVersion {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.major;
        buf[1] = self.minor;
    }
}

const TLS_VERSION: ProtocolVersion = ProtocolVersion { major: 3, minor: 1 };

#[derive(Clone)]
struct Random {
    bytes: [u8; 32]
}

impl Random {
    fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

const MASTER_SECRET_LENGTH: usize = 48;
const RANDOM_LENGTH: usize = 32;

type MasterSecret = [u8; MASTER_SECRET_LENGTH];

impl FixedBinaryLength for Random {
    fn fixed_binary_len() -> usize { 32 }
}

impl BinarySerialisable for Random {
    fn write_to(&self, buf: &mut [u8]) {
        buf.copy_from_slice(self.bytes.as_slice());
    }
}

impl BinaryReadable for Random {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (bytes, buf) = read_slice(buf, 32)?;
        let r = Random { bytes: bytes.try_into().unwrap() };
        Ok((r, buf))
    }
}

impl Random {
    // Copies random bytes from another random and sets the first 4 bytes to a timestamp for
    // the current time
    // TODO: check if this is the correct behaviour!
    fn from_now(random: &Random) -> Random {
        let ts = Utc::now().timestamp() as u32;

        // copy unix timestamp followed by client random bytes
        let mut bytes = random.bytes.clone();
        bytes[0..4].copy_from_slice(ts.to_be_bytes().as_slice());

        Random { bytes }
    }
}

struct CipherSuites(Vec<CipherSuiteIdentifier>);

struct ClientHello {
    client_version: ProtocolVersion,
    random: Random,
    session_id: Vec<u8>,
    cipher_suites: CipherSuites,
    compression_methods: Vec<CompressionMethods>,
}

impl BinaryLength for ClientHello {
    fn binary_len(&self) -> usize {
        ProtocolVersion::fixed_binary_len() +
            Random::fixed_binary_len() +
            self.session_id.as_slice().binary_len() +
            self.cipher_suites.binary_len() +
            self.compression_methods.as_slice().binary_len()
    }
}

fn write_front<'a, T: BinarySerialisable>(msg: &T, buf: &'a mut [u8]) -> &'a mut [u8] {
    let (msg_buf, rest) = buf.split_at_mut(msg.binary_len());
    msg.write_to(msg_buf);
    rest
}

impl BinarySerialisable for ClientHello {
    fn write_to(&self, buf: &mut [u8]) {
        let buf = write_front(&self.client_version, buf);
        let buf = write_front(&self.random, buf);
        let buf = write_front(&self.session_id.as_slice(), buf);
        let buf = write_front(&self.cipher_suites, buf);
        self.compression_methods.as_slice().write_to(buf);
    }
}

fn write_elements<L, T>(buf: &mut [u8], elems: &[T])
    where L: TryFrom<usize> + BinarySerialisable,
          <L as TryFrom<usize>>::Error : Debug,
          T: BinarySerialisable
{
    let len = L::try_from(elems.len()).expect("Length too large for length type");
    let mut buf = write_front(&len, buf);

    for e in elems.iter() {
        buf = write_front(e, buf);
    }
}

fn read_slice(buf: &[u8], length: usize) -> Result<(&[u8], &[u8]), BinaryReadError> {
    if buf.len() >= length {
        Ok(buf.split_at(length))
    } else {
        Err(BinaryReadError::BufferTooSmall)
    }
}

fn read_elements<L, T>(buf: &[u8]) -> Result<(Vec<T>, &[u8]), BinaryReadError>
    where L: Into<usize> + BinaryReadable + FixedBinaryLength,
          T: BinaryReadable + FixedBinaryLength
{
    // read length
    let (length, buf) = L::read_from(buf)?;
    let length = length.into();

    // read element bytes
    let byte_length = length * T::fixed_binary_len();
    let (element_bytes, buf) = read_slice(buf, byte_length)?;

    let mut v = Vec::with_capacity(length);
    for i in (0..length).step_by(T::fixed_binary_len()) {
        // TODO: possible to ensure this can't fail statically?
        // TODO: check bytes read == fixed_binary_len()?
        let (elem, _) = T::read_from(&element_bytes[i..])?;
        v.push(elem);
    }

    Ok((v, buf))
}

impl <T: FixedBinaryLength> BinaryLength for &[T] {
    fn binary_len(&self) -> usize {
        // length is a single byte
        (self.len() * T::fixed_binary_len()) + u8::fixed_binary_len()
    }
}

impl <T: FixedBinaryLength + BinarySerialisable> BinarySerialisable for &[T] {
    fn write_to(&self, buf: &mut [u8]) {
        write_elements::<u8, T>(buf, self);
    }
}

impl BinaryLength for CipherSuites {
    fn binary_len(&self) -> usize {
        // WARNING: cipher suites length is 2 bytes!
        (self.0.len() * CipherSuiteIdentifier::fixed_binary_len()) + u16::fixed_binary_len()
    }
}

impl BinarySerialisable for CipherSuites {
    fn write_to(&self, buf: &mut [u8]) {
        let elems = self.0.as_slice();
        write_elements::<u16, _>(buf, elems);
    }
}

impl FixedBinaryLength for CompressionMethods {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl BinarySerialisable for CompressionMethods {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0] = *self as u8;
    }
}

impl BinaryReadable for CompressionMethods {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        read_into::<u8, CompressionMethods>(buf)
    }
}

#[derive(Clone)]
struct ProtectionParameters {
    mac_secret: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    suite: CipherSuiteIdentifier,
    seq_num: u64
}

impl ProtectionParameters {
    fn set_secrets(&mut self, mac: &[u8], key: &[u8], iv: &[u8]) {
        self.mac_secret = mac.to_vec();
        self.key = key.to_vec();
        self.iv = iv.to_vec();
    }

    fn init(&mut self) {
        self.suite = CipherSuiteIdentifier::TLS_NULL_WITH_NULL_NULL;
        self.seq_num = 0;
        self.mac_secret = Vec::new();
        self.key = Vec::new();
        self.iv = Vec::new();
    }
}

#[derive(Clone)]
struct TLSParameters {
    master_secret: MasterSecret,
    client_random: Random,
    server_random: Random,

    pending_send_parameters: ProtectionParameters,
    pending_recv_parameters: ProtectionParameters,
    active_send_parameters: ProtectionParameters,
    active_recv_parameters: ProtectionParameters,

    server_public_key: PublicKeyInfo,
    server_dh_key: Option<DHKey>,

    md5_handshake_digest: <MD5HashAlgorithm as HashAlgorithm>::State,
    sha1_handshake_digest: <SHA1HashAlgorithm as HashAlgorithm>::State,

    server_hello_done: bool
}

impl TLSParameters {
    fn init(&mut self) {
        self.md5_handshake_digest = (MD5HashAlgorithm {}).initialise();
        self.sha1_handshake_digest = (SHA1HashAlgorithm {}).initialise();
        todo!()
    }

    fn make_active(&mut self) {
        self.active_send_parameters = self.pending_send_parameters.clone();
        self.pending_send_parameters.init();
    }

    fn update_digests(&mut self, data: &[u8]) {
        hash::update(data, &MD5HashAlgorithm {}, &mut self.md5_handshake_digest);
        hash::update(data, &SHA1HashAlgorithm {}, &mut self.sha1_handshake_digest);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
#[allow(non_camel_case_types)]
enum HandshakeType {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20
}

impl FixedBinaryLength for HandshakeType {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl BinarySerialisable for HandshakeType {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0] = *self as u8;
    }
}

impl BinaryReadable for HandshakeType {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (byte, buf) = u8::read_from(buf)?;
        let handshake_type = HandshakeType::try_from(byte).map_err(|_| BinaryReadError::ValueOutOfRange)?;
        Ok((handshake_type, buf))
    }
}

// Represents a 3-byte integer
// This is used to encode the length of a Handshake message and the length of certificate chains
// and their contained certificates
struct U24(u32);

impl TryFrom<usize> for U24 {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > 0xFFFFFFusize {
            Err(())
        } else {
            Ok(U24(value as u32))
        }
    }
}

impl From<U24> for usize {
    fn from(v: U24) -> Self {
        v.0 as usize
    }
}

impl FixedBinaryLength for U24 {
    fn fixed_binary_len() -> usize { 3 }
}

impl BinarySerialisable for U24 {
    fn write_to(&self, buf: &mut [u8]) {
        let len_bytes = self.0.to_be_bytes();
        buf[0..3].copy_from_slice(&len_bytes[1..]);
    }
}

impl BinaryReadable for U24 {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        if buf.len() < 3 {
            Err(BinaryReadError::BufferTooSmall)
        } else {
            let mut be_bytes: [u8; 4] = [0, 0, 0, 0];
            be_bytes[1..].copy_from_slice(&buf[0..3]);
            let value = u32::from_be_bytes(be_bytes);
            Ok((U24(value), &buf[3..]))
        }
    }
}

struct HandshakeHeader {
    handshake_type: HandshakeType,
    length: U24
}

impl FixedBinaryLength for HandshakeHeader {
    fn fixed_binary_len() -> usize {
        HandshakeType::fixed_binary_len() + U24::fixed_binary_len()
    }
}

impl BinarySerialisable for HandshakeHeader {
    fn write_to(&self, buf: &mut [u8]) {
        let buf = write_front(&self.handshake_type, buf);
        write_front(&self.length, buf);
    }
}

impl BinaryReadable for HandshakeHeader {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (handshake_type, buf) = HandshakeType::read_from(buf)?;
        let (length, buf) = U24::read_from(buf)?;
        Ok((HandshakeHeader { handshake_type, length }, buf))
    }
}

enum ClientHandshakeMessage {
    Hello(ClientHello),
    KeyExchange(KeyExchange)
}

impl ClientHandshakeMessage {
    fn get_header(&self) -> HandshakeHeader {
        match self {
            Self::Hello(client_hello) => {
                // TODO: validate message length fits? Should always be enough!
                let length = U24::try_from(client_hello.binary_len()).expect("Message too large");
                HandshakeHeader { handshake_type: HandshakeType::CLIENT_HELLO, length }
            },
            Self::KeyExchange(key_exchange) => {
                let length = U24::try_from(key_exchange.binary_len()).expect("Message too large");
                HandshakeHeader { handshake_type: HandshakeType::CLIENT_KEY_EXCHANGE, length }
            }
        }
    }
}

impl BinaryLength for ClientHandshakeMessage {
    fn binary_len(&self) -> usize {
        let message_len = match self {
            Self::Hello(hello) => hello.binary_len(),
            Self::KeyExchange(rsa_key_exchange) => rsa_key_exchange.binary_len()
        };
        HandshakeHeader::fixed_binary_len() + message_len
    }
}

impl BinarySerialisable for ClientHandshakeMessage {
    fn write_to(&self, buf: &mut [u8]) {
        let header = self.get_header();

        // write header
        let buf = write_front(&header, buf);

        // write message
        match self {
            Self::Hello(client_hello) => {
                write_front(client_hello, buf)
            },
            Self::KeyExchange(rsa_key_exchange) => {
                write_front(rsa_key_exchange, buf)
            }
        };
    }
}

fn send_client_hello<W: Write>(dest: &mut W, params: &mut TLSParameters) -> io::Result<()> {
    let hello = ClientHello {
        client_version: TLS_VERSION,
        random: Random::from_now(&params.client_random),
        session_id: Vec::new(),
        compression_methods: vec![CompressionMethods::None],
        cipher_suites: CipherSuites(vec![CipherSuiteIdentifier::TLS_RSA_WITH_3DES_EDE_CBC_SHA])
    };

    send_handshake_message(dest, ClientHandshakeMessage::Hello(hello), params)
}

enum KeyExchangeMethod {
    RSA,
    DH,
    None
}

#[derive(Clone)]
enum KeyExchange {
    RSA(RSAKeyExchange),
    DH(DHKeyExchange)
}

impl BinaryLength for KeyExchange {
    fn binary_len(&self) -> usize {
        match self {
            Self::RSA(rsa_exchange) => rsa_exchange.binary_len(),
            Self::DH(dh_exchange) => dh_exchange.binary_len()
        }
    }
}

impl BinarySerialisable for KeyExchange {
    fn write_to(&self, buf: &mut [u8]) {
        match self {
            Self::RSA(rsa_exchange) => { rsa_exchange.write_to(buf) },
            Self::DH(dh_exchange) => { dh_exchange.write_to(buf) }
        }
    }
}

impl KeyExchange {
    fn premaster_secret(&self) -> &MasterSecret {
        match self {
            Self::RSA(rsa_key_exchange) => { &rsa_key_exchange.premaster_secret },
            Self::DH(dh_key_exchange) => { &dh_key_exchange.premaster_secret }
        }
    }
}

#[derive(Clone)]
struct RSAKeyExchange {
    premaster_secret: MasterSecret,
    encrypted_premaster_secret: Vec<u8>
}

impl RSAKeyExchange {
    fn new(version: &ProtocolVersion, key: &RSAKey) -> Self {
        let mut premaster_secret = [0u8; MASTER_SECRET_LENGTH];
        let buf = write_front(version, premaster_secret.as_mut_slice());

        // NOTE: Should be random!
        for i in 0..buf.len() {
            premaster_secret[i] = i as u8;
        }

        let encrypted_premaster_secret = rsa::rsa_encrypt(key, premaster_secret.as_slice());

        Self { premaster_secret, encrypted_premaster_secret }
    }
}

impl BinaryLength for RSAKeyExchange {
    fn binary_len(&self) -> usize {
        // 1 byte for ?
        // 1 byte for length
        // n bytes for encrypted premaster secret
        1 + 1 + self.encrypted_premaster_secret.len()
    }
}

impl BinarySerialisable for RSAKeyExchange {
    fn write_to(&self, buf: &mut [u8]) {
        // TODO: what's this for?
        let buf = write_front(&0u8, buf);
        write_elements::<u8, u8>(buf, self.encrypted_premaster_secret.as_slice());
    }
}

#[derive(Clone)]
struct DHKeyExchange {
    y_c: Huge,
    premaster_secret: MasterSecret
}

impl DHKeyExchange {
    fn new(server_dh_key: &DHKey) -> Self {
        // TODO: make this random and much longer
        let a = Huge::from(6u8);

        let y_c = server_dh_key.g.clone().mod_pow(a.clone(), server_dh_key.p.clone());
        let z = server_dh_key.y.clone().mod_pow(a, server_dh_key.p.clone());

        // copy Z to front of new premaster secret buffer
        let mut premaster_secret = [0u8; MASTER_SECRET_LENGTH];
        &mut premaster_secret[0..z.bytes().len()].copy_from_slice(z.bytes());

        Self { y_c, premaster_secret }
    }
}

impl BinaryLength for DHKeyExchange {
    fn binary_len(&self) -> usize {
        // message is 2-byte length followed by the bytes of y_c
        u16::fixed_binary_len() + self.y_c.bytes().len()
    }
}

impl BinarySerialisable for DHKeyExchange {
    fn write_to(&self, buf: &mut [u8]) {
        let len = self.y_c.bytes().len() as u16;
        let buf = write_front(&len, buf);
        &mut buf[0..(len as usize)].copy_from_slice(self.y_c.bytes());
    }
}

fn calculate_keys(parameters: &mut TLSParameters) {
    let suite = get_cipher_suite(parameters.pending_send_parameters.suite);
    let label = "key expansion".as_bytes();
    let key_block_length = suite.hash_size * 2 + suite.key_size * 2 + suite.iv_size * 2;

    // seed is server random followed by client random
    // NOTE: This is the opposite of compute_master_secret
    let seed = [parameters.server_random.bytes(), parameters.client_random.bytes()].concat();

    let key_bytes = prf_bytes(parameters.master_secret.as_slice(), label, seed.as_slice(), key_block_length);
    let (send_mac, remaining) = key_bytes.split_at(suite.hash_size);
    let (recv_mac, remaining) = remaining.split_at(suite.hash_size);
    let (send_key, remaining) = remaining.split_at(suite.key_size);
    let (recv_key, remaining) = remaining.split_at(suite.key_size);
    let (send_iv, remaining) = remaining.split_at(suite.iv_size);
    let (recv_iv, remaining) = remaining.split_at(suite.iv_size);

    assert_eq!(0, remaining.len(), "Should consume all generated bytes");

    // set mac/key/iv for send and receive parameters
    parameters.pending_send_parameters.set_secrets(send_mac, send_key, send_iv);
    parameters.pending_recv_parameters.set_secrets(recv_mac, recv_key, recv_iv);
}

fn send_client_key_exchange<W: Write>(dest: &mut W, parameters: &mut TLSParameters) -> Result<(), TLSError> {
    let key_exchange_message = match parameters.pending_send_parameters.suite.key_exchange_method() {
        KeyExchangeMethod::RSA => {
            // server key should be RSA!
            match &parameters.server_public_key {
                PublicKeyInfo::RSA(rsa_key) => {
                    let rsa_exchange = RSAKeyExchange::new(&TLS_VERSION, rsa_key);
                    Ok(KeyExchange::RSA(rsa_exchange))
                },
                _ => {
                    Err(TLSError::ProtocolError("Server requires RSA key exchange with non-RSA public key".to_owned()))
                }
            }
        },
        KeyExchangeMethod::DH => {
            match &parameters.server_dh_key {
                Some(dh_key) => {
                    let dh_exchange = DHKeyExchange::new(dh_key);
                    Ok(KeyExchange::DH(dh_exchange))
                },
                None => {
                    Err(TLSError::ProtocolError("Cannot perform DH key exchange without server DH key".to_owned()))
                }
            }
        }
        _ => {
            todo!()
        }
    }?;

    let msg = ClientHandshakeMessage::KeyExchange(key_exchange_message.clone());
    send_handshake_message(dest, msg, parameters).map_err(TLSError::IOError)?;

    // calculate the master secret from the premaster secret
    // the server side will perform the same calculation
    compute_master_secret(key_exchange_message.premaster_secret().as_slice(), parameters);

    // TODO: purge the premaster secret from memory
    calculate_keys(parameters);

    Ok(())
}

struct TLSMessageBuffer {
    version: ProtocolVersion,
    message_type: ContentType,
    data: Vec<u8>
}

impl BinaryLength for TLSMessageBuffer {
    fn binary_len(&self) -> usize {
        TLSHeader::fixed_binary_len() + self.data.len()
    }
}

impl BinarySerialisable for TLSMessageBuffer {
    fn write_to(&self, buf: &mut [u8]) {
        let header = TLSHeader {
            message_type: self.message_type,
            version: self.version.clone(),
            length: buf.len() as u16,
        };
        let buf = write_front(&header, buf);
        buf[0..self.data.len()].copy_from_slice(self.data.as_slice());
    }
}

fn send_handshake_message<W: Write>(dest: &mut W, handshake_message: ClientHandshakeMessage, parameters: &mut TLSParameters) -> io::Result<()> {
    // serialise handshake message and use it to update the handshake digests
    let message_buf = handshake_message.write_to_vec();
    parameters.update_digests(message_buf.as_slice());

    let msg = TLSMessageBuffer {
        // TODO: get from TLS parameters?
        version: TLS_VERSION,
        message_type: handshake_message.get_content_type(),
        data: message_buf
    };

    send_message(dest, msg)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
enum AlertLevel {
    Warning = 1,
    Fatal = 2
}

impl Display for AlertLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AlertLevel::Warning => "Warning",
            AlertLevel::Fatal => "Fatal"
        };
        f.write_str(s)
    }
}

impl FixedBinaryLength for AlertLevel {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl BinarySerialisable for AlertLevel {
    fn write_to(&self, buf: &mut [u8]) {
        (*self as u8).write_to(buf);
    }
}

impl BinaryReadable for AlertLevel {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        read_into::<u8, AlertLevel>(buf)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMAC = 20,
    DecryptionFailed = 21,
    RecordOverflow = 22,
    DecompressionFailure = 30,
    HandshakeFailure = 40,
    BadCertificate = 42,
    UnsupportedCertificate = 43,
    CertificateRevoked = 44,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCA = 48,
    AccessDenied = 49,
    DecodeError = 50,
    DecryptError = 51,
    ExportRestriction = 60,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    UserCancelled = 90,
    NoRenegotiation = 100
}

impl Display for AlertDescription {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AlertDescription::CloseNotify => "Close notify",
            AlertDescription::UnexpectedMessage => "Unexpected message",
            AlertDescription::BadRecordMAC => "Bad record MAC",
            AlertDescription::DecryptionFailed => "Decryption failed",
            AlertDescription::RecordOverflow => "Record Overflow",
            AlertDescription::DecompressionFailure => "Decompression Failure",
            AlertDescription::HandshakeFailure => "Handshake Failure",
            AlertDescription::BadCertificate => "Bad Certificate",
            AlertDescription::UnsupportedCertificate => "Unsupported Certificate",
            AlertDescription::CertificateRevoked => "Certificate Revoked",
            AlertDescription::CertificateExpired => "Certificate Expired",
            AlertDescription::CertificateUnknown => "Certificate Unknown",
            AlertDescription::IllegalParameter => "Illegal Parameter",
            AlertDescription::UnknownCA => "Unknown CA",
            AlertDescription::AccessDenied => "Access Denied",
            AlertDescription::DecodeError => "Decode Error",
            AlertDescription::DecryptError => "Decrypt Error",
            AlertDescription::ExportRestriction => "Export Restriction",
            AlertDescription::ProtocolVersion => "Protocol Version",
            AlertDescription::InsufficientSecurity => "Insufficient Security",
            AlertDescription::InternalError => "Internal Error",
            AlertDescription::UserCancelled => "User Cancelled",
            AlertDescription::NoRenegotiation => "No renegotiation"
        };
        f.write_str(s)
    }
}

impl FixedBinaryLength for AlertDescription {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl BinarySerialisable for AlertDescription {
    fn write_to(&self, buf: &mut [u8]) {
        (*self as u8).write_to(buf)
    }
}

impl BinaryReadable for AlertDescription {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        read_into::<u8, AlertDescription>(buf)
    }
}

struct Alert {
    level: AlertLevel,
    description: AlertDescription
}

impl BinarySerialisable for Alert {
    fn write_to(&self, buf: &mut [u8]) {
        let buf = write_front(&self.level, buf);
        self.description.write_to(buf);
    }
}

impl FixedBinaryLength for Alert {
    fn fixed_binary_len() -> usize {
        AlertLevel::fixed_binary_len() + AlertDescription::fixed_binary_len()
    }
}

impl BinaryReadable for Alert {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (level, buf) = AlertLevel::read_from(buf)?;
        let (description, buf) = AlertDescription::read_from(buf)?;
        Ok((Alert { level, description }, buf))
    }
}

impl FixedBinaryLength for ContentType {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl BinarySerialisable for ContentType {
    fn write_to(&self, buf: &mut [u8]) {
        (*self as u8).write_to(buf);
    }
}

impl BinaryReadable for ContentType {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        if buf.len() < 1 {
            Err(BinaryReadError::BufferTooSmall)
        } else {
            let message_type = ContentType::try_from(buf[0]).map_err(|_| BinaryReadError::ValueOutOfRange)?;
            Ok((message_type, &buf[1..]))
        }
    }
}

// TODO: Change to (version, type, buf)?
struct TLSPlaintext<T> {
    version: ProtocolVersion,
    message: T,
}

trait TLSMessage {
    fn get_content_type(&self) -> ContentType;
}

impl TLSMessage for ClientHandshakeMessage {
    fn get_content_type(&self) -> ContentType {
        ContentType::Handshake
    }
}

impl TLSMessage for Alert {
    fn get_content_type(&self) -> ContentType {
        ContentType::Alert
    }
}

impl <T: BinaryLength> BinaryLength for TLSPlaintext<T> {
    fn binary_len(&self) -> usize {
        // 1 byte for message type
        // 2 bytes for protocol version
        // 2 bytes for length
        ContentType::fixed_binary_len() + ProtocolVersion::fixed_binary_len() + 2 + self.message.binary_len()
    }
}

impl <T: TLSMessage + BinarySerialisable> BinarySerialisable for TLSPlaintext<T> {
    fn write_to(&self, buf: &mut [u8]) {
        let header = TLSHeader {
            message_type: self.message.get_content_type(),
            length: self.message.binary_len() as u16,
            version: self.version.clone()
        };

        // write header
        let buf = write_front(&header, buf);

        // write message
        self.message.write_to(buf);
    }
}

fn send_message<W: Write, T: BinarySerialisable>(dest: &mut W, msg: T) -> io::Result<()> {
    let buf = msg.write_to_vec();

    // TODO: check entire message was written
    let result = dest.write(buf.as_slice())?;

    Ok(())
}

fn read_exact<R: Read>(source: &mut R, bytes: usize) -> io::Result<Vec<u8>> {
    let mut dest = vec![0; bytes];
    let mut offset = 0;

    while offset < bytes {
        let bytes_read = source.read(&mut dest[offset..])?;
        if bytes_read == 0 {
            // EOF
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "Failed to read requested number of bytes: EOF"));
        }
        offset += bytes_read
    }
    Ok(dest)
}

struct TLSHeader {
    message_type: ContentType,
    version: ProtocolVersion,
    length: u16
}

impl FixedBinaryLength for TLSHeader {
    fn fixed_binary_len() -> usize {
        ContentType::fixed_binary_len() + ProtocolVersion::fixed_binary_len() + u16::fixed_binary_len()
    }
}

impl BinarySerialisable for TLSHeader {
    fn write_to(&self, buf: &mut [u8]) {
        // write content type
        let buf = write_front(&self.message_type, buf);

        // write protocol version
        let buf = write_front(&self.version, buf);

        // write message length
        write_front(&self.length, buf);
    }
}

impl BinaryReadable for TLSHeader {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (message_type, buf) = ContentType::read_from(buf)?;
        let (version, buf) = ProtocolVersion::read_from(buf)?;
        let (length, buf) = u16::read_from(buf)?;
        let header = TLSHeader {
            message_type, version, length
        };
        Ok((header, buf))
    }
}

fn send_alert_message<W: Write>(dest: &mut W, code: AlertDescription) -> io::Result<()> {
    let alert = Alert { level: AlertLevel::Fatal, description: code };
    let message = TLSPlaintext {
        version: TLS_VERSION,
        message: alert
    };
    send_message(dest, message)
}

enum TLSError {
    IOError(io::Error),
    ParseError(BinaryReadError),
    UnknownMessage,
    ProtocolError(String)
}

struct SessionId(Vec<u8>);

impl BinaryReadable for SessionId {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (bytes, buf) = read_elements::<u8, u8>(buf)?;
        Ok((SessionId(bytes), buf))
    }
}

struct ServerHello {
    server_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suite: CipherSuiteIdentifier,
    compression_method: CompressionMethods
}

impl BinaryReadable for ServerHello {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (server_version, buf) = ProtocolVersion::read_from(buf)?;
        let (random, buf) = Random::read_from(buf)?;
        let (session_id, buf) = SessionId::read_from(buf)?;
        let (cipher_suite, buf) = CipherSuiteIdentifier::read_from(buf)?;
        let (compression_method, buf) = CompressionMethods::read_from(buf)?;

        let server_hello = ServerHello {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method
        };

        Ok((server_hello, buf))
    }
}

struct CertificateChain {
    server_certificate: SignedX509Certificate,
    validation_chain: Vec<SignedX509Certificate>
}

struct ServerCertificateChain {
    chain: CertificateChain
}

fn read_x509_certificate(buf: &[u8]) -> Result<(SignedX509Certificate, &[u8]), BinaryReadError> {
    let (cert_length_bytes, buf) = U24::read_from(buf)?;
    let (cert_bytes, buf) = read_slice(buf, cert_length_bytes.into())?;

    let cert = x509::parse(cert_bytes).map_err(|_| BinaryReadError::ValueOutOfRange)?;

    Ok((cert, buf))
}

impl BinaryReadable for ServerCertificateChain {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (chain_length_bytes, buf) = U24::read_from(buf)?;
        let chain_length_bytes: usize = chain_length_bytes.into();

        let (chain_buf, remaining) = read_slice(buf, chain_length_bytes)?;

        // chain should contain at least one certificate
        let (server_certificate, validation_buf) = read_x509_certificate(chain_buf)?;

        let mut validation_chain = Vec::new();
        let mut validation_buf = validation_buf;

        // parse remaining certificates
        while validation_buf.len() > 0 {
            let (cert, validation_remaining) = read_x509_certificate(validation_buf)?;
            validation_chain.push(cert);
            validation_buf = validation_remaining;
        }

        let chain = CertificateChain { server_certificate, validation_chain };
        Ok((ServerCertificateChain { chain }, remaining))
    }
}

enum ServerHandshakeMessage {
    Hello(ServerHello),
    CertificateChain(ServerCertificateChain),
    Done
}

impl BinaryReadable for ServerHandshakeMessage {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (handshake_header, buf) = HandshakeHeader::read_from(buf)?;
        let message_len: usize = handshake_header.length.into();

        let (message_buf, remaining) = buf.split_at(message_len);

        let handshake_message = match handshake_header.handshake_type {
            HandshakeType::SERVER_HELLO => {
                ServerHello::read_all_from(message_buf).map(ServerHandshakeMessage::Hello)
            },
            HandshakeType::CERTIFICATE => {
                ServerCertificateChain::read_all_from(message_buf).map(ServerHandshakeMessage::CertificateChain)
            },
            HandshakeType::SERVER_HELLO_DONE => {
                // 'server hello done' message contains no data
                // TODO: check message_buf is empty?
                Ok(ServerHandshakeMessage::Done)
            }
            _ => Err(BinaryReadError::UnknownType)
        }?;

        Ok((handshake_message, remaining))
    }
}

struct ChangeCipherSpec {}

impl FixedBinaryLength for ChangeCipherSpec {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl BinarySerialisable for ChangeCipherSpec {
    fn write_to(&self, buf: &mut [u8]) {
        1u8.write_to(buf)
    }
}

impl BinaryReadable for ChangeCipherSpec {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (b, rest) = u8::read_from(buf)?;
        if b == 1 {
            Ok((ChangeCipherSpec {}, rest))
        } else {
            Err(BinaryReadError::ValueOutOfRange)
        }
    }
}

impl TLSMessage for ChangeCipherSpec {
    fn get_content_type(&self) -> ContentType {
        ContentType::ChangeCipherSpec
    }
}

fn send_change_cipher_spec<W: Write>(conn: &mut W, parameters: &mut TLSParameters) -> Result<(), TLSError> {
    let msg = TLSPlaintext { version: TLS_VERSION.clone(), message: ChangeCipherSpec { } };
    send_message(conn, msg).map_err(TLSError::IOError)?;

    parameters.pending_send_parameters.seq_num = 0;
    parameters.make_active();

    Ok(())
}

enum ServerMessage {
    Alert(Alert),
    Handshakes(Vec<ServerHandshakeMessage>),
    ChangeCipherSpec
}

fn read_seq<T: BinaryReadable>(buf: &[u8]) -> Result<Vec<T>, BinaryReadError> {
    let mut result = Vec::new();
    let mut buf = buf;

    while ! buf.is_empty() {
        let (v, remaining) = T::read_from(buf)?;
        result.push(v);
        buf = remaining
    }

    Ok(result)
}

fn parse_server_message(header: &TLSHeader, buf: Vec<u8>, parameters: &mut TLSParameters) -> Result<ServerMessage, TLSError> {
    match header.message_type {
        ContentType::Handshake => {
            // TODO: check this is valid!
            // Need to update hash with each handshake message individually?
            parameters.update_digests(buf.as_slice());
            read_seq(buf.as_slice())
                .map(ServerMessage::Handshakes)
                .map_err(TLSError::ParseError)
        },
        ContentType::Alert => {
            // TODO: Make Alerts errors?
            Alert::read_all_from(buf.as_slice())
                .map(ServerMessage::Alert)
                .map_err(TLSError::ParseError)
        },
        ContentType::ChangeCipherSpec => {
            ChangeCipherSpec::read_all_from(buf.as_slice())
                .map(|_| ServerMessage::ChangeCipherSpec)
                .map_err(TLSError::ParseError)
        }
        _ => {
            Err(TLSError::UnknownMessage)
        }
    }
}

// TODO: make method on TLSParameters?
fn compute_master_secret(premaster_secret: &[u8], parameters: &mut TLSParameters) {
    let label = "master secret".as_bytes();

    // seed is concatenation of the client and server random
    let seed = [parameters.client_random.bytes.as_slice(), parameters.server_random.bytes.as_slice()].concat();

    let mut master_secret = [0u8; MASTER_SECRET_LENGTH];
    prf(premaster_secret, label, seed.as_slice(), master_secret.as_mut_slice());

    parameters.master_secret = master_secret
}

fn receive_tls_msg(conn: &mut TcpStream, parameters: &mut TLSParameters) -> Result<ServerMessage, TLSError> {
    // read TLS Record header
    let header_buf = read_exact(conn, TLSHeader::fixed_binary_len()).map_err(TLSError::IOError)?;
    let (tls_header, _) = TLSHeader::read_from(header_buf.as_slice()).map_err(TLSError::ParseError)?;

    // read message body
    match read_exact(conn, tls_header.length as usize) {
        Ok(message_buf) => {
           parse_server_message(&tls_header, message_buf, parameters)
        },
        Err(_) => {
            send_alert_message(conn, AlertDescription::IllegalParameter);
            // TODO: Add 'state' Error type and remove IOError?
            let ioe = io::Error::new(ErrorKind::UnexpectedEof, "Failed to read message body");
            return Err(TLSError::IOError(ioe));
        }
    }
}

fn report_alert(alert: &Alert) {
    println!("Alert - {}: {}", alert.level, alert.description)
}

// TODO: can change TcpStream to Read?
fn tls_connect(conn: &mut TcpStream, tls_params: &mut TLSParameters) -> Result<(), TLSError> {
    tls_params.init();

    // step 1
    // send the TLS handshake 'client hello' message
    send_client_hello(conn, tls_params).map_err(TLSError::IOError)?;

    // step 2
    // receive the server hello response
    while !tls_params.server_hello_done {
        match receive_tls_msg(conn, tls_params)? {
            ServerMessage::Handshakes(handshakes) => {
                for handshake in handshakes {
                    match handshake {
                        ServerHandshakeMessage::Hello(server_hello) => {
                            // update pending parameters with server cipher suite
                            tls_params.pending_recv_parameters.suite = server_hello.cipher_suite;
                            tls_params.pending_send_parameters.suite = server_hello.cipher_suite;
                        },
                        ServerHandshakeMessage::CertificateChain(server_cert_chain) => {
                            todo!()
                        },
                        ServerHandshakeMessage::Done => {
                            tls_params.server_hello_done = true;
                        }
                    }
                }
            },
            ServerMessage::ChangeCipherSpec => {
                // TODO: can handle?
                return Err(TLSError::ProtocolError("Unexpected 'change cipher spec' message while waiting for server handshake".to_owned()))
            }
            ServerMessage::Alert(alert) => {
                report_alert(&alert);
            }
        };
    }

    // step 3
    // send client key exchange
    send_client_key_exchange(conn, tls_params)?;

    // step 4
    // send 'change cipher spec' message
    send_change_cipher_spec(conn, tls_params)?;

    todo!()
}
