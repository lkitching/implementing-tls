use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};

use num_enum::{TryFromPrimitive};
use chrono::{DateTime, Utc};

use super::serde::*;
use crate::huge::{Huge};
use crate::rsa::{self, RSAKey};
use crate::dh::{DHKey};
use crate::x509::{self, SignedX509Certificate};

pub trait TLSMessage {
    fn get_content_type(&self) -> ContentType;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
pub enum CompressionMethods {
    None = 0
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum CipherSuiteIdentifier {
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

pub enum KeyExchangeMethod {
    RSA,
    DH,
    None
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

impl BinaryReadable for CipherSuiteIdentifier {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        read_into::<u16, CipherSuiteIdentifier>(buf)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8
}

impl ProtocolVersion {
    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
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

#[derive(Clone)]
pub struct Random {
    bytes: [u8; 32]
}

impl Random {
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

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
    pub fn from_now(random: &Random) -> Random {
        let ts = Utc::now().timestamp() as u32;

        // copy unix timestamp followed by client random bytes
        let mut bytes = random.bytes.clone();
        bytes[0..4].copy_from_slice(ts.to_be_bytes().as_slice());

        Random { bytes }
    }
}

pub struct CipherSuites(pub Vec<CipherSuiteIdentifier>);

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

pub struct ClientHello {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: Vec<u8>,
    pub cipher_suites: CipherSuites,
    pub compression_methods: Vec<CompressionMethods>,
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

impl BinarySerialisable for ClientHello {
    fn write_to(&self, buf: &mut [u8]) {
        let buf = write_front(&self.client_version, buf);
        let buf = write_front(&self.random, buf);
        let buf = write_front(&self.session_id.as_slice(), buf);
        let buf = write_front(&self.cipher_suites, buf);
        self.compression_methods.as_slice().write_to(buf);
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum HandshakeType {
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
pub struct U24(u32);

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

pub const VERIFY_DATA_LENGTH: usize = 12;
pub type VerifyData = [u8; VERIFY_DATA_LENGTH];

pub struct Finished {
    pub verify_data: VerifyData
}

impl FixedBinaryLength for Finished {
    fn fixed_binary_len() -> usize { VERIFY_DATA_LENGTH }
}

impl BinarySerialisable for Finished {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0..VERIFY_DATA_LENGTH].copy_from_slice(self.verify_data.as_slice())
    }
}

impl BinaryReadable for Finished {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let verify_data = buf[0..VERIFY_DATA_LENGTH].try_into().map_err(|_| BinaryReadError::BufferTooSmall)?;
        Ok((Finished { verify_data }, &buf[VERIFY_DATA_LENGTH..]))
    }
}

pub struct HandshakeHeader {
    pub handshake_type: HandshakeType,
    pub length: U24
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

// TODO: create proper type?
pub const MASTER_SECRET_LENGTH: usize = 48;
pub type MasterSecret = [u8; MASTER_SECRET_LENGTH];

pub trait KeyExchangeMessage {
    fn premaster_secret(&self) -> &MasterSecret;
}

#[derive(Clone)]
pub struct RSAKeyExchange {
    premaster_secret: MasterSecret,
    encrypted_premaster_secret: Vec<u8>
}

impl KeyExchangeMessage for RSAKeyExchange {
    fn premaster_secret(&self) -> &MasterSecret {
        &self.premaster_secret
    }
}

impl RSAKeyExchange {
    pub fn new(version: &ProtocolVersion, key: &RSAKey) -> Self {
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
pub struct DHKeyExchange {
    y_c: Huge,
    premaster_secret: MasterSecret
}

impl DHKeyExchange {
    pub fn new(server_dh_key: &DHKey) -> Self {
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

impl KeyExchangeMessage for DHKeyExchange {
    fn premaster_secret(&self) -> &MasterSecret {
        &self.premaster_secret
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

pub struct TLSHeader {
    pub message_type: ContentType,
    pub version: ProtocolVersion,
    pub length: u16
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

pub struct TLSMessageBuffer {
    pub version: ProtocolVersion,
    pub message_type: ContentType,
    pub data: Vec<u8>
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum AlertLevel {
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
pub enum AlertDescription {
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

pub struct Alert {
    level: AlertLevel,
    description: AlertDescription
}

impl Alert {
    pub fn new(level: AlertLevel, description: AlertDescription) -> Self {
        Self { level, description }
    }

    pub fn report(&self) {
        println!("Alert - {}: {}", self.level, self.description)
    }
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

impl TLSMessage for Alert {
    fn get_content_type(&self) -> ContentType {
        ContentType::Alert
    }
}

pub struct SessionId(Vec<u8>);

impl BinaryReadable for SessionId {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let (bytes, buf) = read_elements::<u8, u8>(buf)?;
        Ok((SessionId(bytes), buf))
    }
}

pub struct ServerHello {
    server_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    pub cipher_suite: CipherSuiteIdentifier,
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

pub struct ServerCertificateChain {
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

pub struct ChangeCipherSpec {}

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
