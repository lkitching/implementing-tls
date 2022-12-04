use std::io::{self, Write};
use chrono::{DateTime, Utc};
use num_enum::{TryFromPrimitive};

trait FixedBinarySize {
    fn binary_size() -> usize;
}

trait BinarySerialisable {
    fn write_to(&self, buf: &mut Vec<u8>);
    fn write_to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.write_to(&mut v);
        v
    }
}

impl FixedBinarySize for u8 {
    fn binary_size() -> usize { 1 }
}

impl BinarySerialisable for u8 {
    fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
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

impl FixedBinarySize for CipherSuiteIdentifier {
    fn binary_size() -> usize { 2 }
}

impl BinarySerialisable for CipherSuiteIdentifier {
    fn write_to(&self, buf: &mut Vec<u8>) {
        let s = *self as u16;
        buf.extend_from_slice(s.to_be_bytes().as_slice())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct ProtocolVersion {
    major: u8,
    minor: u8
}

impl BinarySerialisable for ProtocolVersion {
    fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.major);
        buf.push(self.minor);
    }
}

const TLS_VERSION: ProtocolVersion = ProtocolVersion { major: 3, minor: 1 };

struct Random {
    gmt_unix_time: u32,
    random_bytes: [u8; 28]
}

impl BinarySerialisable for Random {
    fn write_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.gmt_unix_time.to_be_bytes().as_slice());
        buf.extend_from_slice(self.random_bytes.as_slice());
    }
}

impl Random {
    fn from_now(bytes: &[u8; 28]) -> Random {
        let ts = Utc::now().timestamp() as u32;
        Random { gmt_unix_time: ts, random_bytes: bytes.clone() }
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

impl BinarySerialisable for ClientHello {
    fn write_to(&self, writer: &mut Vec<u8>) {
        self.client_version.write_to(writer);
        self.random.write_to(writer);
        self.session_id.as_slice().write_to(writer);
        self.cipher_suites.write_to(writer);
        self.compression_methods.as_slice().write_to(writer);
    }
}

fn write_elements<T: BinarySerialisable>(buf: &mut Vec<u8>, elems: &[T]) {
    for e in elems.iter() {
        e.write_to(buf);
    }
}

impl <T: FixedBinarySize + BinarySerialisable> BinarySerialisable for &[T] {
    fn write_to(&self, buf: &mut Vec<u8>) {
        let element_len = self.len() * T::binary_size();

        buf.push(element_len as u8);
        write_elements(buf, self);
    }
}

impl BinarySerialisable for CipherSuites {
    fn write_to(&self, buf: &mut Vec<u8>) {
        let elems = self.0.as_slice();
        let element_len = elems.len() * CipherSuiteIdentifier::binary_size();

        // write length
        // WARNING: cipher suites length is 2 bytes!
        buf.extend_from_slice((element_len as u16).to_be_bytes().as_slice());

        // write elements
        write_elements(buf, elems);
    }
}

impl FixedBinarySize for CompressionMethods {
    fn binary_size() -> usize { 1 }
}

impl BinarySerialisable for CompressionMethods {
    fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(*self as u8);
    }
}

struct TLSParameters {
    client_random: Random
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

impl BinarySerialisable for HandshakeType {
    fn write_to(&self, buf: &mut Vec<u8>) {
        (*self as u8).write_to(buf);
    }
}

trait HandshakeMessage {
    fn handshake_message_type(&self) -> HandshakeType;
}

impl HandshakeMessage for ClientHello {
    fn handshake_message_type(&self) -> HandshakeType {
        HandshakeType::CLIENT_HELLO
    }
}

struct Handshake<T>(T);

impl <T: HandshakeMessage + BinarySerialisable> BinarySerialisable for Handshake<T> {
    fn write_to(&self, buf: &mut Vec<u8>) {
        let msg = &self.0;
        let tmp = msg.write_to_vec();

        // write message type
        msg.handshake_message_type().write_to(buf);

        // write inner message length
        // message length field is 3 bytes (24 bits)
        // TODO: validate message length fits? Should always be enough!
        let len_bytes = tmp.len().to_be_bytes();
        buf.extend_from_slice(&len_bytes[(len_bytes.len() - 3) ..]);

        // write inner message
        buf.extend_from_slice(tmp.as_slice());
    }
}

fn send_client_hello<W: Write>(dest: &mut W, params: &TLSParameters) -> Result<(), String> {
    let hello = ClientHello {
        client_version: TLS_VERSION,
        random: Random::from_now(&params.client_random.random_bytes),
        session_id: Vec::new(),
        compression_methods: vec![CompressionMethods::None],
        cipher_suites: CipherSuites(vec![CipherSuiteIdentifier::TLS_RSA_WITH_3DES_EDE_CBC_SHA])
    };

    Ok(())
}

fn send_handshake_message<W: Write, H: HandshakeMessage + BinarySerialisable>(dest: &mut W, msg: H) -> Result<(), String> {
    let buf = Handshake(msg).write_to_vec();
    // TODO: update handshake message digests

    send_message(dest, buf.as_slice())
}

fn send_message<W: Write>(dest: &mut W, buf: &[u8]) -> Result<(), String> {
    todo!()
}
