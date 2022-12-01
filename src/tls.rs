use std::io::{self, Write};
use chrono::{DateTime, Utc};
use num_enum::{TryFromPrimitive};

trait FixedBinarySize {
    fn binary_size() -> usize;
}

trait BinarySerialisable {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize>;
    fn write_to_vec(&self) -> io::Result<Vec<u8>> {
        let mut v = Vec::new();
        let bytes_written = self.write_to(&mut v);
        Ok(v)
    }
}

impl FixedBinarySize for u8 {
    fn binary_size() -> usize { 1 }
}

impl BinarySerialisable for u8 {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write([*self].as_slice())
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
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let s = *self as u16;
        writer.write(s.to_be_bytes().as_slice())
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct ProtocolVersion {
    major: u8,
    minor: u8
}

impl BinarySerialisable for ProtocolVersion {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let bytes = [self.major, self.minor];
        writer.write(&bytes[..])
    }
}

const TLS_VERSION: ProtocolVersion = ProtocolVersion { major: 3, minor: 1 };

struct Random {
    gmt_unix_time: u32,
    random_bytes: [u8; 28]
}

impl BinarySerialisable for Random {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let mut buf = [0u8; 32];
        let mut time_bytes = self.gmt_unix_time.to_be_bytes();
        &mut buf[0..4].copy_from_slice(time_bytes.as_slice());
        &mut buf[4..].copy_from_slice(self.random_bytes.as_slice());
        writer.write(buf.as_slice())
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
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let v = self.client_version.write_to(writer)?;
        let r = self.random.write_to(writer)?;
        let s = self.session_id.as_slice().write_to(writer)?;
        let cs = self.cipher_suites.write_to(writer)?;
        let cms = self.compression_methods.as_slice().write_to(writer)?;

        Ok(v + r + s + cs + cms)
    }
}

fn write_elements<T: BinarySerialisable>(buf: &mut Vec<u8>, elems: &[T]) -> io::Result<usize> {
    let mut bytes_written = 0;

    for e in elems.iter() {
        bytes_written += e.write_to(buf)?;
    }

    Ok(bytes_written)
}

impl <T: FixedBinarySize + BinarySerialisable> BinarySerialisable for &[T] {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let element_len = self.len() * T::binary_size();

        let mut buf = Vec::with_capacity(1 + element_len);
        buf.push(element_len as u8);
        let _ = write_elements(&mut buf, self);

        writer.write(buf.as_slice())
    }
}

impl BinarySerialisable for CipherSuites {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        let elems = self.0.as_slice();
        let element_len = elems.len() * CipherSuiteIdentifier::binary_size();

        // WARNING: cipher suites length is 2 bytes!
        let mut buf = Vec::with_capacity(2 + element_len);

        // write length
        buf.extend_from_slice((element_len as u16).to_be_bytes().as_slice());

        // write elements
        write_elements(&mut buf, elems);

        writer.write(buf.as_slice())
    }
}

impl FixedBinarySize for CompressionMethods {
    fn binary_size() -> usize { 1 }
}

impl BinarySerialisable for CompressionMethods {
    fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<usize> {
        writer.write([*self as u8].as_slice())
    }
}

struct TLSParameters {
    client_random: Random
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