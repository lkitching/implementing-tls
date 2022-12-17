use std::io::{self, Read, Write, ErrorKind};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug};
use chrono::{DateTime, Utc};
use num_enum::{TryFromPrimitive};
use std::net::{TcpStream};

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

impl FixedBinaryLength for u8 {
    fn fixed_binary_len() -> usize { 1 }
}

impl BinarySerialisable for u8 {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0] = *self;
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

impl FixedBinaryLength for CipherSuiteIdentifier {
    fn fixed_binary_len() -> usize { u16::fixed_binary_len() }
}

impl BinarySerialisable for CipherSuiteIdentifier {
    fn write_to(&self, buf: &mut [u8]) {
        let s = *self as u16;
        s.write_to(buf);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct ProtocolVersion {
    major: u8,
    minor: u8
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

struct Random {
    gmt_unix_time: u32,
    random_bytes: [u8; 28]
}

impl FixedBinaryLength for Random {
    fn fixed_binary_len() -> usize { 32 }
}

impl BinarySerialisable for Random {
    fn write_to(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(self.gmt_unix_time.to_be_bytes().as_slice());
        buf[4..].copy_from_slice(self.random_bytes.as_slice());
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

struct TLSParameters {
    client_random: Random
}

impl TLSParameters {
    fn init(&mut self) {
        todo!()
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

trait HandshakeMessage {
    fn handshake_message_type(&self) -> HandshakeType;
}

impl HandshakeMessage for ClientHello {
    fn handshake_message_type(&self) -> HandshakeType {
        HandshakeType::CLIENT_HELLO
    }
}

struct Handshake<T>(T);

impl <T: BinaryLength> BinaryLength for Handshake<T> {
    fn binary_len(&self) -> usize {
        // 1 byte for message type
        // 3 bytes for inner message length
        self.0.binary_len() + HandshakeType::fixed_binary_len() + 3
    }
}

impl <T: HandshakeMessage + BinarySerialisable> BinarySerialisable for Handshake<T> {
    fn write_to(&self, buf: &mut [u8]) {
        let msg = &self.0;

        // write message type
        let buf = write_front(&msg.handshake_message_type(), buf);

        // write inner message length
        // message length field is 3 bytes (24 bits)
        // TODO: validate message length fits? Should always be enough!
        let len_bytes = msg.binary_len().to_be_bytes();
        buf[0..3].copy_from_slice(&len_bytes[(len_bytes.len() - 3) ..]);

        // write inner message
        msg.write_to(&mut buf[3..]);
    }
}

fn send_client_hello<W: Write>(dest: &mut W, params: &TLSParameters) -> io::Result<()> {
    let hello = ClientHello {
        client_version: TLS_VERSION,
        random: Random::from_now(&params.client_random.random_bytes),
        session_id: Vec::new(),
        compression_methods: vec![CompressionMethods::None],
        cipher_suites: CipherSuites(vec![CipherSuiteIdentifier::TLS_RSA_WITH_3DES_EDE_CBC_SHA])
    };

    send_handshake_message(dest, hello)
}

fn send_handshake_message<W: Write, H: HandshakeMessage + BinarySerialisable>(dest: &mut W, handshake_message: H) -> io::Result<()> {
    let wrapped = Handshake(handshake_message);
    let buf = wrapped.write_to_vec();
    // TODO: update handshake message digests

    let msg = TLSPlaintext {
        // TODO: get from TLS parameters?
        version: TLS_VERSION,
        message: wrapped
    };

    send_message(dest, msg)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
enum AlertLevel {
    Warning = 1,
    Fatal = 2
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

struct Alert {
    level: AlertLevel,
    description: AlertDescription
}

impl FixedBinaryLength for AlertLevel {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl FixedBinaryLength for AlertDescription {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl BinarySerialisable for AlertLevel {
    fn write_to(&self, buf: &mut [u8]) {
        (*self as u8).write_to(buf);
    }
}

impl BinarySerialisable for AlertDescription {
    fn write_to(&self, buf: &mut [u8]) {
        (*self as u8).write_to(buf)
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

impl FixedBinaryLength for ContentType {
    fn fixed_binary_len() -> usize { u8::fixed_binary_len() }
}

impl BinarySerialisable for ContentType {
    fn write_to(&self, buf: &mut [u8]) {
        (*self as u8).write_to(buf);
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

impl <T> TLSMessage for Handshake<T> {
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
        // write content type
        let buf = write_front(&self.message.get_content_type(), buf);

        // get inner message
        //let tmp = self.message.write_to_vec();

        // write protocol version
        let buf = write_front(&self.version, buf);

        // write message length
        let buf = write_front(&(self.message.binary_len() as u16), buf);

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
    length: u16
}

impl TLSHeader {
    fn new(bytes: Vec<u8>) -> Self {
        assert_eq!(bytes.len(), 5);
        // TODO: parse message type and version
        let len_bytes: [u8; 2] = bytes[3..].try_into().unwrap();
        TLSHeader {
            length: u16::from_be_bytes(len_bytes)
        }
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
    UnknownMessage
}

struct ServerHello {}

enum ServerMessage {
    Hello(ServerHello)
}

fn parse_server_message(buf: Vec<u8>) -> Result<ServerMessage, TLSError> {
    todo!()
}

fn receive_tls_msg(conn: &mut TcpStream) -> Result<ServerMessage, TLSError> {
    // read TLS Record header
    let header_buf = read_exact(conn, 5).map_err(TLSError::IOError)?;
    let tls_header = TLSHeader::new(header_buf);

    // read message body
    match read_exact(conn, tls_header.length as usize) {
        Ok(message_buf) => {
           parse_server_message(message_buf)
        },
        Err(_) => {
            send_alert_message(conn, AlertDescription::IllegalParameter);
            // TODO: Add 'state' Error type and remove IOError?
            let ioe = io::Error::new(ErrorKind::UnexpectedEof, "Failed to read message body");
            return Err(TLSError::IOError(ioe));
        }
    }
}

// TODO: can change TcpStream to Read?
fn tls_connect(conn: &mut TcpStream, tls_params: &mut TLSParameters) -> io::Result<()> {
    tls_params.init();

    // step 1
    // send the TLS handshake 'client hello' message
    send_client_hello(conn, &tls_params)?;

    // step 2
    // receive the server hello response

    todo!()
}