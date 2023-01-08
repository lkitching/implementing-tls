use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write, ErrorKind};
use std::net::{TcpStream};

use super::serde::*;
use super::messages::*;
use super::secure::{self, ProtectionParameters};

use crate::hash::{Digest};
use crate::md5::{MD5HashAlgorithm};
use crate::sha::{SHA1HashAlgorithm};
use crate::x509::{PublicKeyInfo};
use crate::dh::{DHKey};
use crate::prf::{prf, prf_bytes};

const TLS_VERSION: ProtocolVersion = ProtocolVersion { major: 3, minor: 1 };

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

    md5_handshake_digest: Digest<MD5HashAlgorithm>,
    sha1_handshake_digest: Digest<SHA1HashAlgorithm>,

    server_hello_done: bool,
    server_finished: bool
}

impl TLSParameters {
    fn init(&mut self) {
        self.md5_handshake_digest = Digest::new(MD5HashAlgorithm {});
        self.sha1_handshake_digest = Digest::new(SHA1HashAlgorithm {});
        todo!()
    }

    fn make_active(&mut self) {
        self.active_send_parameters = self.pending_send_parameters.clone();
        self.pending_send_parameters.init();
    }

    fn update_digests(&mut self, data: &[u8]) {
        self.md5_handshake_digest.update(data);
        self.sha1_handshake_digest.update(data);
    }

    fn compute_handshake_hash(&self) -> Vec<u8> {
        [self.md5_handshake_digest.clone().finalise(), self.sha1_handshake_digest.clone().finalise()].concat()
    }
}

fn compute_verify_data(finished_label: &[u8], parameters: &TLSParameters) -> VerifyData {
    let hashes = parameters.compute_handshake_hash();

    let mut verify_data = [0u8; VERIFY_DATA_LENGTH];
    prf(parameters.master_secret.as_slice(), finished_label, hashes.as_slice(), verify_data.as_mut_slice());

    verify_data
}

enum ClientHandshakeMessage {
    Hello(ClientHello),
    KeyExchange(KeyExchange),
    Finished(Finished)
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
            },
            Self::Finished(finished) => {
                let length = U24::try_from(finished.binary_len()).expect("Message too large");
                HandshakeHeader { handshake_type: HandshakeType::FINISHED, length }
            }
        }
    }
}

impl BinaryLength for ClientHandshakeMessage {
    fn binary_len(&self) -> usize {
        let message_len = match self {
            Self::Hello(hello) => hello.binary_len(),
            Self::KeyExchange(rsa_key_exchange) => rsa_key_exchange.binary_len(),
            Self::Finished(finished) => finished.binary_len()
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
                client_hello.write_to(buf)
            },
            Self::KeyExchange(rsa_key_exchange) => {
                rsa_key_exchange.write_to(buf)
            },
            Self::Finished(finished) => {
                finished.write_to(buf);
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
            Self::RSA(rsa_key_exchange) => { rsa_key_exchange.premaster_secret() },
            Self::DH(dh_key_exchange) => { dh_key_exchange.premaster_secret() }
        }
    }
}

fn calculate_keys(parameters: &mut TLSParameters) {
    let suite = secure::get_cipher_suite(parameters.pending_send_parameters.suite);
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

impl TLSMessage for ClientHandshakeMessage {
    fn get_content_type(&self) -> ContentType {
        ContentType::Handshake
    }
}

// TODO: Change to (version, type, buf)?
struct TLSPlaintext<T> {
    version: ProtocolVersion,
    message: T,
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

fn send_alert_message<W: Write>(dest: &mut W, code: AlertDescription) -> io::Result<()> {
    let alert = Alert::new(AlertLevel::Fatal, code);
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

enum ServerHandshakeMessage {
    Hello(ServerHello),
    CertificateChain(ServerCertificateChain),
    Done,
    Finished(Finished)
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
            },
            HandshakeType::FINISHED => {
                Finished::read_all_from(message_buf).map(ServerHandshakeMessage::Finished)
            }
            _ => Err(BinaryReadError::UnknownType)
        }?;

        Ok((handshake_message, remaining))
    }
}

fn send_change_cipher_spec<W: Write>(conn: &mut W, parameters: &mut TLSParameters) -> Result<(), TLSError> {
    let msg = TLSPlaintext { version: TLS_VERSION.clone(), message: ChangeCipherSpec { } };
    send_message(conn, msg).map_err(TLSError::IOError)?;

    parameters.pending_send_parameters.seq_num = 0;
    parameters.make_active();

    Ok(())
}

fn send_finished<W: Write>(conn: &mut W, parameters: &mut TLSParameters) -> Result<(), TLSError> {
    let verify_data = compute_verify_data("client finished".as_bytes(), parameters);
    let message = Finished { verify_data };
    send_handshake_message(conn, ClientHandshakeMessage::Finished(message), parameters)
        .map_err(TLSError::IOError)
}

enum ServerMessage {
    Alert(Alert),
    Handshakes(Vec<ServerHandshakeMessage>),
    ChangeCipherSpec
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
    let seed = [parameters.client_random.bytes(), parameters.server_random.bytes()].concat();

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
                        },
                        ServerHandshakeMessage::Finished(_finished) => {
                            return Err(TLSError::ProtocolError("Unexpected server finished message before change cipher spec".to_owned()))
                        }
                    }
                }
            },
            ServerMessage::ChangeCipherSpec => {
                // TODO: can handle?
                return Err(TLSError::ProtocolError("Unexpected 'change cipher spec' message while waiting for server handshake".to_owned()))
            }
            ServerMessage::Alert(alert) => {
                alert.report()
            }
        };
    }

    // step 3
    // send client key exchange
    send_client_key_exchange(conn, tls_params)?;

    // step 4
    // send 'change cipher spec' message
    send_change_cipher_spec(conn, tls_params)?;

    send_finished(conn, tls_params)?;

    // wait for server finished message
    tls_params.server_finished = false;
    while !tls_params.server_finished {
        match receive_tls_msg(conn, tls_params)? {
            ServerMessage::Handshakes(handshakes) => {
                for handshake in handshakes {
                    match handshake {
                        ServerHandshakeMessage::Finished(finished) => {
                            tls_params.server_finished = true;
                            let expected_server_verify = compute_verify_data("server finished".as_bytes(), tls_params);

                            if expected_server_verify != finished.verify_data {
                                return Err(TLSError::ProtocolError("Server handshake verify data does not match expected value".to_owned()));
                            }
                        },
                        _ => {
                            // TODO: can handle?
                            return Err(TLSError::ProtocolError("Unexpected handshake message while waiting for server finished message".to_owned()));
                        }
                    }
                }
            },
            _ => {
                // TODO: can handle?
                return Err(TLSError::ProtocolError("Unexpected message while waiting for server finished message".to_owned()))
            }
        }
    }

    Ok(())
}
