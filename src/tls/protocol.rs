use std::convert::{TryFrom, TryInto};
use std::io::{self, Read, Write, ErrorKind};
use std::net::{TcpStream};

use super::serde::*;
use super::messages::*;
use super::secure::{self, ProtectionParameters};

use crate::hash::{Digest, HashAlgorithm};
use crate::md5::{MD5HashAlgorithm};
use crate::sha::{SHA1HashAlgorithm};
use crate::x509::{PublicKeyInfo};
use crate::dh::{DHKey};
use crate::prf::{prf, prf_bytes};
use crate::tls::secure::get_cipher_suite;
use crate::hmac;

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

    fn free_protection_parameters(&mut self) {
        self.active_send_parameters.free();
        self.pending_send_parameters.free();
        self.active_recv_parameters.free();
        self.pending_recv_parameters.free();
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

fn send_client_hello<W: Write>(dest: &mut W, params: &mut TLSParameters) -> io::Result<()> {
    let hello = ClientHello {
        client_version: TLS_VERSION,
        random: Random::from_now(&params.client_random),
        session_id: Vec::new(),
        compression_methods: vec![CompressionMethods::None],
        cipher_suites: CipherSuites(vec![CipherSuiteIdentifier::TLS_RSA_WITH_3DES_EDE_CBC_SHA])
    };

    send_handshake_message(dest, &hello, params)
}

#[derive(Clone)]
enum KeyExchange {
    RSA(RSAKeyExchange),
    DH(DHKeyExchange)
}

impl KeyExchange {
    fn premaster_secret(&self) -> &MasterSecret {
        match self {
            Self::RSA(rsa_key_exchange) => { rsa_key_exchange.premaster_secret() },
            Self::DH(dh_key_exchange) => { dh_key_exchange.premaster_secret() }
        }
    }
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

impl ClientHandshakeMessage for KeyExchange {
    fn get_client_handshake_type(&self) -> HandshakeType {
        HandshakeType::CLIENT_KEY_EXCHANGE
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
        },
        KeyExchangeMethod::None => {
            // TODO: don't call if no key exchange method?
            return Ok(());
        }
        KeyExchangeMethod::Unsupported => {
            Err(TLSError::ProtocolError("Unsupported key exchange method".to_owned()))
        }
    }?;

    send_handshake_message(dest, &key_exchange_message, parameters).map_err(TLSError::IOError)?;

    // calculate the master secret from the premaster secret
    // the server side will perform the same calculation
    compute_master_secret(key_exchange_message.premaster_secret().as_slice(), parameters);

    // TODO: purge the premaster secret from memory
    calculate_keys(parameters);

    Ok(())
}

fn send_handshake_message<W: Write, H: ClientHandshakeMessage + BinarySerialisable>(dest: &mut W, message: &H, parameters: &mut TLSParameters) -> io::Result<()> {
    // serialise handshake message and use it to update the handshake digests
    let handshake_message = HandshakeMessage { message };
    let message_buf = handshake_message.write_to_vec();
    parameters.update_digests(message_buf.as_slice());

    let msg = TLSMessageBuffer {
        // TODO: get from TLS parameters?
        version: TLS_VERSION,
        message_type: handshake_message.get_content_type(),
        data: message_buf
    };

    send_message(dest, &msg)
}

// TODO: Change to (version, type, buf)?
struct TLSPlaintext<T> {
    version: ProtocolVersion,
    message: T,
}

impl <T: BinaryLength> BinaryLength for TLSPlaintext<T> {
    fn binary_len(&self) -> usize {
        TLSHeader::fixed_binary_len() + self.message.binary_len()
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

fn send_message<W: Write, T: BinarySerialisable>(dest: &mut W, msg: &T) -> io::Result<()> {
    let buf = msg.write_to_vec();

    // TODO: check entire message was written
    let result = dest.write(buf.as_slice())?;

    Ok(())
}

fn read_exact<R: Read>(source: &mut R, bytes: usize) -> io::Result<Vec<u8>> {
    let mut dest = vec![0; bytes];
    source.read_exact(dest.as_mut_slice())?;
    Ok(dest)
}

fn send_alert_message<W: Write>(dest: &mut W, code: AlertDescription) -> io::Result<()> {
    let alert = Alert::new(AlertLevel::Fatal, code);
    let message = TLSPlaintext {
        version: TLS_VERSION,
        message: alert
    };
    send_message(dest, &message)
}

enum TLSError {
    IOError(io::Error),
    ParseError(BinaryReadError),
    UnknownMessage,
    ProtocolError(String),
    MalformedMessage(String)
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
    send_message(conn, &msg).map_err(TLSError::IOError)?;

    parameters.pending_send_parameters.reset_seq_num();
    parameters.make_active();

    Ok(())
}

fn send_finished<W: Write>(conn: &mut W, parameters: &mut TLSParameters) -> Result<(), TLSError> {
    let verify_data = compute_verify_data("client finished".as_bytes(), parameters);
    let message = Finished { verify_data };
    send_handshake_message(conn, &message, parameters)
        .map_err(TLSError::IOError)
}

enum ServerMessage {
    Alert(Alert),
    Handshakes(Vec<ServerHandshakeMessage>),
    ChangeCipherSpec,
    ApplicationData(Vec<u8>)
}

pub struct UserDataMACMessage<'a> {
    header: TLSHeader,
    data: &'a [u8],
    sequence_number: u64
}

impl <'a> UserDataMACMessage<'a> {
    pub fn new(data: &'a [u8], sequence_number: u64) -> Self {
        Self {
            header: TLSHeader {
                message_type: ContentType::ApplicationData,
                version: TLS_VERSION,
                length: data.len() as u16
            },
            data,
            sequence_number
        }
    }

    pub fn calculate_mac(&self, parameters: &ProtectionParameters) -> Vec<u8> {
        let buf = self.write_to_vec();
        parameters.hmac(buf.as_slice()).unwrap()
    }
}

impl <'a> BinaryLength for UserDataMACMessage<'a> {
    fn binary_len(&self) -> usize {
        // sequence number + TLSHeader + data
        u64::fixed_binary_len() + TLSHeader::fixed_binary_len() + self.data.len()
    }
}

impl <'a> BinarySerialisable for UserDataMACMessage<'a> {
    fn write_to(&self, buf: &mut [u8]) {
        // write sequence number
        let buf = write_front(&self.sequence_number, buf);

        // write TLS header
        let buf = write_front(&self.header, buf);

        // write data
        write_slice(self.data, buf);
    }
}

fn tls_decrypt(raw_msg: Vec<u8>, recv_parameters: &mut ProtectionParameters) -> Result<Vec<u8>, TLSError> {
    let active_suite = get_cipher_suite(recv_parameters.suite);

    let decrypted = if active_suite.has_encryption() {
        let mut plaintext = vec![0u8; raw_msg.len()];
        active_suite.bulk_decrypt(raw_msg.as_slice(), recv_parameters.iv(), recv_parameters.key(), plaintext.as_mut_slice());

        // remove padding
        // TODO: move to decryptor?
        if active_suite.requires_padding() {
            let padding_len = plaintext.last().ok_or(TLSError::MalformedMessage("Empty plaintext when padding required by active cipher suite".to_owned()))?;
            if (*padding_len as usize) > plaintext.len() {
                return Err(TLSError::MalformedMessage("Invalid padding length".to_owned()));
            } else {
                let plaintext_length = plaintext.len() - (*padding_len as usize);
                plaintext.truncate(plaintext_length);
                plaintext
            }
        } else {
            plaintext
        }
    } else {
        raw_msg
    };

    // verify the MAC if the cipher suite defines one
    if active_suite.has_digest() {
        let data_len = if active_suite.hash_size > decrypted.len() {
            return Err(TLSError::MalformedMessage("Invalid MAC".to_owned()));
        } else {
            (decrypted.len() - active_suite.hash_size) as usize
        };

        let (data, sent_mac) = decrypted.split_at(data_len);
        let mac_msg = UserDataMACMessage::new(data, recv_parameters.seq_num());
        let calculated_mac = mac_msg.calculate_mac(&recv_parameters);

        if sent_mac != calculated_mac {
            return Err(TLSError::MalformedMessage("Invalid MAC".to_owned()))
        }

        Ok(data.to_vec())
    } else {
        Ok(decrypted)
    }
}

fn parse_server_message(header: &TLSHeader, buf: Vec<u8>, parameters: &mut TLSParameters) -> Result<ServerMessage, TLSError> {
    // decrypt incoming message if required
    let buf = tls_decrypt(buf, &mut parameters.active_send_parameters)?;

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
        },
        ContentType::ApplicationData => {
            Ok(ServerMessage::ApplicationData(buf))
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
            },
            ServerMessage::ApplicationData(data) => {
                return Err(TLSError::ProtocolError("Unexpected 'application data' message while waiting for server handshake".to_owned()))
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

// TODO: merge with send_message
// Create MessageSink with/without protection parameters?
fn send_encrypted_message<W: Write>(dest: &mut W, application_data: &[u8], options: SendOptions, parameters: &mut ProtectionParameters) -> Result<(), TLSError> {
    let active_suite = get_cipher_suite(parameters.suite);
    let mac = if active_suite.has_digest() {

        // create message for outgoing MAC calculation
        let header = TLSHeader {
            message_type: ContentType::ApplicationData,
            version: TLS_VERSION,
            length: application_data.len() as u16
        };

        // TODO: make method on ProtectionParameters?
        let msg = UserDataMACMessage {
            data: application_data,
            header,
            sequence_number: parameters.seq_num()
        };
        Some(msg.calculate_mac(&parameters))
    } else {
        None
    };

    // calculate the amount of padding required (if any)
    let padding_len = if active_suite.block_size > 0 {
        let data_len = application_data.len() + active_suite.hash_size;
        active_suite.block_size - (data_len % active_suite.block_size)
    } else {
        0
    };

    let send_buffer_len = application_data.len() + active_suite.hash_size + padding_len;

    // TODO: create message type?
    let message_buf = {
        let message_buf_len = TLSHeader::fixed_binary_len() + send_buffer_len;
        let mut message_buf = vec![0u8; message_buf_len];

        let header = TLSHeader {
            message_type: ContentType::ApplicationData,
            version: TLS_VERSION,
            length: send_buffer_len as u16
        };

        // write header
        let mut msg_buf = message_buf.as_mut_slice();
        msg_buf = write_front(&header, msg_buf);

        // write content
        msg_buf = write_slice(application_data, msg_buf);

        // write padding
        for i in 0..padding_len {
            msg_buf[i] = (padding_len - 1) as u8;
        }

        msg_buf = &mut msg_buf[0..padding_len];

        // write MAC (if any)
        if let Some(mac_bytes) = mac {
            write_slice(mac_bytes.as_slice(), msg_buf);
        }

        message_buf
    };

    let send_buf = if active_suite.has_encryption() {
        let mut encrypted_buf = vec![0; message_buf.len()];

        // header is not encrypted
        let (header, data) = message_buf.split_at(TLSHeader::fixed_binary_len());
        let (enc_header, enc_data) = encrypted_buf.split_at_mut(TLSHeader::fixed_binary_len());

        enc_header.copy_from_slice(header);

        // encrypt data into rest of buffer
        // TODO: check data length is multiple of block size?!
        active_suite.bulk_encrypt(data, parameters.iv(), parameters.key(), enc_data);

        encrypted_buf
    } else {
        message_buf
    };

    dest.write_all(send_buf.as_slice()).map_err(TLSError::IOError)?;

    parameters.next_seq_num();

    Ok(())
}

enum SendOptions {}

fn tls_send<W: Write>(dest: &mut W, application_data: &[u8], options: SendOptions, parameters: &mut TLSParameters) -> Result<(), TLSError> {
    send_encrypted_message(dest, application_data, options, &mut parameters.active_send_parameters)
}

fn tls_shutdown<W: Write>(dest: &mut W, parameters: &mut TLSParameters) -> Result<(), TLSError> {
    send_alert_message(dest, AlertDescription::CloseNotify).map_err(TLSError::IOError)
}