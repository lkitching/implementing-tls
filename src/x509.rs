use std::io;
use std::convert::{TryFrom};
use std::collections::{HashMap};
use std::fmt::{self, Display, Formatter};
use num_enum::{TryFromPrimitive};
use chrono::{NaiveDateTime, DateTime, Offset, FixedOffset, Utc};

use crate::asn1::{self, ASN1Item, TagType, TagClass, ASN1Error};
use crate::huge::{Huge};
use crate::dsa::{self, DSASignature, DSAParams};
use crate::{rsa, hex, hash, md5, sha};
use crate::rsa::RSAKey;
use crate::x509::Hasher::SHA1;

pub struct X509Certificate {
    version: Version,
    serial_number: Huge, //TODO: should just be Vec<u8>? Create type?
    issuer: EntityName,
    validity: Validity,
    subject: EntityName,
    public_key_info: PublicKeyInfo,
    signature_algorithm_identifier: SigningAlgorithmIdentifier,
    known_extensions: Vec<KnownExtension>
}

impl Display for Version {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:#02x})", *self as u8, *self as u8)
    }
}

impl X509Certificate {
    // indicates whether this certificate can be used to sign other certificates
    pub fn certificate_authority(&self) -> bool {
        for ext in &self.known_extensions {
            if let KnownExtension::KeyUsage { can_sign } = ext {
                return *can_sign;
            }
        }
        false
    }
}

// TODO: move this
enum Hasher {
    MD5,
    SHA1,
    SHA256
}

impl Display for Hasher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Hasher::MD5 => write!(f, "MD5"),
            Hasher::SHA1 => write!(f, "SHA-1"),
            Hasher::SHA256 => write!(f, "SHA-256")
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum SigningAlgorithmIdentifier {
    MD5WithRSA,
    SHA1WithRSA,
    SHA256WithRSA,
    SHA1WithDSA
}

enum Signature {
    RSA { hasher: Hasher, signature: Huge },
    DSA { hasher: Hasher, signature: DSASignature }
}

pub struct SignedX509Certificate {
    certificate: X509Certificate,
    signing_algorithm_id: SigningAlgorithmIdentifier,
    signature: Signature,
    hash: Vec<u8>
}

#[derive(Debug, PartialEq, Eq)]
pub enum X509Error {
    ASN1(asn1::ASN1Error),
    TypeError { expected_type: TagType, actual_type: TagType },
    ChildCountError { expected_children: usize, actual_children: usize },
    UnknownSigningAlgorithmOID(Vec<u8>),
    UnknownPublicKeyOID(Vec<u8>),
    InvalidVersion,
    InvalidNameComponentType(TagType),
    InvalidString(Vec<u8>),
    InvalidDateType(TagType),
    InvalidDateFormat(String),
    UnexpectedPadding(u8)
}

fn parse_huge(node: &ASN1Item) -> Huge {
    // TODO: validate type?
    Huge::from_bytes(node.data())
}

const OID_MD5_WTIH_RSA: [u8; 9] = [ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04 ];
const OID_SHA1_WITH_RSA: [u8; 9] = [ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 ];
const OID_SHA256_WITH_RSA: [u8; 9] = [ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0b ];
const OID_SHA1_WITH_DSA: [u8; 7] = [ 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03 ];

fn validate_node_type(node: &ASN1Item, expected_type: TagType) -> Result<(), X509Error> {
    if node.tag().tag_type != expected_type {
        Err(X509Error::TypeError { expected_type, actual_type: node.tag().tag_type })
    } else {
        Ok(())
    }
}

fn validate_node_children(node: &ASN1Item, expected_children: usize) -> Result<(), X509Error> {
    if node.children().len() < expected_children {
        Err(X509Error::ChildCountError { expected_children, actual_children: node.children().len() })
    } else {
        Ok(())
    }
}

fn validate_node(node: &ASN1Item, expected_type: TagType, expected_children: usize) -> Result<(), X509Error> {
    let _ = validate_node_type(node, expected_type)?;
    validate_node_children(node, expected_children)
}

fn parse_signing_algorithm_identifier(alg: &ASN1Item) -> Result<SigningAlgorithmIdentifier, X509Error> {
    // node should have a single OID child
    // TODO: validate root node type?
    let _ = validate_node_children(alg, 1);

    let oid_node = &alg.children()[0];
    let _ = validate_node_type(oid_node, TagType::ObjectIdentifier);

    if OID_MD5_WTIH_RSA == oid_node.data() {
        Ok(SigningAlgorithmIdentifier::MD5WithRSA)
    } else if OID_SHA1_WITH_RSA == oid_node.data() {
        Ok(SigningAlgorithmIdentifier::SHA1WithRSA)
    } else if OID_SHA256_WITH_RSA == oid_node.data() {
        Ok(SigningAlgorithmIdentifier::SHA256WithRSA)
    } else if OID_SHA1_WITH_DSA == oid_node.data() {
        Ok(SigningAlgorithmIdentifier::SHA1WithDSA)
    } else {
        Err(X509Error::UnknownSigningAlgorithmOID(oid_node.data().to_vec()))
    }
}

fn parse_dsa_signature(alg: &ASN1Item) -> Result<DSASignature, X509Error> {
    // algorithm node should contain two DSA parameter nodes
    let signature_node = asn1::parse(&alg.data()[1..]).map_err(X509Error::ASN1)?;

    // TODO: validate type?
    let _ = validate_node_children(&signature_node, 2)?;

    let r = parse_huge(&signature_node.children()[0]);
    let s = parse_huge(&signature_node.children()[1]);

    Ok(DSASignature { r, s })
}

fn parse_signature(alg: &ASN1Item, algorithm_id: SigningAlgorithmIdentifier) -> Result<Signature, X509Error> {
    match algorithm_id {
        SigningAlgorithmIdentifier::MD5WithRSA => {
            let signature = parse_huge(alg);
            Ok(Signature::RSA { hasher: Hasher::MD5, signature })
        },
        SigningAlgorithmIdentifier::SHA1WithRSA => {
            let signature = parse_huge(alg);
            Ok(Signature::RSA { hasher: Hasher::SHA1, signature })
        },
        SigningAlgorithmIdentifier::SHA256WithRSA => {
            let signature = parse_huge(alg);
            Ok(Signature::RSA { hasher: Hasher::SHA256, signature })
        }
        SigningAlgorithmIdentifier::SHA1WithDSA => {
            let signature = parse_dsa_signature(alg)?;
            Ok(Signature::DSA { hasher: SHA1, signature })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
enum Version {
    One = 0,
    Two = 1,
    Three = 2
}

fn parse_version_number(node: &ASN1Item) -> Result<Version, X509Error> {
    let _ = validate_node_type(node, TagType::Integer);

    // value should be a single byte in the range [0, 3)
    if node.data().len() == 1 {
        Version::try_from(node.data()[0]).map_err(|_| X509Error::InvalidVersion)
    } else {
        Err(X509Error::InvalidVersion)
    }
}

fn parse_serial_number(node: &ASN1Item) -> Result<Huge, X509Error> {
    Ok(parse_huge(node))
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
enum KnownNameElement {
    CommonName,
    CountryName,
    LocalityName,
    StateOrProvinceName,
    OrganizationName,
    OrganizationalNameUnit
}

impl TryFrom<&[u8]> for KnownNameElement {
    type Error = ();
    fn try_from(value: &[u8]) -> Result<KnownNameElement, ()> {
        if OID_COMMON_NAME == value {
            Ok(KnownNameElement::CommonName)
        } else if OID_COUNTRY_NAME == value {
            Ok(KnownNameElement::CountryName)
        } else if OID_LOCALITY_NAME == value {
            Ok(KnownNameElement::LocalityName)
        } else if OID_STATE_OR_PROVINCE_NAME == value {
            Ok(KnownNameElement::StateOrProvinceName)
        } else if OID_ORGANIZATION_NAME == value {
            Ok(KnownNameElement::OrganizationName)
        } else if OID_ORGANIZATIONAL_NAME_UNIT == value {
            Ok(KnownNameElement::OrganizationalNameUnit)
        } else {
            Err(())
        }
    }
}

const OID_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];
const OID_COUNTRY_NAME: [u8; 3] = [0x55, 0x04, 0x06];
const OID_LOCALITY_NAME: [u8; 3] = [0x55, 0x04, 0x07];
const OID_STATE_OR_PROVINCE_NAME: [u8; 3] = [0x55, 0x04, 0x08];
const OID_ORGANIZATION_NAME: [u8; 3] = [0x55, 0x04, 0x0A];
const OID_ORGANIZATIONAL_NAME_UNIT: [u8; 3] = [0x55, 0x04, 0x0B];

struct EntityName {
    components: HashMap<KnownNameElement, String>
}

impl EntityName {
    fn get(&self, element: KnownNameElement) -> Option<&str> {
        self.components.get(&element).map(|s| s.as_str())
    }
}

impl Display for EntityName {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "C={}/ST={}/L={}/O={}/OU={}/CN={}",
                 self.get(KnownNameElement::CountryName).unwrap_or("?"),
                 self.get(KnownNameElement::StateOrProvinceName).unwrap_or("?"),
                 self.get(KnownNameElement::LocalityName).unwrap_or("?"),
                 self.get(KnownNameElement::OrganizationName).unwrap_or("?"),
                 self.get(KnownNameElement::OrganizationalNameUnit).unwrap_or("?"),
                 self.get(KnownNameElement::CommonName).unwrap_or("?")
        )
    }
}

fn parse_name(node: &ASN1Item) -> Result<EntityName, X509Error> {
    let _ = validate_node(node, TagType::Sequence, 1)?;

    let mut known_elements = HashMap::new();

    for child in node.children() {
        let _ = validate_node(child, TagType::Set, 1)?;

        let sequence_node = &child.children()[0];
        let _ = validate_node(sequence_node, TagType::Sequence, 2);

        let type_node = &sequence_node.children()[0];
        let value_node = &sequence_node.children()[1];

        let _ = validate_node_type(type_node, TagType::ObjectIdentifier);
        let known_element = if let Ok(ne) = KnownNameElement::try_from(type_node.data()) {
            ne
        } else {
            eprintln!("Skipping unrecognised or unsupported name token OID of {}", hex::format_hex(type_node.data()));
            continue;
        };

        let value = match value_node.tag().tag_type {
            TagType::PrintableString |
            TagType::TeletexString |
            TagType::IA5String |
            TagType::UTF8String => {
                String::from_utf8(value_node.data().to_vec()).map_err(|_| X509Error::InvalidString(value_node.data().to_vec()))?
            },
            invalid => {
                return Err(X509Error::InvalidNameComponentType(invalid))
            }
        };

        known_elements.insert(known_element, value);
    }

    Ok(EntityName { components: known_elements })
}

struct Validity {
    not_before: DateTime<FixedOffset>,
    not_after: DateTime<FixedOffset>
}

fn parse_time(node: &ASN1Item) -> Result<DateTime<FixedOffset>, X509Error> {
    let s = match node.tag().tag_type {
        TagType::UTCTime | TagType::GeneralisedTime => {
            String::from_utf8(node.data().to_vec()).map_err(|_| X509Error::InvalidString(node.data().to_vec()))?
        },
        invalid => {
            return Err(X509Error::InvalidDateType(invalid));
        }
    };

    // TODO: check this
    //DateTime::parse_from_str(s.as_str(), "%y%m%d%H%m%M%S%Z").map_err(|_|X509Error::InvalidDateFormat(s))
    NaiveDateTime::parse_from_str(s.as_str(), "%y%m%d%H%M%SZ")
        .map(|ndt| DateTime::from_utc(ndt, Utc.fix()))
        .map_err(|_|X509Error::InvalidDateFormat(s))
}

fn parse_validity(node: &ASN1Item) -> Result<Validity, X509Error> {
    let _ = validate_node(node, TagType::Sequence, 2)?;

    let not_before = parse_time(&node.children()[0])?;
    let not_after = parse_time(&node.children()[1])?;

    Ok(Validity { not_before, not_after })
}

struct DSAKeyInfo {
    public_key: Huge,
    params: DSAParams
}
enum PublicKeyInfo {
    RSA(rsa::RSAKey),
    DSA(DSAKeyInfo)
}

const OID_RSA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_DSA: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01];

fn parse_rsa_key_info(node: &ASN1Item) -> Result<rsa::RSAKey, X509Error> {
    let _ = validate_node(node, TagType::Sequence, 2);
    let modulus = parse_huge(&node.children()[0]);
    let exponent = parse_huge(&node.children()[1]);
    Ok(rsa::RSAKey::new(modulus, exponent))
}

fn parse_dsa_params(node: &ASN1Item) -> Result<DSAParams, X509Error> {
    let _ = validate_node(node, TagType::Sequence, 3)?;
    let p = parse_huge(&node.children()[0]);
    let q = parse_huge(&node.children()[1]);
    let g = parse_huge(&node.children()[2]);

    Ok(DSAParams { p, q, g })
}

fn parse_dsa_key_info(params_node: &ASN1Item, public_key_node: &ASN1Item) -> Result<DSAKeyInfo, X509Error> {
    let _ = validate_node_type(public_key_node, TagType::Integer)?;
    let public_key = parse_huge(public_key_node);

    // if signing algorithm is DSA, parameters should be contained within the children of the params node
    let params = parse_dsa_params(params_node)?;

    Ok(DSAKeyInfo { public_key, params })
}

// TODO: validate the public key info against the certificate signing algorithm? Do it later?
fn parse_public_key_info(node: &ASN1Item) -> Result<PublicKeyInfo, X509Error> {
    let _ = validate_node(node, TagType::Sequence, 2)?;

    // first child should be a Sequence containing a single public key OID
    let oid_sequence_node = &node.children()[0];
    let _ = validate_node(oid_sequence_node, TagType::Sequence, 1)?;
    let oid_node = &oid_sequence_node.children()[0];

    let _ = validate_node_type(oid_node, TagType::ObjectIdentifier)?;

    let public_key_node = &node.children()[1];
    let _ = validate_node_type(public_key_node, TagType::BitString);

    // public key is a bitstring which contains another ASN.1 DER-encoded value
    // NOTE: BitStrings can be any length and are not required to have a length which is a multiple
    // of 8 (i.e. is not required to fit in an integral number of bytes). The first byte of the
    // bitstring data indicates the number of bits of padding within the data component.
    // RSA and DSA public keys should fit into an integral number of bytes and so should have no padding
    let padding_bits = public_key_node.data()[0];
    if padding_bits != 0 {
        return Err(X509Error::UnexpectedPadding(padding_bits))
    }

    let public_key_data_node = asn1::parse(&public_key_node.data()[1..]).map_err(X509Error::ASN1)?;

    if OID_RSA == oid_node.data() {
        let rsa_key = parse_rsa_key_info(&public_key_data_node)?;
        Ok(PublicKeyInfo::RSA(rsa_key))
    } else if OID_DSA == oid_node.data() {
        // DSA parameters should be defined in the next sibling of the OID node
        let _ = validate_node_children(oid_sequence_node, 2)?;
        let params_node = &oid_sequence_node.children()[1];
        let dsa_key_info = parse_dsa_key_info(params_node, &public_key_data_node)?;
        Ok(PublicKeyInfo::DSA(dsa_key_info))
    } else {
        Err(X509Error::UnknownPublicKeyOID(oid_node.data().to_vec()))
    }
}

enum KnownExtension {
    KeyUsage { can_sign: bool }
}

const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x0F];

// indicates the key can be used to sign other certificates
const BIT_CERT_SIGNER: usize = 5;

fn get_bit(buf: &[u8], index: usize) -> bool {
    let byte_index = index / 8;
    let byte_offset = index % 8;

    buf.get(byte_index).map(|byte| ((0x80 >> byte_offset) & byte) > 0).unwrap_or(false)
}

fn parse_extension(node: &ASN1Item) -> Result<Option<KnownExtension>, X509Error> {
    let _ = validate_node(node, TagType::Sequence, 2)?;

    let oid_node = &node.children()[0];
    let (critical, data_node) = {
        let child = &node.children()[1];
        if child.tag().tag_type == TagType::Boolean {
            // TODO: data should always contain a single byte?
            (*child.data().get(0).unwrap_or(&0) > 0, &node.children()[2])
        } else {
            (false, child)
        }
    };

    if OID_KEY_USAGE == oid_node.data() {
        let key_usage_node = asn1::parse(data_node.data()).map_err(X509Error::ASN1)?;

        // NOTE: first byte within parse node data indicates the number of padding bits
        // skip this when searching for the 'cert signing' bit
        let can_sign = get_bit(&key_usage_node.data()[1..], BIT_CERT_SIGNER);
        Ok(Some(KnownExtension::KeyUsage { can_sign }))
    } else {
        Ok(None)
    }
}

fn parse_extensions(extensions_node: &ASN1Item) -> Result<Vec<KnownExtension>, X509Error> {
    // extensions node should be a single-element node containing a Sequence node with an arbitrary number of
    // extension nodes
    let _ = validate_node_children(extensions_node, 1);
    let mut extensions = Vec::new();

    for extension_node in extensions_node.children()[0].children() {
        if let Some(ext) = parse_extension(extension_node)? {
            extensions.push(ext)
        }
    }

    Ok(extensions)
}

fn parse_certificate(cert: &ASN1Item) -> Result<X509Certificate, X509Error> {
    /* SEQUENCE {
         version EXPLICIT
         serialNumber,
         signature,
         issuer,
         validity,
         subject,
         subjectPublicKeyInfo,
         issuerUniqueID,
         subjectUniqueID,
         extensions
       } */

    // TODO: validate expected number of children properly
    let _ = validate_node(cert, TagType::Sequence, 6);

    let (version, child_index) = {
        let version_node = &cert.children()[0];

        // see if there's an explicit version number
        // tag class will be 'context specific' and child should be an integer in the range [0,3)
        if version_node.tag().class == TagClass::ContextSpecific && version_node.tag().tag_type == TagType::BER {
            let _ = validate_node_children(version_node, 1);
            let version_number = parse_version_number(&version_node.children()[0])?;
            (version_number, 1)
        } else {
            // default to version 1 if none specified
            (Version::One, 0)
        }
    };

    let serial_number_node = &cert.children()[child_index];
    let signature_algorithm_node = &cert.children()[child_index + 1];
    let issuer_node = &cert.children()[child_index + 2];
    let validity_node = &cert.children()[child_index + 3];
    let subject_node = &cert.children()[child_index + 4];
    let public_key_info_node = &cert.children()[child_index + 5];
    let extension_node = &cert.children().get(child_index + 6);

    let serial_number = parse_serial_number(serial_number_node)?;
    let signature_algorithm_identifier = parse_signing_algorithm_identifier(signature_algorithm_node)?;
    let issuer = parse_name(issuer_node)?;
    let validity = parse_validity(validity_node)?;
    let subject = parse_name(subject_node)?;
    let public_key_info = parse_public_key_info(public_key_info_node)?;

    let known_extensions = extension_node.map(parse_extensions).unwrap_or(Ok(Vec::new()))?;

    Ok(X509Certificate {
        version,
        serial_number,
        issuer,
        validity,
        subject,
        public_key_info,
        signature_algorithm_identifier,
        known_extensions
    })
}

fn calculate_certificate_hash(alg: SigningAlgorithmIdentifier, node: &ASN1Item) -> Vec<u8> {
    let mut reader = io::Cursor::new(node.node_data());
    match alg {
        SigningAlgorithmIdentifier::MD5WithRSA => {
            hash::hash(&mut reader, &md5::MD5HashAlgorithm {}).expect("Failed to hash")
        },
        SigningAlgorithmIdentifier::SHA1WithDSA | SigningAlgorithmIdentifier::SHA1WithRSA => {
            hash::hash(&mut reader, &sha::SHA1HashAlgorithm {}).expect("Failed to calculate SHA1 hash")
        },
        SigningAlgorithmIdentifier::SHA256WithRSA => {
            hash::hash(&mut reader, &sha::SHA256HashAlgorithm {}).expect("Failed to calculate SHA256 hash")
        }
    }
}

fn parse_signed_certificate(root: &ASN1Item) -> Result<SignedX509Certificate, X509Error> {
    let children = root.children();

    // root certificate should contain the certificate, the signature algorithm and the signature itself
    let _ = validate_node(root, TagType::Sequence, 3)?;

    let certificate_node = &children[0];
    let certificate = parse_certificate(certificate_node)?;
    let signing_algorithm_id = parse_signing_algorithm_identifier(&children[1])?;
    let signature = parse_signature(&children[2], signing_algorithm_id)?;
    let hash = calculate_certificate_hash(signing_algorithm_id, &certificate_node);
    Ok(SignedX509Certificate { certificate, signing_algorithm_id, signature, hash })
}

pub fn parse(buf: &[u8]) -> Result<SignedX509Certificate, X509Error> {
    let raw = asn1::parse(buf).map_err(X509Error::ASN1)?;
    parse_signed_certificate(&raw)
}

fn write_indent(indent: usize) {
    print!("{}", "  ".repeat(indent));
}

fn pretty_print_public_key_info(info: &PublicKeyInfo, indent: usize) {
    match info {
        PublicKeyInfo::RSA(ref rsa) => {
            write_indent(indent);
            println!("Public Key Algorithm: RSA");

            write_indent(indent + 1);
            println!("Modulus: {}", format_huge(&rsa.modulus));
            write_indent(indent + 1);
            println!("Exponent: {}", format_huge(&rsa.exponent));
        },
        PublicKeyInfo::DSA(ref dsa) => {
            write_indent(indent);
            println!("Public key algorithm: DSA");

            write_indent(indent + 1);
            println!("y: {}", format_huge(&dsa.public_key));
            write_indent(indent + 1);
            println!("p: {}", format_huge(&dsa.params.p));
            write_indent(indent + 1);
            println!("q: {}", format_huge(&dsa.params.q));
            write_indent(indent + 1);
            println!("g: {}", format_huge(&dsa.params.g));
        }
    }
}

fn pretty_print_extensions(extensions: &[KnownExtension], indent: usize) {
    write_indent(indent);
    println!("Extensions:");

    for ext in extensions {
        write_indent(indent + 1);
        match ext {
            KnownExtension::KeyUsage { can_sign } => {
                println!("Key Usage:");
                write_indent(indent + 2);
                println!("CA: {}", can_sign);
            }
        }
    }
}

fn format_bytes(bytes: &[u8]) -> String {
    let formatted_bytes: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    formatted_bytes.join(":")
}

fn format_huge(huge: &Huge) -> String {
    format_bytes(huge.bytes())
}

fn pretty_print_cert(cert: &X509Certificate, indent: usize) {
    write_indent(indent);
    println!("Data:");

    write_indent(indent + 1);
    println!("Version: {}", cert.version);

    write_indent(indent + 1);
    println!("Serial number:");
    write_indent(indent + 2);
    println!("{}", format_huge(&cert.serial_number));

    write_indent(indent + 1);
    println!("Signature Algorithm: {:?}", cert.signature_algorithm_identifier);

    write_indent(indent + 1);
    println!("Issuer: {}", cert.issuer);

    write_indent(indent + 1);
    println!("Validity:");
    write_indent(indent + 2);
    {
        let date_format = "%b %d %H:%M:%S %Y";
        println!("Not before: {}", cert.validity.not_before.format(date_format));
        write_indent(indent + 2);
        println!("Not after: {}", cert.validity.not_after.format(date_format));
    }

    write_indent(indent + 1);
    println!("Subject {}", cert.subject);

    write_indent(indent + 1);
    println!("Subject Public Key Info:");
    pretty_print_public_key_info(&cert.public_key_info, indent + 2);

    if ! cert.known_extensions.is_empty() {
        pretty_print_extensions(&cert.known_extensions, indent + 1);
    }
}

fn pretty_print_signing_algorithm(signing_algorithm: &Signature, indent: usize) {
    write_indent(indent);
    println!("Signature algorithm:");

    write_indent(indent + 1);
    match signing_algorithm {
        Signature::RSA { hasher, ..} => {
            println!("{} with RSA encryption: ", hasher)
        },
        Signature::DSA { hasher, signature } => {
            println!("{} with DSA: r: {}, s: {}", hasher, format_huge(&signature.r), format_huge(&signature.s))
        }
    }
}

pub fn pretty_print(cert: &SignedX509Certificate) {
    println!("Certificate:");
    pretty_print_cert(&cert.certificate, 1);

    pretty_print_signing_algorithm(&cert.signature, 1);
}

pub enum SignatureError {
    RSADecryptionFailed, //TODO: update rsa_decrypt to return a Result
    RSAHashMismatch(Vec<u8>),
    DSAVerificationFailed,
    NodeParseFailed(ASN1Error),
    NodeStructure(ASN1Item),
    SignatureAlgorithmMismatch
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::RSADecryptionFailed => "Failed to decrypt RSA signature".to_owned(),
            Self::RSAHashMismatch(_) => "RSA hash did not match".to_owned(),
            Self::NodeParseFailed(ref asn1_err) => format!("Failed to parse signature ASN1: {}", asn1_err),
            Self::NodeStructure(_) => "Unexpected structure for signature ASN1".to_owned(),
            Self::SignatureAlgorithmMismatch => "Key invalid for certificate signature".to_owned(),
            Self::DSAVerificationFailed => "DSA verification failed".to_owned()
        };
        write!(f, "{}", msg)
    }
}

fn validate_certificate_rsa(signature: &Huge, public_key: &rsa::RSAKey, cert_hash: &[u8]) -> Result<(), SignatureError> {
    // decrypted bytes should represent an ASN1 structure
    let bytes = rsa::rsa_decrypt(public_key, signature.bytes());

    let node = asn1::parse(&bytes[..]).map_err(SignatureError::NodeParseFailed)?;
    if node.children().len() < 2 {
        Err(SignatureError::NodeStructure(node))
    } else {
        let hash_node = &node.children()[1];
        if cert_hash == hash_node.data() {
            Ok(())
        } else {
            Err(SignatureError::RSAHashMismatch(hash_node.data().to_vec()))
        }
    }
}

pub fn verify_self_signed_certificate(cert: &SignedX509Certificate) -> Result<(), SignatureError> {
    let cert_hash = &cert.hash[..];

    match cert.signature {
        Signature::RSA { ref signature, .. } => {
            match cert.certificate.public_key_info {
                PublicKeyInfo::RSA(ref rsa_key) => {
                    validate_certificate_rsa(signature, rsa_key, cert_hash)
                },
                _ => { Err(SignatureError::SignatureAlgorithmMismatch) }
            }
        },
        Signature::DSA { ref signature, .. } => {
            match cert.certificate.public_key_info {
                PublicKeyInfo::DSA(ref dsa_key) => {
                    if dsa::verify(&dsa_key.params, &dsa_key.public_key, cert_hash, signature) {
                        Ok(())
                    } else {
                        Err(SignatureError::DSAVerificationFailed)
                    }
                },
                _ => Err(SignatureError::SignatureAlgorithmMismatch)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::asn1::{ASN1Item, TagType, Tag, TagClass };
    use chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, Utc, Offset, TimeZone};

    #[test]
    fn parse_time_test_valid() {
        let time_str = "221119121030Z";
        let tag = Tag { constructed: false, class: TagClass::Universal, tag_type: TagType::UTCTime };
        let node = asn1::ASN1Item::leaf(tag, time_str.as_bytes().to_vec());

        let result = parse_time(&node);
        let expected = DateTime::from_local(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2022, 11, 19).unwrap(),
                NaiveTime::from_hms_opt(12, 10, 30).unwrap()),
            Utc.fix());

        assert_eq!(Ok(expected), result);
    }
}