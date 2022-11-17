use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::convert::TryFrom;

use crate::hex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TagClass {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
#[repr(u8)]
pub enum TagType {
    BER = 0,
    Boolean = 1,
    Integer = 2,
    BitString = 3,
    OctetString = 4,
    Null = 5,
    ObjectIdentifier = 6,
    ObjectDescriptor = 7,
    InstanceOfExternal = 8,
    Real = 9,
    Enumerated = 10,
    EmbeddedPPV = 11,
    UTF8String = 12,
    RelativeOID = 13,
    // 14 and 15 undefined
    Sequence = 16,
    Set = 17,
    NumericString = 18,
    PrintableString = 19,
    TeletexString = 20,
    T61String = 21,
    IA5String = 22,
    UTCTime = 23,
    GeneralisedTime = 24,
    GraphicString = 25,
    VisibleString = 26,
    //ISO64String =
    GeneralString = 27,
    UniversalString = 28,
    CharacterString = 29,
    BMPString = 30
}

#[derive(Debug, Copy, Clone)]
pub struct Tag {
    constructed: bool,
    class: TagClass,
    tag_type: TagType
}

pub struct ASN1Item {
    tag: Tag,
    data: Vec<u8>,
    children: Vec<ASN1Item>
}

// TODO: return Result
fn parse_tag(buf: &[u8]) -> (Tag, &[u8]) {
    let tag_byte = buf[0];
    let mut i = 1;

    // If bits 1-5 are all set, tag is variable length
    // NOTE: not used in X.509
    let tag_value = if tag_byte & 0x1F == 0x1F {
        // let mut v: u8 = 0;
        // while buf[i] & 0x80 == 0x80 {
        //     // TODO: should only shift by 7 bits?
        //     v <<= 8;
        //     v |= (buf[i] & 0x7F);
        //     // NOTE: missing in book
        //     i += 1;
        // }
        // v
        panic!("Variable length tags not supported");
    } else {
        tag_byte
    };

    // TODO: deal with 'high tag numbers'
    let constructed = tag_value & 0x20 == 0x20;
    let class_value = (tag_value & 0xC0) >> 6;
    let type_value = tag_value & 0x1F;

    let class = TagClass::try_from(class_value).expect("Invalid class value");
    let ty = TagType::try_from(type_value).expect("Invalid type value");
    let tag = Tag { constructed, class, tag_type: ty };

    (tag, &buf[i..])
}

// TODO: return Result
fn parse_length(buf: &[u8]) -> (usize, &[u8]) {
    let tag_length_byte = buf[0];

    // if the high bit is set in the length byte, the lower 7 bytes encode the length of the length
    let (i, length) = if tag_length_byte & 0x80 == 0x80 {
        let length_length = tag_length_byte & 0x7F;
        let mut len = 0;
        for i in 1..=length_length {
            len <<= 8;
            len |= buf[i as usize] as usize;
        }
        (length_length as usize + 1, len)
    } else {
        (1, tag_length_byte as usize)
    };

    (length, &buf[i..])
}

// TODO: return Result
pub fn parse_node(buf: &[u8]) -> (ASN1Item, &[u8]) {
    let mut remaining = buf;

    let (tag, remaining) = parse_tag(remaining);
    let (length, remaining) = parse_length(remaining);
    let data = remaining[0..length].to_vec();
    let mut children = Vec::new();

    if tag.constructed {
        let mut child_remaining = &data[..];
        while ! child_remaining.is_empty() {
            let (child_node, child_buf) = parse_node(&child_remaining[..]);
            children.push(child_node);
            child_remaining = child_buf;
        }
    }

    (ASN1Item { tag, data, children }, &remaining[length..])
}

pub fn parse(buf: &[u8]) -> Result<ASN1Item, String> {
    let (root, remaining) = parse_node(&buf[..]);
    // TODO: validate properly
    assert!(remaining.is_empty(), "");
    Ok(root)
}

fn pretty_print_node(node: &ASN1Item, indent: usize) {
    let type_desc = match node.tag.class {
        TagClass::Universal => { format!("{:?}", node.tag.tag_type) },
        TagClass::Application => { String::from("application") },
        TagClass::ContextSpecific => { String::from("context") },
        TagClass::Private => { String::from("private") }
    };

    let value = match node.tag.tag_type {
        TagType::ObjectIdentifier => {
            hex::format_hex(&node.data[..])
        },
        TagType::UTF8String => {
            String::from_utf8(node.data.clone()).expect("Invalid UTF-8 string")
        },
        _ => { String::new() }
    };

    println!("{}{} ({}, {}) {}", "  ".repeat(indent), type_desc, node.tag.tag_type as u8, node.data.len(), value);

    for child in node.children.iter() {
        pretty_print_node(child, indent + 1);
    }
}

pub fn pretty_print(cert: &ASN1Item) {
    pretty_print_node(cert, 0);
}

#[cfg(test)]
pub mod test {
    use super::*;
    use std::fs;
    use std::io::{Read};

    #[test]
    fn parse_length_single() {
        let bytes = vec![0x28];
        let (len, remaining) = parse_length(&bytes[..]);

        assert_eq!(0x28usize, len);
        assert!(remaining.is_empty());
    }

    #[test]
    fn parse_length_multiple() {
        let bytes = vec![0x82, 0x03, 0x49, 0x01, 0x02];
        let (len, remaining) = parse_length(&bytes[..]);

        assert_eq!(841, len);
        assert_eq!(&bytes[3..], remaining);
    }

    #[test]
    fn parse_version_number_node() {
        // tag - 0x02
        //  class 0 (Universal)
        //  constructed - false
        //  type 2 (Integer)
        let bytes = vec![0x02, 0x01, 0x02];
        let (node, remaining) = parse_node(&bytes[..]);

        assert_eq!(false, node.tag.constructed);
        assert_eq!(TagType::Integer, node.tag.tag_type);
        assert_eq!(1, node.data.len());

        assert!(remaining.is_empty());
    }

    #[test]
    fn wat() {
        let path = "/home/lee/tmp/implementing_ssl/cert.der";
        let mut f = fs::File::open(path).expect("Failed to open certificate file");
        let mut bytes = Vec::new();
        let bytes_read = f.read_to_end(&mut bytes).expect("Failed to read certficate file");

        let cert = parse(&bytes[..]).expect("Failed to parse ASN1");
    }
}