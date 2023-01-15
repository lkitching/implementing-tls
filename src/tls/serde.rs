use std::convert::{TryFrom, TryInto};
use std::fmt::{Debug};

pub trait BinaryLength {
    fn binary_len(&self) -> usize;
}

pub trait FixedBinaryLength {
    fn fixed_binary_len() -> usize;
}

impl <T: FixedBinaryLength> BinaryLength for T {
    fn binary_len(&self) -> usize {
        T::fixed_binary_len()
    }
}

pub trait BinarySerialisable : BinaryLength {
    fn write_to(&self, buf: &mut [u8]);
    fn write_to_vec(&self) -> Vec<u8> {
        let mut v = vec![0; self.binary_len()];
        self.write_to(v.as_mut_slice());
        v
    }
}

// TODO: merge with BinarySerialisable?
pub enum BinaryReadError {
    ValueOutOfRange,
    BufferTooSmall,
    BufferTooLarge,
    UnknownType
}

pub trait BinaryReadable {
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

pub fn read_into<T, U>(buf: &[u8]) -> Result<(U, &[u8]), BinaryReadError>
    where T: BinaryReadable,
          U: TryFrom<T> {
    let (t, buf) = T::read_from(buf)?;
    let u = U::try_from(t).map_err(|_| BinaryReadError::ValueOutOfRange)?;
    Ok((u, buf))
}

pub fn read_slice(buf: &[u8], length: usize) -> Result<(&[u8], &[u8]), BinaryReadError> {
    if buf.len() >= length {
        Ok(buf.split_at(length))
    } else {
        Err(BinaryReadError::BufferTooSmall)
    }
}

pub fn write_slice<'a, 'b>(slice: &'a [u8], buf: &'b mut [u8]) -> &'b mut [u8] {
    let (to_write, rest) = buf.split_at_mut(slice.len());
    to_write.copy_from_slice(slice);
    rest
}

pub fn read_elements<L, T>(buf: &[u8]) -> Result<(Vec<T>, &[u8]), BinaryReadError>
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

pub fn read_seq<T: BinaryReadable>(buf: &[u8]) -> Result<Vec<T>, BinaryReadError> {
    let mut result = Vec::new();
    let mut buf = buf;

    while ! buf.is_empty() {
        let (v, remaining) = T::read_from(buf)?;
        result.push(v);
        buf = remaining
    }

    Ok(result)
}

pub fn write_front<'a, T: BinarySerialisable>(msg: &T, buf: &'a mut [u8]) -> &'a mut [u8] {
    let (msg_buf, rest) = buf.split_at_mut(msg.binary_len());
    msg.write_to(msg_buf);
    rest
}

pub fn write_elements<L, T>(buf: &mut [u8], elems: &[T])
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

impl FixedBinaryLength for u64 {
    fn fixed_binary_len() -> usize { 8 }
}

impl BinarySerialisable for u64 {
    fn write_to(&self, buf: &mut [u8]) {
        todo!()
    }
}

impl BinaryReadable for u64 {
    fn read_from(buf: &[u8]) -> Result<(Self, &[u8]), BinaryReadError> where Self: Sized {
        let bytes: [u8; 8] = buf.try_into().map_err(|_| BinaryReadError::BufferTooSmall)?;
        let value = u64::from_be_bytes(bytes);
        Ok((value, &buf[8..]))
    }
}