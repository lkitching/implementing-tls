use std::ops::{Add, Sub, Mul, Shl, Div};
use std::cmp::{PartialEq, Eq, PartialOrd, Ord, Ordering};
use std::convert::{From, TryFrom};
use std::num::{TryFromIntError};

#[derive(Copy, Clone, Debug)]
pub struct TryFromHugeError;

#[derive(Clone)]
pub struct Huge {
    rep: Vec<u8>
}

impl Huge {
    pub fn len(&self) -> usize {
        self.rep.len()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.rep
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        // skip any leading zeros in buf
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != 0 {
                break;
            }
            i += 1;
        }

        Huge { rep: bytes[i..].to_vec() }
    }

    pub fn pow(self, exp: Huge) -> Huge {

        let mut tmp1 = self.clone();
        let mut result = Huge::from(1u8);

        for i in (0..exp.len()).rev() {
            for mask in BitMasks::from(0x01) {
                if (exp.rep[i] & mask) > 0 {
                    result = result * tmp1.clone();
                }

                // square tmp1
                tmp1 = tmp1.clone() * tmp1;
            }
        }

        result
    }

    // computes self ^ e % n
    pub fn mod_pow(self, e: Huge, n: Huge) -> Huge {
        let mut tmp1 = self.clone();
        let mut result = Huge::from(1u8);

        for i in (0..e.len()).rev() {
            for mask in BitMasks::from(0x01) {
                if e.rep[i] & mask > 0 {
                    result = result.clone() * tmp1.clone();
                    let DivResult { remainder, .. } = result / n.clone();
                    result = remainder;
                }

                // square tmp1
                tmp1 = tmp1.clone() * tmp1;
                let DivResult { remainder, .. } = tmp1 / n.clone();
                tmp1 = remainder;
            }
        }

        result
    }
}

fn expand_buf(buf: &mut Vec<u8>) {
    // implements any final carry by prepending 0x01 to the
    // internal buffer
    buf.insert(0, 1);
}

fn contract_buf(buf: &mut Vec<u8>) {
    // find index of first non-zero byte
    let mut offset = 0;
    while offset < buf.len() {
        if buf[offset] != 0 {
            break;
        }
        offset += 1;
    }

    if offset == 0 {
        return;
    }

    // special case - all bytes are zero so clear vector
    if offset == buf.len() {
        buf.clear();
        return;
    }

    // shift each byte down by offset bytes
    for i in offset .. buf.len() {
        buf[i - offset] = buf[i];
    }

    unsafe { buf.set_len(buf.len() - offset); }
    buf.shrink_to_fit();
}

fn left_shift_buf(buf: &mut Vec<u8>) {
    // NOTE: version in book expects buffer to be non-empty
    assert!(buf.len() > 0);

    let mut old_carry = false;
    let mut carry = false;

    for i in (0..buf.len()).rev() {
        old_carry = carry;

        // carry required if high-order bit is set
        carry = (buf[i] & 0x80) == 0x80;

        // shift current byte left and set lower-order bit to previous carry
        buf[i] = (buf[i] << 1) | u8::from(old_carry);
    }

    if carry {
        expand_buf(buf);
    }
}

fn right_shift_buf(buf: &mut Vec<u8>) {
    // iterate from most to least-significant byte shifting right
    // if least-significant bit is set this becomes the most-significant bit of the
    // next byte
    let mut old_carry: u8 = 0;
    let mut carry: u8 = 0;

    for i in 0..buf.len() {
        old_carry = carry;
        carry = (buf[i] & 0x01) << 7;
        buf[i] = (buf[i] >> 1) | old_carry;
    }

    contract_buf(buf);
}

fn expand_to_size(buf: &mut Vec<u8>, size: usize) {
    if size > buf.len() {
        let offset = size - buf.len();
        let old_len = buf.len();

        // expand buf to required size
        buf.resize(size, 0);

        // shift each element up by offset
        for i in (0..old_len).rev() {
            buf[i + offset] = buf[i];
        }

        // zero lower bytes
        for i in 0..offset {
            buf[i] = 0;
        }
    }

    assert!(buf.len() >= size);
}

fn add_buf(h1: &mut Vec<u8>, h2: &Vec<u8>) {
    // ensure h1 buffer is at least as large as h2 buffer
    expand_to_size(h1, h2.len());

    // LSB is at the end of both buffers
    // iterate towards start of h1 until the beginning is reached
    let mut i = h1.len();
    let mut j = h2.len();
    let mut is_carry = false;

    while i > 0 {
        i -= 1;
        let sum: u16 = if j > 0 {
            j -= 1;
            (h1[i] as u16) + (h2[j] as u16) + u16::from(is_carry)
        } else {
            (h1[i] as u16) + u16::from(is_carry)
        };

        h1[i] = (sum & 0xFF) as u8;
        is_carry = sum > 0xFF;
    }

    // if carry flag still set, need to expand result by 1 and set MSB to 1
    if is_carry {
        expand_buf(h1);
    }
}

impl Add for Huge {
    type Output = Huge;

    fn add(self, rhs: Huge) -> Huge {
        // create result buffer - this should be large enough to contain either
        // self or rhs
        let mut result: Vec<u8> = self.rep.clone();
        add_buf(&mut result, &rhs.rep);
        Huge { rep: result }
    }
}

fn subtract_buf(h1: &mut Vec<u8>, h2: &Vec<u8>) {
    let mut i = h1.len();
    let mut j = h2.len();
    let mut is_borrow = false;

    while i > 0 {
        i -= 1;
        let difference = if j > 0 {
            j -= 1;
            (h1[i] as i16) - (h2[j] as i16) - i16::from(is_borrow)
        } else {
            (h1[i] as i16) - i16::from(is_borrow)
        };

        h1[i] = (difference & 0x00FF) as u8;
        is_borrow = difference < 0;
    }

    contract_buf(h1);
}

impl Sub for Huge {
    type Output = Huge;

    fn sub(self, rhs: Huge) -> Huge {
        if rhs.len() > self.len() {
            panic!("Result would be negative");
        }

        let mut buf = self.rep;
        subtract_buf(&mut buf, &rhs.rep);
        Huge { rep: buf }
    }
}

struct BitMaskIterator {
    value: u8
}

impl Iterator for BitMaskIterator {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.value == 0 {
            None
        } else {
            let result = Some(self.value);
            self.value <<= 1;
            result
        }
    }
}

struct BitMasks {
    start: u8
}

impl BitMasks {
    pub fn from(start: u8) -> BitMasks {
        BitMasks { start }
    }
}

impl IntoIterator for BitMasks {
    type Item = u8;
    type IntoIter = BitMaskIterator;

    fn into_iter(self) -> Self::IntoIter {
        BitMaskIterator { value: self.start }
    }
}

impl Mul for Huge {
    type Output = Huge;

    fn mul(self, rhs: Huge) -> Huge {
        // copy self into temp buffer
        let mut temp = self.rep;

        // create output buffer
        // TODO: reserve more space? Need to trim at the end anyway!
        let mut result: Vec<u8> = vec![0; 1];

        // iterate through each bit of rhs
        for i in (0..rhs.rep.len()).rev() {
            for mask in BitMasks::from(0x01) {
                if (mask & rhs.rep[i]) > 0 {
                    add_buf(&mut result, &temp)
                }
                left_shift_buf(&mut temp);
            }
        }

        contract_buf(&mut result);
        Huge { rep: result }
    }
}

pub struct DivResult {
    pub quotient: Huge,
    pub remainder: Huge
}

impl Div for Huge {
    type Output = DivResult;

    fn div(self, divisor: Huge) -> Self::Output {

        let mut bit_size = 0;
        let mut dividend = self;
        let mut divisor = divisor;

        // TODO: clone divisor buffer?

        // left-shift divisor until it's >= the dividend
        while divisor < dividend {
            left_shift_buf(&mut divisor.rep);
            bit_size += 1;
        }

        // overestimates a bit in some cases
        let quot_len = (bit_size / 8) + 1;
        let mut quot_buf = vec![0; quot_len];

        // keeps track of which bit of the quotient is being set or cleared on the current operation
        let mut bit_position = 8 - (bit_size % 8) - 1;

        loop {
            if divisor <= dividend {
                subtract_buf(&mut dividend.rep, &divisor.rep);
                quot_buf[(bit_position / 8) as usize] |= (0x80 >> (bit_position % 8));
            }

            if bit_size > 0 {
                right_shift_buf(&mut divisor.rep);
                bit_position += 1;
                bit_size -= 1;
            } else {
                break;
            }
        }

        DivResult {
            quotient: Huge { rep: quot_buf },
            remainder: dividend,
        }
    }
}

fn buf_cmp(h1: &Vec<u8>, h2: &Vec<u8>) -> Ordering {
    if h1.len() > h2.len() {
        Ordering::Greater
    } else if h2.len() > h1.len() {
        Ordering::Less
    } else {
        // both have same number of digits
        // compare from most to least-significant digits
        for i in 0..h1.len() {
            let c = h1[i].cmp(&h2[i]);
            if c != Ordering::Equal {
                return c;
            }
        }

        // all digits equal
        Ordering::Equal
    }
}

impl PartialEq for Huge {
    fn eq(&self, other: &Self) -> bool {
        buf_cmp(&self.rep, &other.rep) == Ordering::Equal
    }
}

impl Eq for Huge {}

impl PartialOrd for Huge {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(buf_cmp(&self.rep, &other.rep))
    }
}

impl Ord for Huge {
    fn cmp(&self, other: &Huge) -> Ordering {
        buf_cmp(&self.rep, &other.rep)
    }
}

impl From<u8> for Huge {
    fn from(b: u8) -> Huge {
        Huge { rep: vec![b] }
    }
}

impl From<usize> for Huge {
    fn from(num: usize) -> Huge {
        let bytes = num.to_be_bytes();

        // remove leading 0 bytes
        let rep: Vec<u8> = bytes.into_iter().skip_while(|b| **b == 0).map(|b| *b).collect();
        Huge { rep }
    }
}

impl TryFrom<Huge> for u8 {
    type Error = TryFromHugeError;
    fn try_from(value: Huge) -> Result<u8, TryFromHugeError> {
        match value.len() {
            0 => { Ok(0) },
            1 => { Ok(value.rep[0]) },
            _ => { Err(TryFromHugeError) }
        }
    }
}

impl TryFrom<Huge> for usize {
    type Error = TryFromHugeError;
    fn try_from(value: Huge) -> Result<usize, TryFromHugeError> {
        let bytes = (usize::BITS / 8) as usize;
        if value.rep.len() > bytes {
            Err(TryFromHugeError)
        } else {
            let mut le_bytes = [0; 8];
            let offset = 8 - value.rep.len();
            for i in 0..value.rep.len() {
                le_bytes[i + offset] = value.rep[i];
            }
            Ok(usize::from_be_bytes(le_bytes))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::{TryInto};

    #[test]
    fn add_bytes() {
        let h1: Huge = Huge::from(8u8);
        let h2 = Huge::from(29u8);
        let result = h1 + h2;
        assert_eq!(37, u8::try_from(result).unwrap());
    }

    #[test]
    fn add_bytes_overflow() {
        let h1 = Huge::from(0xf4u8);
        let h2 = Huge::from(0xfau8);
        let result = h1 + h2;
        let expected: usize = 0xf4 + 0xfa;
        assert_eq!(expected, usize::try_from(result).unwrap());
    }

    #[test]
    fn from_usize_zero() {
        let h = Huge::from(0usize);
        assert_eq!(0, h.len());
    }

    #[test]
    fn from_usize_len() {
        let value = usize::from_be_bytes([0x00, 0x00, 0x12, 0x45, 0x83, 0xf2, 0x39, 0xae]);
        let h = Huge::from(value);
        assert_eq!(6, h.len());
    }

    #[test]
    fn round_trip_usize() {
        let u: usize = 234543829;
        let h = Huge::from(u);
        assert_eq!(u, usize::try_from(h).unwrap());
    }

    #[test]
    fn subtract_small() {
        let h1 = Huge::from(30u8);
        let h2 = Huge::from(15u8);
        let result = h1 - h2;
        assert_eq!(15, u8::try_from(result).unwrap());
    }

    #[test]
    fn subtract_large() {
        let u1: usize = 0xd420986413025702;
        let u2: usize = 0x023809743310fdc8;
        let expected = u1 - u2;
        let result = Huge::from(u1) - Huge::from(u2);

        assert_eq!(expected, usize::try_from(result).unwrap());
    }

    #[test]
    fn subtract_small_from_large() {
        let u1: usize = 0xca8930891204;
        let u2: usize = 0x2165;
        let expected = u1 - u2;
        let result = Huge::from(u1) - Huge::from(u2);

        assert_eq!(expected, usize::try_from(result).unwrap());
    }

    #[test]
    fn subtract_same() {
        let h1 = Huge::from(123u8);
        let h2 = Huge::from(123u8);
        let result = h1 - h2;

        assert_eq!(0, result.len());
        assert_eq!(0, u8::try_from(result).unwrap());
    }

    #[test]
    fn mul_zero_lhs() {
        let result = Huge::from(0u8) * Huge::from(24u8);
        assert_eq!(0, result.len());
        assert_eq!(0, u8::try_from(result).unwrap());
    }

    #[test]
    fn mul_zero_rhs() {
        let result = Huge::from(89u8) * Huge::from(0u8);
        assert_eq!(0, result.len());
        assert_eq!(0, u8::try_from(result).unwrap());
    }

    #[test]
    fn mul_one_lhs() {
        let result = Huge::from(1u8) * Huge::from(139u8);
        assert_eq!(139, u8::try_from(result).unwrap());
    }

    #[test]
    fn mul_one_rhs() {
        let lhs: usize = 2390835493805;
        let result = Huge::from(lhs) * Huge::from(1u8);
        assert_eq!(lhs, usize::try_from(result).unwrap());
    }

    #[test]
    fn mul_small() {
        let b1: u8 = 39;
        let b2: u8 = 203;
        let result = Huge::from(b1) * Huge::from(b2);
        let expected = (b1 as usize) * (b2 as usize);
        assert_eq!(expected, usize::try_from(result).unwrap());
    }

    #[test]
    fn mul_large() {
        let u1: usize = 359981;
        let u2: usize = 23492;
        let result = Huge::from(u1) * Huge::from(u2);

        assert_eq!(u1 * u2, usize::try_from(result).unwrap());
    }

    #[test]
    fn cmp_small_less() {
        assert!(Huge::from(14u8) < Huge::from(189u8));
    }

    #[test]
    fn cmp_small_greater() {
        assert!(Huge::from(248u8) > Huge::from(188u8));
    }

    #[test]
    fn cmp_small_equal() {
        assert!(Huge::from(49u8) == Huge::from(49u8));
    }

    #[test]
    fn cmp_large_less() {
        assert!(Huge::from(24983009usize) < Huge::from(79034812usize));
    }

     #[test]
    fn cmp_large_greater() {
        assert!(Huge::from(70998451usize) > Huge::from(41298846usize));
    }

    #[test]
    fn cmp_large_equal() {
        let n = 357901248342usize;
        assert!(Huge::from(n) == Huge::from(n));
    }

    #[test]
    fn div_small() {
        let DivResult { quotient, remainder } = Huge::from(14u8) / Huge::from(5u8);
        assert_eq!(2, u8::try_from(quotient).unwrap());
        assert_eq!(4, u8::try_from(remainder).unwrap());
    }

    #[test]
    fn div_large() {
        let numerator: usize = 349077981228;
        let divisor: usize = 29861;
        let DivResult { quotient, remainder } = Huge::from(numerator) / Huge::from(divisor);

        assert_eq!(numerator / divisor, usize::try_from(quotient).unwrap());
        assert_eq!(numerator % divisor, usize::try_from(remainder).unwrap());
    }

    #[test]
    fn div_zero_numerator() {
        let divisor: u8 = 219;
        let DivResult { quotient, remainder } = Huge::from(0u8) / Huge::from(divisor);

        assert_eq!(0, u8::try_from(quotient).unwrap());
        assert_eq!(0, u8::try_from(remainder).unwrap());
    }

    #[test]
    fn div_divisor_larger() {
        let numerator: u8 = 23;
        let DivResult { quotient, remainder } = Huge::from(23u8) / Huge::from(113u8);

        assert_eq!(0, u8::try_from(quotient).unwrap());
        assert_eq!(numerator, u8::try_from(remainder).unwrap());
    }

    #[test]
    fn pow_small() {
        let n = Huge::from(3u8);
        let e = Huge::from(6u8);
        let result = n.pow(e);

        assert!(result == Huge::from(729usize))
    }

    #[test]
    fn pow_large() {
        let n = Huge::from(357usize);
        let e = Huge::from(7u8);
        let result = n.pow(e);

        assert!(result == Huge::from(739056281869446093usize));
    }

    #[test]
    fn mod_pow_small() {
        let x = Huge::from(7u8);
        let e = Huge::from(16u8);
        let n = Huge::from(11u8);

        let result = x.mod_pow(e, n);
        assert!(result == Huge::from(4u8))
    }

    #[test]
    fn mod_pow_large() {
        let x = Huge::from(481usize);
        let e = Huge::from(9u8);
        let n = Huge::from(122u8);

        let result = x.mod_pow(e, n);
        assert!(result == Huge::from(89u8));
    }
}