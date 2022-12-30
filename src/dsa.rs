use crate::huge::*;
use std::cmp;
use crate::hex;

#[derive(Clone)]
pub struct DSAParams {
    pub g: Huge,
    pub p: Huge,
    pub q: Huge
}

pub struct DSASignature {
    pub r: Huge,
    pub s: Huge
}

fn generate_c(params: &DSAParams) -> Huge {
    // generate some 'random' bytes and use it to initialise c
    let mut buf = vec![0u8; params.q.len() + 8];
    for i in 0..buf.len() {
        buf[i] = (i + 1) as u8;
    }
    Huge::from_bytes(&buf[..])
}

// loads a huge from the given bytes truncated to the length of h
fn load_truncated(bytes: &[u8], h: &Huge) -> Huge {
    let l = cmp::min(bytes.len(), h.len());
    Huge::from_bytes(&bytes[0..l])
}

pub fn sign(params: &DSAParams, private_key: &Huge, hash: &[u8]) -> DSASignature {
    let c = generate_c(params);

    // k = (c % (q - 1)) + 1
    let k = c.modulo(params.q.clone() - Huge::one()) + Huge::one();

    // r = (g ^ k % p) % q
    let r = params.g.clone().mod_pow(k.clone(), params.p.clone()).modulo(params.q.clone());

    // z = hash truncated to length of q
    let z = load_truncated(hash, &params.q);

    // s = ( inv(k, q) * (z + xr)) % q
    let s = (Huge::inv(k, params.q.clone()) * (z + (private_key.clone() * r.clone()))).modulo(params.q.clone());

    DSASignature { r, s }
}

pub fn verify(params: &DSAParams, public_key: &Huge, hash: &[u8], signature: &DSASignature) -> bool {
    let q = params.q.clone();
    let p = params.p.clone();
    let g = params.g.clone();
    let s = signature.s.clone();
    let r = signature.r.clone();
    let y = public_key.clone();

    // w = inv(s, q) % q
    let w = Huge::inv(s, q.clone()).modulo(q.clone());

    // z = hash truncates to length of q
    let z = load_truncated(hash, &q);

    // u1 = (zw) % q
    let u1 = (z * w.clone()).modulo(q.clone());

    // u2 = (rw) % q
    let u2 = (r.clone() * w).modulo(q.clone());

    // NOTE: differs from given definition of v
    // % p distributes over multiplication
    //v = (((g^u1 % p) * (y^u2 % p)) % p) % q
    let v = (g.mod_pow(u1, p.clone()) * y.mod_pow(u2, p.clone())).modulo(p).modulo(q);

    // valid if v == r
    v == r
}