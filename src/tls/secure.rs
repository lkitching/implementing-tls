use super::messages::*;
use crate::hash::{HashAlgorithm};

pub struct CipherSuite {
    id: CipherSuiteIdentifier,
    pub block_size: usize,
    pub hash_size: usize,
    pub key_size: usize,
    pub iv_size: usize
}

impl CipherSuite {
    pub fn has_digest(&self) -> bool {
        todo!()
    }

    pub fn has_encryption(&self) -> bool {
        todo!()
    }

    pub fn requires_padding(&self) -> bool {
        self.block_size > 0
    }

    pub fn bulk_encrypt(&self, plaintext: &[u8], iv: &[u8], key: &[u8], ciphertext_buf: &mut [u8]) {
        todo!()
    }

    pub fn bulk_decrypt(&self, ciphertext: &[u8], iv: &[u8], key: &[u8], plaintext_buf: &mut [u8]) {
        todo!()
    }
}

// TODO: get hash algorithm from id and move to method
const MD5_BYTE_SIZE: usize = 16;
const SHA1_BYTE_SIZE: usize = 20;

const CIPHER_SUITES: [CipherSuite; 57] = [
    CipherSuite { id: CipherSuiteIdentifier::TLS_NULL_WITH_NULL_NULL, block_size: 0, hash_size: 0, key_size: 0, iv_size: 0, },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_NULL_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_NULL_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_EXPORT_WITH_RC4_40_MD5, block_size: 0, hash_size: 0, key_size: 5, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_RC4_128_MD5, block_size: 0, hash_size: 0, key_size: 16, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_RC4_128_SHA, block_size: 0, hash_size: 0, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_IDEA_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_DES_CBC_SHA, block_size: 8, hash_size: 8, key_size: 8, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_3DES_EDE_CBC_SHA, block_size: 8, hash_size: 8, key_size: 24, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, block_size: 8, hash_size: 8, key_size: 24, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_WITH_DES_CBC_SHA, block_size: 8, hash_size: 8, key_size: 8, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_RC4_128_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_DES_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_3DES_EDE_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_RC4_128_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_IDEA_CBC_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_DES_CBC_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_3DES_EDE_CBC_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_RC4_128_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_WITH_IDEA_CBC_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_RC4_40_SHA, block_size: 0, hash_size: 0, key_size: 0, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_KRB5_EXPORT_WITH_RC4_40_MD5, block_size: 0, hash_size: 0, key_size: 0, iv_size: MD5_BYTE_SIZE },

    // XXX are these three defined?
    CipherSuite { id: CipherSuiteIdentifier::TLS_UNDEF_1, block_size: 0, hash_size: 0, key_size: 0, iv_size: 0 },
    CipherSuite { id: CipherSuiteIdentifier::TLS_UNDEF_2, block_size: 0, hash_size: 0, key_size: 0, iv_size: 0 },
    CipherSuite { id: CipherSuiteIdentifier::TLS_UNDEF_3, block_size: 0, hash_size: 0, key_size: 0, iv_size: 0 },

    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_AES_128_CBC_SHA, block_size: 16, hash_size: 16, key_size: 16, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_RSA_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_DSS_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_RSA_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_DSS_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DHE_RSA_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
    CipherSuite { id: CipherSuiteIdentifier::TLS_DH_anon_WITH_AES_256_CBC_SHA, block_size: 16, hash_size: 16, key_size: 32, iv_size: SHA1_BYTE_SIZE },
];

pub fn get_cipher_suite(suite_id: CipherSuiteIdentifier) -> &'static CipherSuite {
    &CIPHER_SUITES[suite_id as usize]
}

#[derive(Clone)]
pub struct ProtectionParameters {
    pub mac_secret: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    pub suite: CipherSuiteIdentifier,
    pub seq_num: u64
}

impl ProtectionParameters {
    pub fn set_secrets(&mut self, mac: &[u8], key: &[u8], iv: &[u8]) {
        self.mac_secret = mac.to_vec();
        self.key = key.to_vec();
        self.iv = iv.to_vec();
    }

    pub fn init(&mut self) {
        self.suite = CipherSuiteIdentifier::TLS_NULL_WITH_NULL_NULL;
        self.seq_num = 0;
        self.mac_secret = Vec::new();
        self.key = Vec::new();
        self.iv = Vec::new();
    }

    pub fn hmac(&self, data: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }

    pub fn iv(&self) -> &[u8] {
        self.iv.as_slice()
    }

    pub fn key(&self) -> &[u8] {
        self.key.as_slice()
    }

    pub fn seq_num(&self) -> u64 {
        self.seq_num
    }

    pub fn next_seq_num(&mut self) {
        self.seq_num += 1;
    }

    pub fn reset_seq_num(&mut self) {
        self.seq_num = 0;
    }
}