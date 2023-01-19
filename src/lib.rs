pub const PUBLIC_KEY_LEN: usize = 261120;
pub const SECRET_KEY_LEN: usize = 6492;
pub const CIPHER_TEXT_LEN: usize = 96;
pub const PLAIN_TEXT_LEN: usize = 32;
const SUCCESS: i32 = 0;

pub mod impls;

extern "C" {
    fn key_pair(pk: *mut u8, sk: *mut u8) -> i32;
    fn generate_session(c: *mut u8, key: *mut u8, pk: *const u8) -> i32;
    fn open_secret(key: *mut u8, c: *const u8, sk: *const u8) -> i32;
}

#[no_mangle]
pub extern "C" fn randombytes(bytes: *mut u8, len: u64) -> i32 {
    let buf = unsafe { std::slice::from_raw_parts_mut(bytes, len as usize) };
    openssl::rand::rand_bytes(buf).expect("Failed to generate random seed");
    SUCCESS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; PUBLIC_KEY_LEN]>);

impl PublicKey {
    fn empty() -> Self {
        Self(Box::new([0u8; PUBLIC_KEY_LEN]))
    }
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
    pub fn session(self) -> (ShareableSecret, PlainSecret) {
        let mut shared = ShareableSecret([0u8; CIPHER_TEXT_LEN]);
        let mut plain = PlainSecret([0u8; PLAIN_TEXT_LEN]);
        let res = unsafe {
            generate_session(shared.0.as_mut_ptr(), plain.0.as_mut_ptr(), self.0.as_ptr())
        };
        debug_assert_eq!(res, SUCCESS);
        (shared, plain)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(Box<[u8; SECRET_KEY_LEN]>);

impl SecretKey {
    fn empty() -> Self {
        Self(Box::new([0u8; SECRET_KEY_LEN]))
    }
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }
}

pub fn keypair() -> (PublicKey, SecretKey) {
    let mut pk = PublicKey::empty();
    let mut sk = SecretKey::empty();
    let res = unsafe { key_pair(pk.0.as_mut_ptr(), sk.0.as_mut_ptr()) };
    debug_assert_eq!(res, SUCCESS);
    (pk, sk)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareableSecret([u8; CIPHER_TEXT_LEN]);

impl ShareableSecret {
    pub fn open(self, sk: SecretKey) -> PlainSecret {
        let mut plain = PlainSecret([0u8; PLAIN_TEXT_LEN]);
        let res = unsafe { open_secret(plain.0.as_mut_ptr(), self.0.as_ptr(), sk.0.as_ptr()) };
        debug_assert_eq!(res, SUCCESS);
        plain
    }
    pub fn as_bytes(&self) -> &[u8; CIPHER_TEXT_LEN] {
        &self.0
    }
}

impl From<ShareableSecret> for [u8; CIPHER_TEXT_LEN] {
    fn from(s: ShareableSecret) -> Self {
        s.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainSecret([u8; PLAIN_TEXT_LEN]);

impl PlainSecret {
    pub fn as_bytes(&self) -> &[u8; PLAIN_TEXT_LEN] {
        &self.0
    }
}

impl From<PlainSecret> for [u8; PLAIN_TEXT_LEN] {
    fn from(p: PlainSecret) -> Self {
        p.0
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn encrypts_decrypts() {
        // local
        let (pk, sk) = keypair();
        // remote
        let (ss, ps1) = pk.session();
        // local
        let ps2 = ss.open(sk);
        assert_eq!(ps1, ps2);
    }
}
