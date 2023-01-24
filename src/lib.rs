mod impls;

use std::io::{Read, Write};

use impls::me8192128f::{
  BoxedArrayExt, CIPHER_TEXT_LEN, PLAIN_TEXT_LEN, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
};

#[cfg(feature = "openssl")]
fn crypto_random(data: &mut [u8]) {
  openssl::rand::rand_bytes(data).unwrap();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; Self::SIZE]>);

impl PublicKey {
  pub const SIZE: usize = PUBLIC_KEY_LEN;
  fn empty() -> Self {
    let arr = Box::<[u8; Self::SIZE]>::placement_new(0); //vec![0u8; Self::SIZE].into_boxed_slice().try_into().unwrap();
    Self(arr)
  }
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
  #[cfg(feature = "openssl")]
  pub fn session(&self) -> (ShareableSecret, PlainSecret) {
    self.session_with_entropy_provider(crypto_random)
  }
  pub fn session_with_entropy_provider<F: FnMut(&mut [u8])>(
    &self,
    entropy_provider: F,
  ) -> (ShareableSecret, PlainSecret) {
    let mut shared = ShareableSecret([0u8; ShareableSecret::SIZE]);
    let mut plain = PlainSecret([0u8; PlainSecret::SIZE]);
    impls::me8192128f::operations::crypto_kem_enc(
      &mut shared.0,
      &mut plain.0,
      &self.0,
      entropy_provider,
    );
    (shared, plain)
  }
  pub fn from_file<P: AsRef<std::path::Path>>(p: P) -> std::io::Result<Self> {
    let mut file = std::fs::File::open(p.as_ref())?;
    let mut pk = Self::empty();
    file.read_exact(pk.0.as_mut_slice())?;
    Ok(pk)
  }
  pub fn to_file<P: AsRef<std::path::Path>>(&self, p: P) -> std::io::Result<()> {
    let mut file = std::fs::File::create(p.as_ref())?;
    file.write_all(self.0.as_slice())?;
    Ok(())
  }
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
  InvalidLength { got: usize, expected: usize },
}

impl std::fmt::Display for Error {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{self:?}")
  }
}

impl TryFrom<&[u8]> for PublicKey {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    let pk: &[u8; Self::SIZE] = value.try_into().map_err(|_| Self::Error::InvalidLength {
      got: value.len(),
      expected: Self::SIZE,
    })?;
    let mut pk_own = Self::empty();
    pk_own.0.copy_from_slice(pk);
    Ok(pk_own)
  }
}

impl TryFrom<Vec<u8>> for PublicKey {
  type Error = Error;
  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
    let len = value.len();
    let pk: Box<[u8; Self::SIZE]> =
      value
        .into_boxed_slice()
        .try_into()
        .map_err(|_| Self::Error::InvalidLength {
          got: len,
          expected: Self::SIZE,
        })?;
    Ok(Self(pk))
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(Box<[u8; Self::SIZE]>);

impl SecretKey {
  pub const SIZE: usize = SECRET_KEY_LEN;
  fn empty() -> Self {
    let arr = Box::<[u8; Self::SIZE]>::placement_new(0);
    Self(arr)
  }
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
  pub fn from_file<P: AsRef<std::path::Path>>(p: P) -> std::io::Result<Self> {
    let mut file = std::fs::File::open(p.as_ref())?;
    let mut pk = Self::empty();
    file.read_exact(pk.0.as_mut_slice())?;
    Ok(pk)
  }
  pub fn to_file<P: AsRef<std::path::Path>>(&self, p: P) -> std::io::Result<()> {
    let mut file = std::fs::File::create(p.as_ref())?;
    file.write_all(self.0.as_slice())?;
    Ok(())
  }
}

#[cfg(feature = "openssl")]
pub fn generate_keypair() -> (PublicKey, SecretKey) {
  generate_keypair_with_entropy_provider(crypto_random)
}

pub fn generate_keypair_with_entropy_provider<F: FnMut(&mut [u8])>(
  entropy_provider: F,
) -> (PublicKey, SecretKey) {
  let mut pk = PublicKey::empty();
  let mut sk = SecretKey::empty();
  impls::me8192128f::operations::crypto_kem_keypair(&mut pk.0, &mut sk.0, entropy_provider);
  (pk, sk)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareableSecret([u8; Self::SIZE]);

impl ShareableSecret {
  pub const SIZE: usize = CIPHER_TEXT_LEN;
  pub fn open(&self, sk: &SecretKey) -> PlainSecret {
    let mut plain = PlainSecret([0u8; PlainSecret::SIZE]);
    impls::me8192128f::operations::crypto_kem_dec(&mut plain.0, &self.0, &sk.0);
    plain
  }
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
}

impl From<ShareableSecret> for [u8; ShareableSecret::SIZE] {
  fn from(s: ShareableSecret) -> Self {
    s.0
  }
}

impl From<[u8; ShareableSecret::SIZE]> for ShareableSecret {
  fn from(value: [u8; ShareableSecret::SIZE]) -> Self {
    Self(value)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainSecret([u8; Self::SIZE]);

impl PlainSecret {
  pub const SIZE: usize = PLAIN_TEXT_LEN;
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
}

impl From<PlainSecret> for [u8; PlainSecret::SIZE] {
  fn from(p: PlainSecret) -> Self {
    p.0
  }
}

impl From<[u8; PlainSecret::SIZE]> for PlainSecret {
  fn from(value: [u8; PlainSecret::SIZE]) -> Self {
    Self(value)
  }
}
