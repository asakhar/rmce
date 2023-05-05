mod impls;

use boxed_array::from_default;
use serde::{de::Visitor, Deserialize, Serialize};

use impls::me8192128f::{CIPHER_TEXT_LEN, PUBLIC_KEY_LEN, SECRET_KEY_LEN};

#[cfg(feature = "openssl")]
fn crypto_random(data: &mut [u8]) {
  openssl::rand::rand_bytes(data).unwrap();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; Self::SIZE]>);

impl Serialize for PublicKey {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(self.as_bytes())
  }
}

pub struct BoxedArrayVisitor<const SIZE: usize>;
pub struct ArrayVisitor<const SIZE: usize>;
impl<'de, const SIZE: usize> Visitor<'de> for BoxedArrayVisitor<SIZE> {
  type Value = Box<[u8; SIZE]>;
  fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
    formatter.write_fmt(format_args!("raw bytes of length: {}", SIZE))
  }
  fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    let len = v.len();
    v.into_boxed_slice()
      .try_into()
      .map_err(|_| E::invalid_length(len, &self))
  }
  fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    if v.len() != SIZE {
      return Err(E::invalid_length(v.len(), &self));
    }
    let mut arr: Box<[u8; SIZE]> = boxed_array::from_default();
    arr.copy_from_slice(v);
    Ok(arr)
  }
}
impl<'de, const SIZE: usize> Visitor<'de> for ArrayVisitor<SIZE> {
  type Value = [u8; SIZE];
  fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
    formatter.write_fmt(format_args!("raw bytes of length: {}", SIZE))
  }
  fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
  }
}

impl<'de> Deserialize<'de> for PublicKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let contents = deserializer.deserialize_byte_buf(BoxedArrayVisitor)?;
    Ok(Self(contents))
  }
}

impl From<Box<[u8; Self::SIZE]>> for PublicKey {
  fn from(array: Box<[u8; Self::SIZE]>) -> Self {
    Self(array)
  }
}

impl PublicKey {
  pub const SIZE: usize = PUBLIC_KEY_LEN;
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
  #[cfg(feature = "openssl")]
  pub fn session(&self, plain_secret_len: usize) -> (ShareableSecret, PlainSecret) {
    self.session_with_entropy_provider(plain_secret_len, crypto_random)
  }
  pub fn session_with_entropy_provider<F: FnMut(&mut [u8])>(
    &self,
    plain_secret_len: usize,
    entropy_provider: F,
  ) -> (ShareableSecret, PlainSecret) {
    if plain_secret_len < 16 {
      log::warn!("Selected length of plain secret is too low ({plain_secret_len}). Consider choosing it in range [16..=128].")
    }
    if plain_secret_len > 128 {
      log::warn!("Selected length of plain secret is too high ({plain_secret_len}). Consider choosing it in range [16..=128].")
    }
    let mut shared = ShareableSecret([0u8; ShareableSecret::SIZE]);
    let mut plain = PlainSecret(vec![0u8; plain_secret_len]);
    impls::me8192128f::operations::crypto_kem_enc(
      &mut shared.0,
      &mut plain.0,
      &self.0,
      entropy_provider,
    );
    (shared, plain)
  }
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
  InvalidLength { got: usize, expected: usize },
}

impl std::error::Error for Error {}

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
    let mut pk_own = Self(from_default());
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

impl Serialize for SecretKey {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(self.as_bytes())
  }
}

impl<'de> Deserialize<'de> for SecretKey {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let contents = deserializer.deserialize_byte_buf(BoxedArrayVisitor)?;
    Ok(Self(contents))
  }
}

impl From<Box<[u8; Self::SIZE]>> for SecretKey {
  fn from(array: Box<[u8; Self::SIZE]>) -> Self {
    Self(array)
  }
}

impl SecretKey {
  pub const SIZE: usize = SECRET_KEY_LEN;
  pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
    &self.0
  }
}

impl TryFrom<&[u8]> for SecretKey {
  type Error = Error;
  fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
    let sk: &[u8; Self::SIZE] = value.try_into().map_err(|_| Self::Error::InvalidLength {
      got: value.len(),
      expected: Self::SIZE,
    })?;
    let mut sk_own = Self(from_default());
    sk_own.0.copy_from_slice(sk);
    Ok(sk_own)
  }
}

impl TryFrom<Vec<u8>> for SecretKey {
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

#[cfg(feature = "openssl")]
pub fn generate_keypair() -> (PublicKey, SecretKey) {
  generate_keypair_with_entropy_provider(crypto_random)
}

pub fn generate_keypair_with_entropy_provider<F: FnMut(&mut [u8])>(
  entropy_provider: F,
) -> (PublicKey, SecretKey) {
  let mut pk = PublicKey(from_default());
  let mut sk = SecretKey(from_default());
  impls::me8192128f::operations::crypto_kem_keypair(&mut pk.0, &mut sk.0, entropy_provider);
  (pk, sk)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareableSecret([u8; Self::SIZE]);

impl TryFrom<Vec<u8>> for ShareableSecret {
  type Error = Vec<u8>;
  fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
    Ok(Self(value.try_into()?))
  }
}

impl Serialize for ShareableSecret {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bytes(&self.0)
  }
}

impl<'de> Deserialize<'de> for ShareableSecret {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let contents = deserializer.deserialize_bytes(ArrayVisitor)?;
    Ok(Self(contents))
  }
}

impl ShareableSecret {
  pub const SIZE: usize = CIPHER_TEXT_LEN;
  pub fn open(&self, plain_secret_len: usize, sk: &SecretKey) -> PlainSecret {
    let mut plain = PlainSecret(vec![0u8; plain_secret_len]);
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainSecret(Vec<u8>);

impl PlainSecret {
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }
}

impl From<PlainSecret> for Vec<u8> {
  fn from(value: PlainSecret) -> Self {
    value.0
  }
}

impl From<Vec<u8>> for PlainSecret {
  fn from(value: Vec<u8>) -> Self {
    Self(value.into())
  }
}
