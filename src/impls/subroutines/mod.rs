pub mod crypto_declassify;
pub mod crypto_int;
pub mod crypto_uint;

pub trait HasMultIdent {
  fn multiplicative_identity() -> Self;
}

impl HasMultIdent for u16 {
  fn multiplicative_identity() -> Self {
    1u16
  }
}

impl HasMultIdent for u32 {
  fn multiplicative_identity() -> Self {
    1u32
  }
}

impl HasMultIdent for u64 {
  fn multiplicative_identity() -> Self {
    1u64
  }
}

impl HasMultIdent for i16 {
  fn multiplicative_identity() -> Self {
    1i16
  }
}

impl HasMultIdent for i32 {
  fn multiplicative_identity() -> Self {
    1i32
  }
}

impl HasMultIdent for i64 {
  fn multiplicative_identity() -> Self {
    1i64
  }
}

pub trait IsSigned {
  type RespectiveUnsigned: IsUnsigned<RespectiveSigned = Self>;
  fn to_unsigned(self) -> Self::RespectiveUnsigned;
}
impl IsSigned for i16 {
  type RespectiveUnsigned = u16;
  fn to_unsigned(self) -> Self::RespectiveUnsigned {
    self as Self::RespectiveUnsigned
  }
}
impl IsSigned for i32 {
  type RespectiveUnsigned = u32;
  fn to_unsigned(self) -> Self::RespectiveUnsigned {
    self as Self::RespectiveUnsigned
  }
}
impl IsSigned for i64 {
  type RespectiveUnsigned = u64;
  fn to_unsigned(self) -> Self::RespectiveUnsigned {
    self as Self::RespectiveUnsigned
  }
}
pub trait IsUnsigned {
  type RespectiveSigned: IsSigned<RespectiveUnsigned = Self>;
  fn to_signed(self) -> Self::RespectiveSigned;
}
impl IsUnsigned for u16 {
  type RespectiveSigned = i16;
  fn to_signed(self) -> Self::RespectiveSigned {
    self as Self::RespectiveSigned
  }
}
impl IsUnsigned for u32 {
  type RespectiveSigned = i32;
  fn to_signed(self) -> Self::RespectiveSigned {
    self as Self::RespectiveSigned
  }
}
impl IsUnsigned for u64 {
  type RespectiveSigned = i64;
  fn to_signed(self) -> Self::RespectiveSigned {
    self as Self::RespectiveSigned
  }
}
