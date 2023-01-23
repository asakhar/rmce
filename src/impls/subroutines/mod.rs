pub mod crypto_declassify;
pub mod crypto_int;
pub mod crypto_uint;

pub trait One {
  fn one() -> Self;
}

impl One for u16 {
  fn one() -> Self {
    1u16
  }
}

impl One for u32 {
  fn one() -> Self {
    1u32
  }
}

impl One for u64 {
  fn one() -> Self {
    1u64
  }
}

impl One for i16 {
  fn one() -> Self {
    1i16
  }
}

impl One for i32 {
  fn one() -> Self {
    1i32
  }
}

impl One for i64 {
  fn one() -> Self {
    1i64
  }
}

pub trait Signed {
  type Unsigned: Unsigned<Signed = Self>;
  fn to_unsigned(self) -> Self::Unsigned;
}
impl Signed for i16 {
  type Unsigned = u16;
  fn to_unsigned(self) -> Self::Unsigned {
    self as Self::Unsigned
  }
}
impl Signed for i32 {
  type Unsigned = u32;
  fn to_unsigned(self) -> Self::Unsigned {
    self as Self::Unsigned
  }
}
impl Signed for i64 {
  type Unsigned = u64;
  fn to_unsigned(self) -> Self::Unsigned {
    self as Self::Unsigned
  }
}
pub trait Unsigned {
  type Signed: Signed<Unsigned = Self>;
  fn to_signed(self) -> Self::Signed;
}
impl Unsigned for u16 {
  type Signed = i16;
  fn to_signed(self) -> Self::Signed {
    self as Self::Signed
  }
}
impl Unsigned for u32 {
  type Signed = i32;
  fn to_signed(self) -> Self::Signed {
    self as Self::Signed
  }
}
impl Unsigned for u64 {
  type Signed = i64;
  fn to_signed(self) -> Self::Signed {
    self as Self::Signed
  }
}
