#![allow(dead_code)]
use super::{One, Signed, Unsigned};

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct CryptoUint<T>(pub T);
pub type CryptoUint16 = CryptoUint<u16>;
pub type CryptoUint32 = CryptoUint<u32>;
pub type CryptoUint64 = CryptoUint<u64>;

impl<T> CryptoUint<T> {
  const SHIFT_AMOUNT: usize = std::mem::size_of::<T>() * 8 - 1;
}

impl<T> CryptoUint<T>
where
  T: Signed,
{
  pub fn to_unsigned(self) -> CryptoUint<T::Unsigned> {
    CryptoUint(self.0.to_unsigned())
  }
}

impl<T> CryptoUint<T>
where
  T: std::ops::Shr<usize, Output = T> + Signed,
{
  pub fn signed_negative_mask(self) -> Self {
    debug_assert_eq!(0x0000000000008000u16 as i16 >> 15, -1);
    debug_assert_eq!(0x0000000080000000u32 as i32 >> 31, -1);
    debug_assert_eq!(0x8000000000000000u64 as i64 >> 63, -1);
    Self(self.0 >> Self::SHIFT_AMOUNT)
  }
}

impl<T> CryptoUint<T>
where
  T: Unsigned,
{
  pub fn to_signed(self) -> CryptoUint<T::Signed> {
    CryptoUint(self.0.to_signed())
  }
}

impl<T> CryptoUint<T>
where
  T: Copy
    + Unsigned
    + std::ops::Shl<usize, Output = T>
    + std::ops::BitOr<Output = T>
    + std::ops::Not<Output = T>
    + std::ops::BitAnd<Output = T>
    + std::ops::BitXorAssign
    + std::ops::BitXor<Output = T>
    + std::ops::Sub<Output = T>
    + std::ops::BitAndAssign<T>,
  T::Signed: Copy + std::ops::Shr<usize, Output = T::Signed> + std::ops::Neg<Output = T::Signed>,
  T: One,
{
  pub fn nonzero_mask(self) -> Self {
    let signed = self.to_signed();
    CryptoUint(
      signed.signed_negative_mask().0.to_unsigned()
        | CryptoUint(-signed.0).signed_negative_mask().0.to_unsigned(),
    )
  }
  pub fn zero_mask(self) -> Self {
    Self(!self.nonzero_mask().0)
  }
  pub fn unequal_mask(self, y: Self) -> Self {
    let xy = self.0 ^ y.0;
    Self(xy).nonzero_mask()
  }
  pub fn equal_mask(self, y: Self) -> Self {
    Self(!self.unequal_mask(y).0)
  }
  pub fn smaller_mask(self, y: Self) -> Self {
    let xy = self.0 ^ y.0;
    let mut z = self.0 - y.0;
    z ^= xy & (z ^ self.0 ^ (T::one() << Self::SHIFT_AMOUNT));
    CryptoUint(z.to_signed())
      .signed_negative_mask()
      .to_unsigned()
  }
  pub fn min(self, y: Self) -> Self {
    let xy = y.0 ^ self.0;
    let mut z = y.0 - self.0;
    z ^= xy & (z ^ y.0 ^ (T::one() << Self::SHIFT_AMOUNT));
    z = CryptoUint(z.to_signed())
      .signed_negative_mask()
      .to_unsigned()
      .0;
    z &= xy;
    Self(self.0 ^ z)
  }

  pub fn max(self, y: Self) -> Self {
    let xy = y.0 ^ self.0;
    let mut z = y.0 - self.0;
    z ^= xy & (z ^ y.0 ^ (T::one() << Self::SHIFT_AMOUNT));
    z = CryptoUint(z.to_signed())
      .signed_negative_mask()
      .to_unsigned()
      .0;
    z &= xy;
    Self(y.0 ^ z)
  }
  pub fn minmax(a: &mut Self, b: &mut Self) {
    let x = *a;
    let y = *b;
    let xy = y.0 ^ x.0;
    let mut z = y.0 - x.0;
    z ^= xy & (z ^ y.0 ^ (T::one() << Self::SHIFT_AMOUNT));
    z = CryptoUint(z.to_signed())
      .signed_negative_mask()
      .to_unsigned()
      .0;
    z &= xy;
    *a = Self(x.0 ^ z);
    *b = Self(y.0 ^ z);
  }
}
