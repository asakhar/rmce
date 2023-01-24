#![allow(dead_code)]
use super::Signed;

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct CryptoInt<T>(pub T);

impl<T> CryptoInt<T>
where
  T: Copy
    + Signed
    + std::ops::Shr<usize, Output = T>
    + std::ops::Neg<Output = T>
    + std::ops::BitOr<Output = T>
    + std::ops::Not<Output = T>
    + std::ops::BitAnd<Output = T>
    + std::ops::BitXorAssign
    + std::ops::BitXor<Output = T>
    + std::ops::Sub<Output = T>
    + std::ops::BitAndAssign<T>,
{
  const SHIFT_AMOUNT: usize = std::mem::size_of::<T>() * 8 - 1;

  pub fn negative_mask(self) -> Self {
    Self(self.0 >> Self::SHIFT_AMOUNT)
  }
  pub fn nonzero_mask(self) -> Self {
    Self(self.negative_mask().0 | Self(-self.0).negative_mask().0)
  }
  pub fn zero_mask(self) -> Self {
    Self(!self.nonzero_mask().0)
  }
  pub fn positive_mask(self) -> Self {
    let mut z = -self.0;
    z ^= self.0 & z;
    Self(z).negative_mask()
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
    z ^= xy & (z ^ self.0);
    Self(z).negative_mask()
  }
  pub fn min(self, y: Self) -> Self {
    let xy = y.0 ^ self.0;
    let mut z = y.0 - self.0;
    z ^= xy & (z ^ y.0);
    z = Self(z).negative_mask().0;
    z &= xy;
    Self(self.0 ^ z)
  }

  pub fn max(self, y: Self) -> Self {
    let xy = y.0 ^ self.0;
    let mut z = y.0 - self.0;
    z ^= xy & (z ^ y.0);
    z = Self(z).negative_mask().0;
    z &= xy;
    Self(y.0 ^ z)
  }
  pub fn minmax(a: &mut Self, b: &mut Self) {
    let x = *a;
    let y = *b;
    let xy = y.0 ^ x.0;
    let mut z = y.0 - x.0;
    z ^= xy & (z ^ y.0);
    z = Self(z).negative_mask().0;
    z &= xy;
    *a = Self(x.0 ^ z);
    *b = Self(y.0 ^ z);
  }
}
