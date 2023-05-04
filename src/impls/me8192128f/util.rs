/*
  This file is for loading/storing data in a little-endian fashion and other utils
*/

use super::{gf::Gf, params::GFMASK};

pub fn store_gf(dest: &mut [u8; 2], a: Gf) {
  dest.copy_from_slice(&a.0.to_le_bytes())
}

pub fn load_gf(src: &[u8; 2]) -> Gf {
  Gf(u16::from_le_bytes(*src) & GFMASK as u16)
}

pub fn load4(inp: &[u8; 4]) -> u32 {
  u32::from_le_bytes(*inp)
}

pub fn store8(out: &mut [u8; 8], inp: u64) {
  out.copy_from_slice(&inp.to_le_bytes());
}

pub fn load8(inp: &[u8; 8]) -> u64 {
  u64::from_le_bytes(*inp)
}

pub fn bitrev(a: Gf) -> Gf {
  Gf(a.0.reverse_bits() >> 3)
}

pub trait AsMutArray<T> {
  fn as_mut_array<const N: usize>(&mut self, offset: usize) -> &mut [T; N];
}

impl<T> AsMutArray<T> for [T] {
  fn as_mut_array<const N: usize>(&mut self, offset: usize) -> &mut [T; N] {
    #[inline]
    unsafe fn as_array<T, const N: usize>(slice: &mut [T]) -> &mut [T; N] {
      &mut *(slice.as_mut_ptr() as *mut [_; N])
    }
    let offset = offset;
    let slice = &mut self[offset..offset + N];
    #[allow(unused_unsafe)]
    unsafe {
      as_array::<T, N>(slice)
    }
  }
}
pub trait AsRefArray<T> {
  fn as_ref_array<const N: usize>(&self, offset: usize) -> &[T; N];
}

impl<T> AsRefArray<T> for [T] {
  fn as_ref_array<const N: usize>(&self, offset: usize) -> &[T; N] {
    #[inline]
    unsafe fn as_array<T, const N: usize>(slice: &[T]) -> &[T; N] {
      &*(slice.as_ptr() as *const [_; N])
    }
    let offset = offset;
    let slice = &self[offset..offset + N];
    #[allow(unused_unsafe)]
    unsafe {
      as_array::<T, N>(slice)
    }
  }
}
