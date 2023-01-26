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
    (&mut self[offset..offset + N]).try_into().unwrap()
  }
}
pub trait AsRefArray<T> {
  fn as_ref_array<const N: usize>(&self, offset: usize) -> &[T; N];
}

impl<T> AsRefArray<T> for [T] {
  fn as_ref_array<const N: usize>(&self, offset: usize) -> &[T; N] {
    (&self[offset..offset + N]).try_into().unwrap()
  }
}

pub trait BoxedArrayExt<T> {
  fn placement_new(init: T) -> Self;
}

impl<T: Clone, const N: usize> BoxedArrayExt<T> for Box<[T; N]> {
  fn placement_new(init: T) -> Self {
    // Safety: boxed slice to boxed array conversion may only fail in case of size mismatch. We have fixed size
    // std lib implementation of <Box<[T; N]> as TryFrom<Box<[T]>>>::try_from
    unsafe { Box::from_raw(Box::into_raw(vec![init; N].into_boxed_slice()) as *mut [T; N]) }
  }
}
