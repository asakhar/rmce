use super::{gf::Gf, params::GFMASK};

pub fn store_gf(dest: &mut [u8; 2], a: Gf) {
  dest[0] = ((a.0 >> 0) & 0xFF) as u8;
  dest[1] = ((a.0 >> 8) & 0xFF) as u8;
}

pub fn load_gf(src: &[u8; 2]) -> Gf {
  let mut a;
  a = src[1] as u16;
  a <<= 8;
  a |= src[0] as u16;
  Gf(a & GFMASK as u16)
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
  let mut a = a.0;
  a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
  a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
  a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
  a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);

  Gf(a >> 3)
}
