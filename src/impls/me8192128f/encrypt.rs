/*
  This file is for Niederreiter encryption
*/

use crate::impls::subroutines::{
  crypto_declassify::crypto_declassify,
  crypto_uint::{CryptoUint, CryptoUint32},
};

use super::{
  gf::Gf,
  params::{PK_NROWS, PK_ROW_BYTES, SYND_BYTES, SYS_N, SYS_T},
  util::{load_gf, AsRefArray, BoxedArrayExt},
  PUBLIC_KEY_LEN,
};

pub fn encrypt<F: FnMut(&mut [u8])>(
  s: &mut [u8; SYND_BYTES],
  pk: &[u8; PUBLIC_KEY_LEN],
  e: &mut [u8; SYS_N / 8],
  random_bytes_generator: F,
) {
  gen_e(e, random_bytes_generator);

  syndrome(s, pk, e)
}

fn is_equal_declassify(t: u32, u: u32) -> CryptoUint32 {
  let mut mask = CryptoUint(t).equal_mask(CryptoUint(u));
  crypto_declassify(&mut mask);
  mask
}

fn same_mask(x: u16, y: u16) -> u8 {
  let mut mask = (x ^ y) as u32;
  mask = mask.wrapping_sub(1);
  mask >>= 31;
  mask = mask.wrapping_neg();
  (mask & 0xFF) as u8
}

/* output: e, an error vector of weight t */
fn gen_e<F: FnMut(&mut [u8])>(e: &mut [u8; SYS_N / 8], mut random_bytes_generator: F) {
  let mut ind = [Gf(0); SYS_T];
  let mut bytes = [0u8; SYS_T * 2];
  let mut val = [0u8; SYS_T];

  loop {
    random_bytes_generator(&mut bytes);

    for i in 0..SYS_T {
      ind[i] = load_gf(bytes.as_ref_array(i*2));
    }

    // check for repetition

    let mut eq = false;

    for i in 1..SYS_T {
      for j in 0..i {
        if is_equal_declassify(ind[i].0 as u32, ind[j].0 as u32).0 != 0 {
          eq = true;
        }
      }
    }

    if !eq {
      break;
    }
  }

  for j in 0..SYS_T {
    val[j] = 1 << (ind[j].0 & 7);
  }

  for i in 0..SYS_N / 8 {
    for j in 0..SYS_T {
      let mask = same_mask(i as u16, ind[j].0 >> 3);
      e[i] |= val[j] & mask;
    }
  }
}

fn syndrome(s: &mut [u8; SYND_BYTES], pk: &[u8; PUBLIC_KEY_LEN], e: &[u8; SYS_N / 8]) {
  let mut row = Box::<[u8; SYS_N / 8]>::placement_new(0);
  let mut pkoffset = 0;

  s.fill(0);

  for i in 0..PK_NROWS {
    row.fill(0);
    for j in 0..PK_ROW_BYTES {
      row[SYS_N / 8 - PK_ROW_BYTES + j] = pk[pkoffset+j];
    }
    row[i / 8] |= 1 << (i % 8);

    let mut b = 0;
    for j in 0..SYS_N / 8 {
      b ^= row[j] & e[j];
    }

    b ^= b >> 4;
    b ^= b >> 2;
    b ^= b >> 1;
    b &= 1;

    s[i / 8] |= b << (i % 8);

    pkoffset += PK_ROW_BYTES;
  }
}
