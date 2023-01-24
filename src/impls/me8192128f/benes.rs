/*
  This file is for Benes network related functions

  For the implementation strategy, see
  https://eprint.iacr.org/2017/793.pdf
*/

use super::{
  gf::Gf,
  params::{COND_BYTES, GFBITS, SYS_N},
  transpose::transpose_64x64,
  util::{load8, store8, AsMutArray, AsRefArray},
};

/* input: r, sequence of bits to be permuted */
/*        bits, condition bits of the Benes network */
/*        rev, 0 for normal application; !0 for inverse */
/* output: r, permuted bits */
pub fn apply_benes(r: &mut [u8; (1 << GFBITS) / 8], bits: &[u8; COND_BYTES], rev: bool) {
  let mut r_int_v = [[0u64; 64]; 2];
  let mut r_int_h = [[0u64; 64]; 2];
  let mut b_int_v = [0u64; 64];
  let mut b_int_h = [0u64; 64];

  let (mut bits_offset, inc) = if rev { (12288, 1024) } else { (0, 0) };

  for i in 0..64 {
    r_int_v[0][i] = load8(r.as_ref_array(i * 16 + 0));
    r_int_v[1][i] = load8(r.as_ref_array(i * 16 + 8));
  }
  transpose_64x64(&mut r_int_h[0], &r_int_v[0]);
  transpose_64x64(&mut r_int_h[1], &r_int_v[1]);
  for iter in 0..=6 {
    for i in 0..64 {
      b_int_v[i] = load8(bits.as_ref_array(bits_offset));
      bits_offset += 8;
    }

    bits_offset -= inc;

    transpose_64x64(&mut b_int_h, &b_int_v);

    layer_ex(&mut r_int_h, &b_int_h, iter);
  }
  transpose_64x64(&mut r_int_v[0], &r_int_h[0]);
  transpose_64x64(&mut r_int_v[1], &r_int_h[1]);

  for iter in 0..=5 {
    for i in 0..64 {
      b_int_v[i] = load8(bits.as_ref_array(bits_offset));
      bits_offset += 8;
    }
    bits_offset -= inc;

    layer_in(&mut r_int_v, &b_int_v, iter);
  }

  for iter in (0..=4).rev() {
    for i in 0..64 {
      b_int_v[i] = load8(bits.as_ref_array(bits_offset));
      bits_offset += 8;
    }
    bits_offset -= inc;

    layer_in(&mut r_int_v, &b_int_v, iter);
  }

  transpose_64x64(&mut r_int_h[0], &r_int_v[0]);
  transpose_64x64(&mut r_int_h[1], &r_int_v[1]);

  for iter in (0..=6).rev() {
    for i in 0..64 {
      b_int_v[i] = load8(bits.as_ref_array(bits_offset));
      bits_offset += 8;
    }

    bits_offset += inc;

    transpose_64x64(&mut b_int_h, &b_int_v);

    layer_ex(&mut r_int_h, &b_int_h, iter);
  }

  transpose_64x64(&mut r_int_v[0], &r_int_h[0]);
  transpose_64x64(&mut r_int_v[1], &r_int_h[1]);

  for i in 0..64 {
    store8(r.as_mut_array(i * 16 + 0), r_int_v[0][i]);
    store8(r.as_mut_array(i * 16 + 8), r_int_v[1][i]);
  }
}

/* input: condition bits c */
/* output: support s */
#[allow(non_snake_case)]
pub fn support_gen(s: &mut [Gf; SYS_N], c: &[u8; COND_BYTES]) {
  // pregenerate L
  // lazy_static::lazy_static! {
  //   static ref L: [[u8; (1 << GFBITS) / 8]; GFBITS] = {
  //     use super::util::bitrev;
  //     let mut l = [[0u8; (1 << GFBITS) / 8]; GFBITS];
  //     for i in 0..(1 << GFBITS) {
  //       let a = bitrev(Gf(i));

  //       for j in 0..GFBITS {
  //         l[j][i as usize / 8] |= ((((a.0 >> j) & 1) << (i % 8)) & 0xFF) as u8;
  //       }
  //     }
  //     use std::io::Write;
  //     let mut file = std::fs::File::create("L_mat.in").unwrap();
  //     write!(file, "{l:?}").unwrap();
  //     l
  //   };
  // };
  let mut l = include!("benes_mat_13.in");

  for j in 0..GFBITS {
    apply_benes(&mut l[j], c, false);
  }

  for i in 0..SYS_N {
    s[i] = Gf(0);
    for j in (0..GFBITS).rev() {
      s[i].0 <<= 1;
      s[i].0 |= ((l[j][i / 8] >> (i % 8)) & 1) as u16;
    }
  }
}

/* middle layers of the benes network */
fn layer_in(data: &mut [[u64; 64]; 2], bits: &[u64; 64], lgs: i32) {
  let mut d;

  let s = 1 << lgs;
  let mut i = 0;
  let mut offset = 0;
  while i < 64 {
    for j in i..i + s {
      d = data[0][j + 0] ^ data[0][j + s];
      d &= bits[offset];
      offset += 1;
      data[0][j + 0] ^= d;
      data[0][j + s] ^= d;

      d = data[1][j + 0] ^ data[1][j + s];
      d &= bits[offset];
      offset += 1;
      data[1][j + 0] ^= d;
      data[1][j + s] ^= d;
    }
    i += s * 2;
  }
}
/* first and last layers of the benes network */
fn layer_ex(data: &mut [[u64; 64]; 2], bits: &[u64; 64], lgs: i32) {
  let mut d;

  let s = 1 << lgs;
  let mut offset = 0;
  let mut i = 0;

  while i < 128 {
    for j in i..i + s {
      d = data[j / 64][j % 64 + 0] ^ data[(j + s) / 64][(j + s) % 64];
      d &= bits[offset];
      offset += 1;
      data[(j + 0) / 64][(j + 0) % 64] ^= d;
      data[(j + s) / 64][(j + s) % 64] ^= d;
    }
    i += s * 2;
  }
}
