/*
  This file is for public-key generation
*/

use boxed_array::from_default;

use crate::impls::{
  me8192128f::util::AsMutArray,
  subroutines::{
    crypto_declassify::crypto_declassify,
    crypto_uint::{CryptoUint, CryptoUint64},
  },
  uint64_sort,
};

use super::{
  gf::Gf,
  params::{GFBITS, GFMASK, PK_NROWS, PK_ROW_BYTES, SYS_N, SYS_T},
  root::root,
  util::{bitrev, load8, load_gf, store8, AsRefArray},
  PUBLIC_KEY_LEN,
};

/* input: secret key sk */
/* output: public key pk */
#[allow(non_snake_case)]
pub fn pk_gen(
  pk: &mut [u8; PUBLIC_KEY_LEN],
  sk: &[u8; SYS_T * 2],
  perm: &[u32; 1 << GFBITS],
  pi: &mut [i16; 1 << GFBITS],
  pivots: &mut u64,
) -> bool {
  let mut buf: Box<[u64; 1 << GFBITS]> = from_default();

  let mut mat: Box<[[u8; SYS_N / 8]; PK_NROWS]> = from_default::<u8, _, _ >();

  let mut g = [Gf(0); SYS_T + 1];

  let mut L: Box<[Gf; SYS_N]> = from_default();
  let mut inv: Box<[Gf; SYS_N]> = from_default();

  //

  g[SYS_T] = Gf(1);

  for i in 0..SYS_T {
    g[i] = load_gf(sk.as_ref_array(i * 2));
  }
  drop(sk);

  for i in 0..(1 << GFBITS) {
    buf[i] = perm[i] as u64;
    buf[i] <<= 31;
    buf[i] |= i as u64;
  }

  uint64_sort::sort(&mut buf[..1 << GFBITS]);

  for i in 1..(1 << GFBITS) {
    if is_equal_declassify(buf[i - 1] >> 31, buf[i] >> 31).0 != 0 {
      return false;
    }
  }

  for i in 0..(1 << GFBITS) {
    pi[i] = (buf[i] & GFMASK) as i16;
  }
  for i in 0..SYS_N {
    L[i] = bitrev(Gf(pi[i] as u16));
  }

  //filling the matrix

  root(&mut inv, &g, &L);

  for i in 0..SYS_N {
    inv[i] = inv[i].inv();
  }

  for i in 0..SYS_T {
    for j in (0..SYS_N).step_by(8) {
      for k in 0..GFBITS {
        let mut b = (inv[j + 7].0 >> k) & 1;
        b <<= 1;
        b |= (inv[j + 6].0 >> k) & 1;
        b <<= 1;
        b |= (inv[j + 5].0 >> k) & 1;
        b <<= 1;
        b |= (inv[j + 4].0 >> k) & 1;
        b <<= 1;
        b |= (inv[j + 3].0 >> k) & 1;
        b <<= 1;
        b |= (inv[j + 2].0 >> k) & 1;
        b <<= 1;
        b |= (inv[j + 1].0 >> k) & 1;
        b <<= 1;
        b |= (inv[j + 0].0 >> k) & 1;

        mat[i * GFBITS + k][j / 8] = b as u8;
      }
    }
    for j in 0..SYS_N {
      inv[j] = inv[j].mul(L[j]);
    }
  }

  // gaussian elimination

  for i in 0..(PK_NROWS + 7) / 8 {
    for j in 0..8 {
      let row = i * 8 + j;
      if row >= PK_NROWS {
        break;
      }
      if row == PK_NROWS - 32 {
        if !mov_columns(&mut *mat, pi, pivots) {
          return false;
        }
      }

      for k in row + 1..PK_NROWS {
        let mut mask = mat[row][i] ^ mat[k][i];
        mask >>= j;
        mask &= 1;
        mask = mask.wrapping_neg();

        for c in 0..SYS_N / 8 {
          mat[row][c] ^= mat[k][c] & mask;
        }
      }

      if is_zero_declassify(((mat[row][i] >> j) & 1) as u64).0 != 0 {
        // return if not systematic
        return false;
      }

      for k in 0..PK_NROWS {
        if k != row {
          let mut mask = mat[k][i] >> j;
          mask &= 1;
          mask = mask.wrapping_neg();

          for c in 0..SYS_N / 8 {
            mat[k][c] ^= mat[row][c] & mask;
          }
        }
      }
    }
  }

  for i in 0..PK_NROWS {
    pk[i * PK_ROW_BYTES..i * PK_ROW_BYTES + PK_ROW_BYTES]
      .copy_from_slice(&mat[i][PK_NROWS / 8..PK_NROWS / 8 + PK_ROW_BYTES]);
  }

  true
}

fn is_equal_declassify(t: u64, u: u64) -> CryptoUint64 {
  let mut mask = CryptoUint(t).equal_mask(CryptoUint(u));
  crypto_declassify(&mut mask);
  mask
}

fn is_zero_declassify(t: u64) -> CryptoUint64 {
  let mut mask = CryptoUint(t).zero_mask();
  crypto_declassify(&mut mask);
  mask
}

fn ctz(inp: u64) -> u64 {
  inp.trailing_zeros() as u64
}

fn same_mask(x: u16, y: u16) -> u64 {
  let mut mask = (x ^ y) as u64;
  mask = mask.wrapping_sub(1);
  mask >>= 63;
  mask = mask.wrapping_neg();

  mask
}

fn mov_columns(mat: &mut [[u8; SYS_N / 8]; PK_NROWS], pi: &mut [i16], pivots: &mut u64) -> bool {
  const ONE: u64 = 1;
  let mut buf = [0u64; 64];
  let mut ctz_list = [0u64; 32];

  const ROW: usize = PK_NROWS - 32;
  const BLOCK_IDX: usize = ROW / 8;

  // extract the 32x64 matrix

  for i in 0..32 {
    buf[i] = load8(mat[ROW + i].as_ref_array(BLOCK_IDX));
  }

  // compute the column indices of pivots by Gaussian elimination.
  // the indices are stored in ctz_list

  *pivots = 0;

  for i in 0..32 {
    let mut t = buf[i];
    for j in i + 1..32 {
      t |= buf[j];
    }
    if is_zero_declassify(t).0 != 0 {
      // return if buf is not full rank
      return false;
    }
    let s = ctz(t);
    ctz_list[i] = s;
    *pivots |= ONE << s;

    for j in i + 1..32 {
      let mut mask = (buf[i] >> s) & 1;
      mask = mask.wrapping_sub(1);
      buf[i] ^= buf[j] & mask;
    }
    for j in i + 1..32 {
      let mut mask = (buf[j] >> s) & 1;
      mask = mask.wrapping_neg();
      buf[j] ^= buf[i] & mask;
    }
  }

  // updating permutation

  for j in 0..32 {
    for k in j + 1..64 {
      let mut d = (pi[ROW + j] ^ pi[ROW + k]) as u64;
      d &= same_mask(k as u16, ctz_list[j] as u16);
      pi[ROW + j] ^= d as i16;
      pi[ROW + k] ^= d as i16;
    }
  }

  // moving columns of mat according to the column indices of pivots

  for i in 0..PK_NROWS {
    let mut t = load8(mat[i].as_ref_array(BLOCK_IDX));
    for j in 0..32 {
      let mut d = t >> j;
      d ^= t >> ctz_list[j];
      d &= 1;

      t ^= d << ctz_list[j];
      t ^= d << j;
    }

    store8(mat[i].as_mut_array(BLOCK_IDX), t);
  }

  true
}
