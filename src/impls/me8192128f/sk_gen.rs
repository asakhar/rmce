use crate::impls::subroutines::{crypto_uint::{CryptoUint16, CryptoUint}, crypto_declassify::crypto_declassify};

use super::{gf::{Gf, gf_mul}, params::SYS_T};



fn is_zero_declassify(t: Gf) -> CryptoUint16 {
  let mut mask = CryptoUint(t.0).zero_mask();
  crypto_declassify(&mut mask);
  mask
}


/* input: f, element in GF((2^m)^t) */
/* output: out, minimal polynomial of f */
/* return: 0 for success and -1 for failure */
pub fn genpoly_gen(out: &mut [Gf; SYS_T], f: &[Gf; SYS_T]) -> bool {
  let mut mat = [[Gf(0); SYS_T]; SYS_T+1];

  // fill matrix 

  mat[0][0] = Gf(1);

  for i in 0..SYS_T {
    mat[1][i] = f[i];
  }

  for j in 2..=SYS_T {
    let (p1, p2) = mat.split_at_mut(j);
    gf_mul(&mut p2[0], &p1[j-1], f);
  }

  // gaussian

  for j in 0..SYS_T {
    for k in j+1..SYS_T {
      let mask = mat[j][j].is_zero();  
      for c in j..SYS_T+1 {
        mat[c][j].0 ^= mat[c][k].0 & mask.0;
      }
    }
    if is_zero_declassify(mat[j][j]).0 != 0 { // return if not systematic
      return false;
    }

    let inv = mat[j][j].inv(); 

    for c in j..SYS_T+1 {
      mat[c][j] = mat[c][j].mul(inv); 
    }

    for k in 0..SYS_T {
      if k != j {
        let t = mat[j][k];
        for c in j..SYS_T+1 {
          mat[c][k].0 ^= mat[c][j].mul(t).0; 
        }
      }
    }
  }

  for i in 0..SYS_T {
    out[i] = mat[SYS_T][i];
  }

  true
}