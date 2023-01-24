/*
  This file is for the Berlekamp-Massey algorithm
  see http://crypto.stanford.edu/~mironov/cs359/massey.pdf
*/

use super::{gf::Gf, params::SYS_T};

/* the Berlekamp-Massey algorithm */
/* input: s, sequence of field elements */
/* output: out, minimal polynomial of s */
#[allow(non_snake_case)]
pub fn bm(out: &mut [Gf; SYS_T + 1], s: &[Gf; 2 * SYS_T]) {
  let mut L = 0;
  let mut mle;
  let mut mne;

  let mut T = [Gf(0); SYS_T + 1];
  let mut C = [Gf(0); SYS_T + 1];
  let mut B = [Gf(0); SYS_T + 1];

  let mut b = Gf(1);
  let mut d;
  let mut f;

  B[1].0 = 1;
  C[0].0 = 1;

  //

  for N in 0..2 * SYS_T
  //(N = 0; N < 2 * SYS_T; N++)
  {
    d = Gf(0);

    for i in 0..=std::cmp::min(N, SYS_T)
    //(i = 0; i <= min(N, SYS_T); i++)
    {
      d.0 ^= C[i].mul(s[N - i]).0; // gf_mul(C[i], s[ N-i]);
    }

    mne = d.0;
    mne = mne.wrapping_sub(1);
    mne >>= 15;
    mne = mne.wrapping_sub(1);
    mle = N as u16;
    mle = mle.wrapping_sub(2 * L);
    mle >>= 15;
    mle = mle.wrapping_sub(1);
    mle &= mne;

    for i in 0..=SYS_T
    //(i = 0; i <= SYS_T; i++)
    {
      T[i] = C[i];
    }

    f = b.frac(d); //gf_frac(b, d);

    for i in 0..=SYS_T
    //(i = 0; i <= SYS_T; i++)
    {
      C[i].0 ^= f.mul(B[i]).0 & mne //gf_mul(f, B[i]) & mne;
    }

    L = (L & !mle) | (((N as u16 + 1).wrapping_sub(L)) & mle);

    for i in 0..=SYS_T
    // (i = 0; i <= SYS_T; i++)
    {
      B[i].0 = (B[i].0 & !mle) | (T[i].0 & mle);
    }

    b.0 = (b.0 & !mle) | (d.0 & mle);

    for i in (1..=SYS_T).rev()
    //(i = SYS_T; i >= 1; i--)
    {
      B[i] = B[i - 1];
    }
    B[0].0 = 0;
  }

  for i in 0..=SYS_T
  //(i = 0; i <= SYS_T; i++)
  {
    out[i] = C[SYS_T - i];
  }
}
