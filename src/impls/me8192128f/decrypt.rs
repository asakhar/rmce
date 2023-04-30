/*
  This file is for Nieddereiter decryption
*/

use boxed_array::from_default;

use super::{
  benes::support_gen,
  bm::bm,
  gf::Gf,
  params::{COND_BYTES, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T},
  root::root,
  synd::synd,
  util::{load_gf, AsRefArray},
};

/* Niederreiter decryption with the Berlekamp decoder */
/* intput: sk, secret key */
/*         c, ciphertext */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
#[allow(non_snake_case)]
pub fn decrypt(
  e: &mut [u8; SYS_N / 8],
  sk: &[u8; IRR_BYTES + COND_BYTES],
  c: &[u8; SYND_BYTES],
) -> u16 {
  let mut w = 0;
  let mut check: u16;

  let mut r: Box<[u8; SYS_N / 8]> = from_default();

  let mut g = [Gf(0); SYS_T + 1];
  let mut L: Box<[Gf; SYS_N]> = from_default();

  let mut s = [Gf(0); SYS_T * 2];
  let mut s_cmp = [Gf(0); SYS_T * 2];
  let mut locator = [Gf(0); SYS_T + 1];
  let mut images :Box<[Gf; SYS_N]> = from_default();

  //

  for i in 0..SYND_BYTES {
    r[i] = c[i];
  }

  for i in 0..SYS_T {
    g[i] = load_gf(sk.as_ref_array(i*2));
  }
  g[SYS_T] = Gf(1);

  support_gen(&mut L, sk.as_ref_array(IRR_BYTES));

  synd(&mut s, &g, &L, &r);

  bm(&mut locator, &s);

  root(&mut images, &locator, &L);

  //

  e.fill(0);

  for i in 0..SYS_N {
    let t = images[i].is_zero().0 & 1;

    e[i / 8] |= (t << (i % 8)) as u8;
    w += t;
  }

  synd(&mut s_cmp, &g, &L, e);

  //

  check = w;
  check ^= SYS_T as u16;

  for i in 0..SYS_T * 2 {
    check |= s[i].0 ^ s_cmp[i].0;
  }

  check = check.wrapping_sub(1);
  check >>= 15;

  check ^ 1
}
