use super::{params::{SYS_N, SYS_T, SYND_BYTES}, gf::Gf, util::load_gf, benes::support_gen, bm::bm, synd::synd, root::root};


/* Niederreiter decryption with the Berlekamp decoder */
/* intput: sk, secret key */
/*         c, ciphertext */
/* output: e, error vector */
/* return: 0 for success; 1 for failure */
pub fn decrypt(e: &mut[u8; SYS_N/8], sk: &[u8; SYS_T*2], c: &[u8; SYND_BYTES]) -> bool {
  let mut w = 0;
  let mut check: u16;
  
  let mut r = [0u8; SYS_N/8];

  let mut g = [Gf(0); SYS_T+1];
  let mut L = [Gf(0); SYS_N];
  
  let mut s = [Gf(0); SYS_T*2];
  let mut s_cmp = [Gf(0); SYS_T*2];
  let mut locator = [Gf(0); SYS_T+1];
  let mut images = [Gf(0); SYS_N];

  //

  for i in 0..SYND_BYTES {
    r[i] = c[i];
  }

  for i in 0..SYS_T {
    g[i] = load_gf(sk[i*2..i*2+2].try_into().unwrap());
  }
  g[SYS_T] = Gf(1);

  support_gen(&mut L, sk);

  synd(&mut s, &g, L, &r);

  bm(&mut locator, (&s[..SYS_T+1]).try_into().unwrap());

  root(&mut images, &locator, &L);

  //

  e.fill(0);

  for i in 0..SYS_N {
    let t = images[i].is_zero().0 & 1;

    e[i/8] |= (t << (i%8)) as u8;
    w += t;
  }

  synd(&mut s_cmp, &g, L, e);

  //

  check = w;
  check ^= SYS_T as u16;

  for i in 0..SYS_T*2 {
    check |= s[i].0 ^ s_cmp[i].0;
  }

  check -= 1;
  check >>= 15;

  check == 1 
}