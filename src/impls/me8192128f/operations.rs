use crate::impls::{libkeccak::shake256, me8192128f::{util::{load_gf, store_gf, load4}, sk_gen::genpoly_gen}};

use super::{PUBLIC_KEY_LEN, params::{SYS_N, SYND_BYTES, IRR_BYTES, COND_BYTES, SYS_T, GFBITS}, encrypt::encrypt, PLAIN_TEXT_LEN, SECRET_KEY_LEN, decrypt::decrypt, CIPHER_TEXT_LEN, gf::Gf};

pub fn crypto_kem_enc<F: Fn(&mut [u8])>(c: &mut [u8; CIPHER_TEXT_LEN], key: &mut [u8; PLAIN_TEXT_LEN], pk: &[u8; PUBLIC_KEY_LEN], random_bytes_generator: F) {
  let mut e = [0u8; SYS_N/8];
  let mut one_ec = [1u8; 1+SYS_N/8+SYND_BYTES];

  encrypt(c, pk, &mut e, random_bytes_generator);

  one_ec[1..1+SYS_N/8].copy_from_slice(&e);
  one_ec[1+SYS_N/8..].copy_from_slice(c);

  shake256(key, &one_ec);
}

pub fn crypto_kem_dec(key: &mut [u8; PLAIN_TEXT_LEN], c: &[u8; CIPHER_TEXT_LEN], sk: &[u8; SECRET_KEY_LEN]) {
  let mut e = [0u8; SYS_N/8];
  let mut preimage = [0u8; 1+SYS_N/8+SYND_BYTES];
  let mut x = &mut preimage[..];
  let mut s = &sk[40+IRR_BYTES+COND_BYTES..];

  let ret_decrypt = decrypt(& mut e, (&sk[40..40+SYS_T*2]).try_into().unwrap(), c);

  let mut m = ret_decrypt as u16;
  m = m.wrapping_sub(1);
  m >>= 8;
  let m = m as u8;

  let mut offset = 0;
  preimage[offset] = m & 1;
  offset += 1;
  for i in 0.. SYS_N/8 {
    preimage[offset] = (!m & s[i]) | (m & e[i]);
    offset += 1;
  }

  for i in 0..SYND_BYTES {
    preimage[offset] = c[i];
    offset += 1;
  }

  shake256(key, &preimage);
}

pub fn crypto_kem_keypair<F: Fn(&mut [u8])>(pk: &mut [u8; PUBLIC_KEY_LEN], sk: &mut [u8; SECRET_KEY_LEN], random_bytes_generator: F) {
  let mut seed = [64u8; 33];
  const SIZE_OF_R: usize = SYS_N/8+(1<<GFBITS)*4 + SYS_T*2 + 32;
  const LEN_OF_PERM: usize = 1 << GFBITS;
  const SIZE_OF_PERM: usize = LEN_OF_PERM*4;
  let mut r = [0u8; SIZE_OF_R];
  
  let mut f = [Gf(0); SYS_T];
  let mut irr = [Gf(0); SYS_T];
  let mut perm = [0u32; LEN_OF_PERM];
  let mut pi = [0u16; 1<< GFBITS];

  random_bytes_generator(&mut seed[1..]);

  let mut roffset;
  let mut skp;

  loop {
    roffset = SIZE_OF_R-32;
    skp = &mut sk[..];

    // expanding and updating the seed

    shake256(&mut r, &seed);
    skp[..32].copy_from_slice(&seed[1..]);
    skp = &mut skp[32+8..];
    seed[1..].copy_from_slice(&r[SIZE_OF_R-32..]);

    // generating irreducible polynomial

    roffset -= SYS_T * 2;

    for i in 0..SYS_T {
      f[i] = load_gf(r[roffset + i*2..roffset+i*2+2].try_into().unwrap());
    }

    if !genpoly_gen(&mut irr, &f) {
      continue;
    }

    for i in 0..SYS_T {
      store_gf((&mut skp[i*2..i*2+2]).try_into().unwrap(), irr[i]);
    }

    skp = &mut skp[IRR_BYTES..];

    // generating permutation

    roffset -= SIZE_OF_PERM;

    for i in 0.. (1<<GFBITS) {
      let off = roffset + i*4;
      perm[i] = load4(&r[off..off+4].try_into().unwrap());
    }

    // if pk_gen
    todo!()
  }
}