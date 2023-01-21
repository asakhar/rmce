use crate::impls::{
  libkeccak::shake256,
  me8192128f::{
    controlbits::control_bits_from_permutation,
    pk_gen::pk_gen,
    sk_gen::genpoly_gen,
    util::{load4, load_gf, store8, store_gf},
  },
};

use super::{
  decrypt::decrypt,
  encrypt::encrypt,
  gf::Gf,
  params::{COND_BYTES, GFBITS, IRR_BYTES, SYND_BYTES, SYS_N, SYS_T},
  CIPHER_TEXT_LEN, PLAIN_TEXT_LEN, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
};

pub fn crypto_kem_enc<F: Fn(&mut [u8])>(
  c: &mut [u8; CIPHER_TEXT_LEN],
  key: &mut [u8; PLAIN_TEXT_LEN],
  pk: &[u8; PUBLIC_KEY_LEN],
  random_bytes_generator: F,
) {
  let mut e = [0u8; SYS_N / 8];
  let mut one_ec = [1u8; 1 + SYS_N / 8 + SYND_BYTES];

  encrypt(c, pk, &mut e, random_bytes_generator);

  one_ec[1..1 + SYS_N / 8].copy_from_slice(&e);
  one_ec[1 + SYS_N / 8..].copy_from_slice(c);

  shake256(key, &one_ec);
}

pub fn crypto_kem_dec(
  key: &mut [u8; PLAIN_TEXT_LEN],
  c: &[u8; CIPHER_TEXT_LEN],
  sk: &[u8; SECRET_KEY_LEN],
) {
  let mut e = [0u8; SYS_N / 8];
  let mut preimage = [0u8; 1 + SYS_N / 8 + SYND_BYTES];
  let x = &mut preimage[..];
  let s = &sk[40 + IRR_BYTES + COND_BYTES..];

  let ret_decrypt = decrypt(&mut e, (&sk[40..40 + SYS_T * 2]).try_into().unwrap(), c);

  let mut m = ret_decrypt as u16;
  m = m.wrapping_sub(1);
  m >>= 8;
  let m = m as u8;

  let mut offset = 0;
  preimage[offset] = m & 1;
  offset += 1;
  for i in 0..SYS_N / 8 {
    preimage[offset] = (!m & s[i]) | (m & e[i]);
    offset += 1;
  }

  for i in 0..SYND_BYTES {
    preimage[offset] = c[i];
    offset += 1;
  }

  shake256(key, &preimage);
}

pub fn crypto_kem_keypair<F: Fn(&mut [u8])>(
  pk: &mut [u8; PUBLIC_KEY_LEN],
  sk: &mut [u8; SECRET_KEY_LEN],
  random_bytes_generator: F,
) {
  let mut seed = [64u8; 33];
  const SIZE_OF_R: usize = SYS_N / 8 + (1 << GFBITS) * 4 + SYS_T * 2 + 32;
  const LEN_OF_PERM: usize = 1 << GFBITS;
  const SIZE_OF_PERM: usize = LEN_OF_PERM * 4;
  let mut r = [0u8; SIZE_OF_R];

  let mut f = [Gf(0); SYS_T];
  let mut irr = [Gf(0); SYS_T];
  let mut perm = [0u32; LEN_OF_PERM];
  let mut pi = [0i16; LEN_OF_PERM];

  random_bytes_generator(&mut seed[1..]);

  loop {
    let mut roffset = SIZE_OF_R - 32;
    let mut skp = &mut sk[..];

    // expanding and updating the seed

    shake256(&mut r, &seed);
    skp[..32].copy_from_slice(&seed[1..]);
    skp = &mut skp[32 + 8..];
    seed[1..].copy_from_slice(&r[SIZE_OF_R - 32..]);

    // generating irreducible polynomial

    roffset -= SYS_T * 2;

    for i in 0..SYS_T {
      f[i] = load_gf(r[roffset + i * 2..roffset + i * 2 + 2].try_into().unwrap());
    }

    if !genpoly_gen(&mut irr, &f) {
      continue;
    }

    for i in 0..SYS_T {
      store_gf((&mut skp[i * 2..i * 2 + 2]).try_into().unwrap(), irr[i]);
    }

    // generating permutation

    roffset -= SIZE_OF_PERM;

    for i in 0..(1 << GFBITS) {
      let off = roffset + i * 4;
      perm[i] = load4(&r[off..off + 4].try_into().unwrap());
    }

    let mut pivots = 0;

    if !pk_gen(pk, (&*skp).try_into().unwrap(), &perm, &mut pi, &mut pivots) {
      continue;
    }

    skp = &mut skp[IRR_BYTES..];
    control_bits_from_permutation(skp, &pi, GFBITS, 1 << GFBITS);
    skp = &mut skp[COND_BYTES..];

    // storing the random string s

    roffset -= SYS_N / 8;
    skp.copy_from_slice(&r[roffset..roffset + SYS_N / 8]);

    // storing positions of the 32 pivots

    store8((&mut sk[32..]).try_into().unwrap(), pivots);
    break;
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn encrypts_decrypts() {
    let mut pk = vec![0u8; super::PUBLIC_KEY_LEN];
    let mut sk = vec![0u8; super::SECRET_KEY_LEN];
    crypto_kem_keypair(
      (&mut pk[..]).try_into().unwrap(),
      (&mut sk[..]).try_into().unwrap(),
      |data| openssl::rand::rand_bytes(data).unwrap(),
    );

    let mut c = vec![0u8; super::CIPHER_TEXT_LEN];
    let mut key = vec![0u8; super::PLAIN_TEXT_LEN];

    crypto_kem_enc(
      (&mut c[..]).try_into().unwrap(),
      (&mut key[..]).try_into().unwrap(),
      (&pk[..]).try_into().unwrap(),
      |data| openssl::rand::rand_bytes(data).unwrap(),
    );

    let mut key1 = vec![0u8; super::PLAIN_TEXT_LEN];

    crypto_kem_dec(
      (&mut key1[..]).try_into().unwrap(),
      (&c[..]).try_into().unwrap(),
      (&sk[..]).try_into().unwrap(),
    );

    assert_eq!(key1, key);
  }
}
