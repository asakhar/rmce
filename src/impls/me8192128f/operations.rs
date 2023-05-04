use boxed_array::from_default;

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
  util::{AsMutArray, AsRefArray},
  CIPHER_TEXT_LEN, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
};

pub fn crypto_kem_enc<F: FnMut(&mut [u8])>(
  c: &mut [u8; CIPHER_TEXT_LEN],
  key: &mut [u8],
  pk: &[u8; PUBLIC_KEY_LEN],
  random_bytes_generator: F,
) {
  let mut e: Box<[u8; SYS_N / 8]> = from_default();
  let mut one_ec = vec![1u8; 1 + SYS_N / 8 + SYND_BYTES].into_boxed_slice();

  encrypt(c, pk, &mut e, random_bytes_generator);

  one_ec[1..1 + SYS_N / 8].copy_from_slice(e.as_ref());
  one_ec[1 + SYS_N / 8..].copy_from_slice(c);

  shake256(key, &one_ec);
}

pub fn crypto_kem_dec(key: &mut [u8], c: &[u8; CIPHER_TEXT_LEN], sk: &[u8; SECRET_KEY_LEN]) {
  let mut e: Box<[u8; SYS_N / 8]> = from_default();
  let mut preimage = vec![0u8; 1 + SYS_N / 8 + SYND_BYTES].into_boxed_slice();
  let s = &sk[40 + IRR_BYTES + COND_BYTES..];

  let ret_decrypt = decrypt(&mut e, sk.as_ref_array(40), c);

  let mut m = ret_decrypt;
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

const SIZE_OF_R: usize = SYS_N / 8 + (1 << GFBITS) * std::mem::size_of::<u32>() + SYS_T * 2 + 32;
const LEN_OF_PERM: usize = 1 << GFBITS;
const SIZE_OF_PERM: usize = LEN_OF_PERM * std::mem::size_of::<u32>();

pub fn crypto_kem_keypair<F: FnMut(&mut [u8])>(
  pk: &mut [u8; PUBLIC_KEY_LEN],
  sk: &mut [u8; SECRET_KEY_LEN],
  mut random_bytes_generator: F,
) {
  let mut seed = [64u8; 33];
  let mut r: Box<[u8; SIZE_OF_R]> = from_default();

  let mut f = [Gf(0); SYS_T];
  let mut irr = [Gf(0); SYS_T];
  let mut perm: Box<[u32; LEN_OF_PERM]> = from_default();
  let mut pi: Box<[i16; LEN_OF_PERM]> = from_default();

  random_bytes_generator(&mut seed[1..]);

  loop {
    let mut roffset = SIZE_OF_R - 32;
    let mut skoffset = 0;

    // expanding and updating the seed

    shake256(r.as_mut_slice(), &seed);
    sk[..32].copy_from_slice(&seed[1..]);
    skoffset += 32 + 8;
    seed[1..].copy_from_slice(&r[SIZE_OF_R - 32..]);

    // generating irreducible polynomial

    roffset -= SYS_T * std::mem::size_of::<Gf>();

    for i in 0..SYS_T {
      f[i] = load_gf(r.as_ref_array(roffset + i * 2));
    }

    if !genpoly_gen(&mut irr, &f) {
      continue;
    }

    for i in 0..SYS_T {
      store_gf(sk.as_mut_array(skoffset + i * 2), irr[i]);
    }

    // generating permutation

    roffset -= SIZE_OF_PERM;

    for i in 0..(1 << GFBITS) {
      perm[i] = load4(r.as_ref_array(roffset + i * 4));
    }

    let mut pivots = 0;

    if !pk_gen(pk, sk.as_ref_array(skoffset), &perm, &mut pi, &mut pivots) {
      continue;
    }

    skoffset += IRR_BYTES;
    control_bits_from_permutation(sk.as_mut_array(skoffset), &*pi);
    skoffset += COND_BYTES;

    // storing the random string s

    roffset -= SYS_N / 8;
    sk[skoffset..skoffset + SYS_N / 8].copy_from_slice(&r[roffset..roffset + SYS_N / 8]);

    // storing positions of the 32 pivots

    store8(sk.as_mut_array(32), pivots);
    break;
  }
}
