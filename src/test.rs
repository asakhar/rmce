use rmce::*;

fn main() {
  // // local
  // let (pk, sk) = keypair();
  // // remote
  // let (ss, ps1) = pk.session();
  // // local
  // let ps2 = ss.open(&sk);
  // assert_eq!(ps1, ps2);

  test(/*pk, sk*/);
}

extern "C" {
  fn randombytes_init(
    entropy_input: *mut u8,
    personalization_string: *mut u8,
    security_strength: i32,
  );
  fn randombytes(x: *mut u8, xlen: u64) -> i32;
}

fn test(/*pk: PublicKey, sk: SecretKey*/) {
  let mut entropy_input: [u8; 48] = std::array::from_fn(|i| i as u8);
  unsafe { randombytes_init(entropy_input.as_mut_ptr(), 0 as _, 256) };
  let mut seed = [0u8; 48];
  unsafe { randombytes(seed.as_mut_ptr(), 48) };
  
  unsafe { randombytes_init(seed.as_mut_ptr(), 0 as _, 256) };

  use impls::me8192128f::operations::*;
  use impls::me8192128f::*;
  let mut pk = vec![0u8; PUBLIC_KEY_LEN];
  let mut sk = vec![0u8; SECRET_KEY_LEN];
  crypto_kem_keypair(
    (&mut pk[..]).try_into().unwrap(),
    (&mut sk[..]).try_into().unwrap(),
    |data| {
      // openssl::rand::rand_bytes(data).unwrap()
      unsafe { randombytes(data.as_mut_ptr(), data.len() as u64) };
    },
  );

  println!("there");

  let mut c = vec![0u8; CIPHER_TEXT_LEN];
  let mut key = vec![0u8; PLAIN_TEXT_LEN];

  crypto_kem_enc(
    (&mut c[..]).try_into().unwrap(),
    (&mut key[..]).try_into().unwrap(),
    (&pk[..]).try_into().unwrap(),
    |data| openssl::rand::rand_bytes(data).unwrap(),
  );

  let mut key1 = vec![0u8; PLAIN_TEXT_LEN];

  crypto_kem_dec(
    (&mut key1[..]).try_into().unwrap(),
    (&c[..]).try_into().unwrap(),
    (&sk[..]).try_into().unwrap(),
  );

  assert_eq!(key1, key);
}
