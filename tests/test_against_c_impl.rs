use rmce::*;

extern "C" {
  fn randombytes_init(
    entropy_input: *mut u8,
    personalization_string: *mut u8,
    security_strength: i32,
  );
  fn randombytes(x: *mut u8, xlen: u64) -> i32;
}

#[cfg(test)]
#[test]
fn test() {
  use impls::me8192128f::operations::*;
  use impls::me8192128f::*;
  let mut pk = vec![0u8; PUBLIC_KEY_LEN];
  let mut sk = vec![0u8; SECRET_KEY_LEN];
  let keypair_randombytes = include!("keypair_randombytes.txt");
  let encrypt_randombytes = include!("encrypt_randombytes.txt");
  let results = include!("results.txt");
  for ((k, e), r) in keypair_randombytes.iter().zip(encrypt_randombytes).zip(results) {
    crypto_kem_keypair(
      (&mut pk[..]).try_into().unwrap(),
      (&mut sk[..]).try_into().unwrap(),
      |data| {
        data.copy_from_slice(k);
      },
    );
  
    let mut c = [0u8; CIPHER_TEXT_LEN];
    let mut key = [0u8; PLAIN_TEXT_LEN];
  
    crypto_kem_enc(&mut c, &mut key, (&pk[..]).try_into().unwrap(), |data| {
      data.copy_from_slice(&e);    
    });
  
    let mut key1 = [0u8; PLAIN_TEXT_LEN];
  
    crypto_kem_dec(&mut key1, &c, (&sk[..]).try_into().unwrap());
    
    assert_eq!(key1, key);
    assert_eq!(key, r);
  }
}

// #[test]
fn generate_tests() {
  const KATNUM: usize = 20;
  let mut buf = [0u8; 32];
  openssl::rand::rand_bytes(&mut buf).unwrap();
  println!("random from openssl: {buf:?}");
  let mut entropy_input: [u8; 48] = std::array::from_fn(|i| i as u8);
  unsafe { randombytes_init(entropy_input.as_mut_ptr(), 0 as _, 256) };
  let mut seeds = [[0u8; 48]; KATNUM];
  for seed in &mut seeds {
    unsafe { randombytes(seed.as_mut_ptr(), 48) };
  }
  let mut keypair_randombytes = [[0u8; 32]; KATNUM];
  let mut encrypt_randombytes = [[0u8; 256]; KATNUM];
  let mut results = [[0u8; 32]; KATNUM];

  for (i, seed) in seeds.iter_mut().enumerate() {
    println!("generating kat #{i}");
    unsafe { randombytes_init(seed.as_mut_ptr(), 0 as _, 256) };
  
    use impls::me8192128f::operations::*;
    use impls::me8192128f::*;
    let mut pk = vec![0u8; PUBLIC_KEY_LEN];
    let mut sk = vec![0u8; SECRET_KEY_LEN];
    crypto_kem_keypair(
      (&mut pk[..]).try_into().unwrap(),
      (&mut sk[..]).try_into().unwrap(),
      |data| {
        unsafe { randombytes(data.as_mut_ptr(), data.len() as u64) };
        keypair_randombytes[i].copy_from_slice(data);
      },
    );
  
    let mut c = [0u8; CIPHER_TEXT_LEN];
    let mut key = [0u8; PLAIN_TEXT_LEN];
  
    crypto_kem_enc(&mut c, &mut key, (&pk[..]).try_into().unwrap(), |data| {
      unsafe { randombytes(data.as_mut_ptr(), data.len() as u64) };
      encrypt_randombytes[i].copy_from_slice(data);
    });
  
    let mut key1 = [0u8; PLAIN_TEXT_LEN];
  
    crypto_kem_dec(&mut key1, &c, (&sk[..]).try_into().unwrap());

    assert_eq!(key1, key);
    results[i].copy_from_slice(&key);
  }
  let mut file = std::fs::File::create("keypair_randombytes.txt").unwrap();
  use std::io::Write;
  writeln!(file, "{keypair_randombytes:?}").unwrap();
  drop(file);
  let mut file = std::fs::File::create("encrypt_randombytes.txt").unwrap();
  writeln!(file, "{encrypt_randombytes:?}").unwrap();
  drop(file);
  let mut file = std::fs::File::create("results.txt").unwrap();
  writeln!(file, "{results:?}").unwrap();
}