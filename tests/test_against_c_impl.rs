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
  crypto_kem_keypair(
    (&mut pk[..]).try_into().unwrap(),
    (&mut sk[..]).try_into().unwrap(),
    |data| {
      data.copy_from_slice(&[
        124, 153, 53, 160, 176, 118, 148, 170, 12, 109, 16, 228, 219, 107, 26, 221, 47, 216, 26,
        37, 204, 177, 72, 3, 45, 205, 115, 153, 54, 115, 127, 45,
      ]);
    },
  );

  let mut c = [0u8; CIPHER_TEXT_LEN];
  let mut key = [0u8; PLAIN_TEXT_LEN];

  crypto_kem_enc(&mut c, &mut key, (&pk[..]).try_into().unwrap(), |data| {
    data.copy_from_slice(&[
      142, 13, 12, 10, 123, 96, 163, 186, 220, 138, 36, 166, 229, 71, 226, 68, 195, 217, 65, 120,
      239, 253, 30, 155, 141, 144, 68, 50, 175, 253, 45, 93, 145, 156, 207, 12, 135, 48, 235, 68,
      46, 1, 122, 156, 0, 200, 97, 204, 117, 237, 24, 58, 62, 156, 204, 226, 3, 229, 171, 43, 107,
      178, 55, 116, 192, 185, 84, 193, 118, 10, 95, 116, 187, 102, 179, 22, 222, 127, 41, 53, 204,
      18, 94, 196, 60, 5, 22, 128, 199, 192, 137, 108, 22, 2, 21, 44, 104, 87, 157, 54, 222, 205,
      253, 19, 69, 43, 179, 147, 142, 36, 137, 54, 255, 155, 143, 87, 11, 160, 138, 254, 112, 253,
      129, 158, 5, 30, 30, 81, 197, 69, 151, 208, 84, 238, 227, 166, 132, 181, 76, 35, 44, 229, 83,
      14, 15, 5, 49, 204, 226, 129, 225, 100, 81, 200, 228, 99, 72, 106, 13, 93, 249, 113, 248,
      231, 147, 106, 59, 64, 221, 140, 243, 204, 195, 97, 36, 186, 126, 37, 12, 252, 69, 181, 82,
      77, 203, 36, 27, 211, 54, 181, 28, 2, 8, 81, 52, 118, 74, 100, 174, 127, 72, 227, 21, 15,
      221, 210, 198, 101, 5, 196, 57, 43, 202, 47, 92, 83, 196, 6, 192, 223, 127, 254, 206, 178,
      138, 14, 71, 193, 24, 133, 154, 192, 74, 223, 159, 145, 142, 143, 2, 226, 15, 73, 113, 191,
      37, 107, 219, 61, 177, 167, 247, 104, 95, 110, 138, 205,
    ]);    
  });

  let mut key1 = [0u8; PLAIN_TEXT_LEN];

  crypto_kem_dec(&mut key1, &c, (&sk[..]).try_into().unwrap());
  let expected = [
    188, 30, 146, 251, 211, 75, 121, 7, 192, 250, 37, 104, 197, 229, 250, 147, 106, 247, 166, 240,
    194, 238, 100, 43, 223, 199, 96, 216, 148, 104, 63, 146,
  ];
  
  assert_eq!(key1, key);
  assert_eq!(key, expected);
}

#[test]
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