use rmce::*;

#[test]
fn validate_plain_secret() {
  let keypair_randombytes = include!("resources/keypair_randombytes.in");
  let encrypt_randombytes = include!("resources/encrypt_randombytes.in");
  let results = include!("resources/results.in");
  for ((k, e), r) in keypair_randombytes
    .iter()
    .zip(encrypt_randombytes)
    .zip(results)
  {
    let (pk, sk) = generate_keypair_with_entropy_provider(|data| {
      data.copy_from_slice(k);
    });

    let (ct, ss) = pk.session_with_entropy_provider(|data| {
      data.copy_from_slice(&e);
    });

    let ss1 = ct.open(&sk);

    assert_eq!(ss1, ss);
    assert_eq!(ss.as_bytes(), &r);
  }
}
