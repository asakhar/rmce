
#[cfg(feature = "openssl")]
#[test]
fn validate_plain_secret() {
  use rmce::*;
  for _ in 0..20 {
    let (pk, sk) = generate_keypair();

    let (ct, ss) = pk.session(32);

    let ss1 = ct.open(32, &sk);

    assert_eq!(ss1, ss);
  }
}
