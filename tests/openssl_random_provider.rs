
#[cfg(feature = "openssl")]
#[test]
fn validate_plain_secret() {
  use rmce::*;
  for _ in 0..20 {
    let (pk, sk) = generate_keypair();

    let (ct, ss) = pk.session();

    let ss1 = ct.open(&sk);

    assert_eq!(ss1, ss);
  }
}
