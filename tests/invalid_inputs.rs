use rmce::*;

#[test]
fn invalid_sharable_secret_input() {
  let keypair_randombytes = include!("resources/keypair_randombytes.in");
  let encrypt_randombytes = include!("resources/encrypt_randombytes.in");
  for (k, e) in keypair_randombytes.iter().zip(encrypt_randombytes) {
    let (pk, sk) = generate_keypair_with_entropy_provider(
      |data| {
        data.copy_from_slice(k);
      },
    );

    let (ct, ss) = pk.session_with_entropy_provider(|data| {
      data.copy_from_slice(&e);    
    });

    let mut ct_altered: [u8; ShareableSecret::SIZE] = ct.into();
    ct_altered[2] = ct_altered[2].wrapping_add(1);
    let ct_altered: ShareableSecret = ct_altered.into();
  
    let ss1 = ct_altered.open(&sk);
    
    test_avalanche_effect(ss, ss1);
  }
}

fn test_avalanche_effect(ss: PlainSecret, ss1: PlainSecret) {
  let mut score = 0;
  for (s1, s2) in ss.as_bytes().iter().zip(ss1.as_bytes()) {
    score += (s1 == s2) as usize;
  }
  const HIGHEST_SCORE: usize = 2;
  assert!(score < HIGHEST_SCORE, "{score} bytes of wrong PlainSecret was equal to true PlainSecret. Threshold: {HIGHEST_SCORE}.\nTrue : {ss:?}\nWrong: {ss1:?}\n")
}