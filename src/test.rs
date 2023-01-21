use rmce::*;

fn main() {
    // local
    let (pk, sk) = keypair();
    // remote
    let (ss, ps1) = pk.session();
    // local
    let ps2 = ss.open(sk);
    assert_eq!(ps1, ps2);

    test();
}

fn test() {
    use impls::me8192128f::*;
    use impls::me8192128f::operations::*;
    let mut pk = vec![0u8; PUBLIC_KEY_LEN];
    let mut sk = vec![0u8; SECRET_KEY_LEN];
    crypto_kem_keypair((&mut pk[..]).try_into().unwrap(), (&mut sk[..]).try_into().unwrap(), |data|{
    openssl::rand::rand_bytes(data).unwrap()
    });

    let mut c = vec![0u8; CIPHER_TEXT_LEN];
    let mut key = vec![0u8; PLAIN_TEXT_LEN];

    crypto_kem_enc((&mut c[..]).try_into().unwrap(), (&mut key[..]).try_into().unwrap(), (&pk[..]).try_into().unwrap(), |data|{
    openssl::rand::rand_bytes(data).unwrap()
    });

    let mut key1 = vec![0u8; PLAIN_TEXT_LEN];

    crypto_kem_dec((&mut key1[..]).try_into().unwrap(), (&c[..]).try_into().unwrap(), (&sk[..]).try_into().unwrap());

    assert_eq!(key1, key);

}