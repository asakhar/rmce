use rmce::*;

fn main() {
    // local
    let (pk, sk) = keypair();
    // remote
    let (ss, ps1) = pk.session();
    // local
    let ps2 = ss.open(sk);
    assert_eq!(ps1, ps2);
    println!("Hello");
}
