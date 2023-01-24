// Source: https://classic.mceliece.org/nist.html
// Round-4 submission: https://classic.mceliece.org/nist/mceliece-20221023.tar.gz

// This is reimplementation in Rust of 4-th round submission of Classic McEliece to NIST in C
// Currently implemented only optimized/mceliece8192128f

// Implementations of other key lengths are not so much different, so i am looking for a way to organize implementation
// without massive copy-pasting. Rn my idea is to use const generics

mod benes;
mod bm;
mod controlbits;
mod decrypt;
mod encrypt;
mod gf;
pub mod operations;
mod params;
mod pk_gen;
mod root;
mod sk_gen;
mod synd;
mod transpose;
mod util;

pub const PUBLIC_KEY_LEN: usize = 1357824;
pub const SECRET_KEY_LEN: usize = 14120;
pub const CIPHER_TEXT_LEN: usize = 208;
pub const PLAIN_TEXT_LEN: usize = 32;
