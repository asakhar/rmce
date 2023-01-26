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

pub(crate) use util::BoxedArrayExt;

use self::params::{PK_ROW_BYTES, PK_NROWS, SYND_BYTES, SYS_N, COND_BYTES, IRR_BYTES}; 
pub const PUBLIC_KEY_LEN: usize = PK_NROWS*PK_ROW_BYTES;
pub const SECRET_KEY_LEN: usize = 40 + IRR_BYTES + COND_BYTES + SYS_N/8;
pub const CIPHER_TEXT_LEN: usize = SYND_BYTES;
