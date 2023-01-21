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
