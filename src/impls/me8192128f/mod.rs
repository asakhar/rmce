mod params;
mod benes;
mod gf;
mod util;
mod transpose;
mod bm;
mod controlbits;
mod root;
mod synd;
mod decrypt;
mod encrypt;
mod operations;
mod sk_gen;
mod pk_gen;

pub const PUBLIC_KEY_LEN: usize = 1357824;
pub const SECRET_KEY_LEN: usize = 14120;
pub const CIPHER_TEXT_LEN: usize = 208;
pub const PLAIN_TEXT_LEN: usize = 32;