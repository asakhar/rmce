use crate::impls::subroutines::{
    crypto_declassify::crypto_declassify,
    crypto_uint::{CryptoUint, CryptoUint64},
};

use super::params::{PK_NROWS, SYS_N};

fn is_equal_declassify(t: u64, u: u64) -> CryptoUint64 {
    let mut mask = CryptoUint(t).equal_mask(CryptoUint(u));
    crypto_declassify(&mut mask);
    mask
}

fn is_zero_declassify(t: u64) -> CryptoUint64 {
    let mut mask = CryptoUint(t).zero_mask();
    crypto_declassify(&mut mask);
    mask
}

fn ctz(inp: u64) -> u64 {
    inp.trailing_zeros() as u64
}

fn same_mask(x: u16, y: u16) -> u64 {
    let mut mask = x as u64 ^ y as u64;
    mask -= 1;
    mask >>= 63;
    mask = -(mask as i64) as u64;

    mask
}

fn mov_columns(mat: &mut [[u8; SYS_N / 8]], pi: &mut [i16], pivots: &mut [u64]) -> bool {
  todo!();
    let mut buf: [u64; 64] = [0; 64];
    let mut ctz_list: [u64; 32] = [0; 32];
    let mut one = 1u64;
    let mut row = PK_NROWS - 32;
    let block_idx = row / 8;
    pivots[0] = 0;
    let mut i = 0;
    while i < 32 {
        let mut t = buf[i];
        let mut j = i + 1;
        while j < 32 {
            t |= buf[j];
            j += 1;
        }
        if is_zero_declassify(t).0 != 0 {
            return false;
        }
        let s = ctz(t);
        ctz_list[i] = s;
        pivots[0] |= one << s;
        j = i + 1;
        while j < 32 {
            let mut mask = buf[i] >> s & 1;
            mask = (mask).wrapping_sub(1) as u64 as u64;
            buf[i as usize] ^= buf[j] & mask;
            j += 1;
        }
        j = i + 1;
        while j < 32 {
            let mut mask = buf[j as usize] >> s & 1;
            mask = mask.wrapping_neg();
            buf[j as usize] ^= buf[i] & mask;
            j += 1;
        }
        i += 1;
    }
    let mut j = 0;
    while j < 32 {
        let mut k = j + 1;
        while k < 64 {
            let mut d = (pi[row + j] ^ pi[row + k]) as u64;
            d &= same_mask(k as u16, ctz_list[j] as u16);
            pi[row + j] ^= d as i16;
            pi[row + k] ^= d as i16;
            k += 1;
        }
        j += 1;
    }

    // for i in 0..PK_NROWS {
    //   t = load8( &mat[ i ][ block_idx ] );
    //   for j in 0..32 {
    //         d = t >> j;
    //         d ^= t >> ctz_list[j as usize];
    //         d &= 1 as libc::c_int as libc::c_ulonglong;
    //         t ^= d << ctz_list[j as usize];
    //         t ^= d << j;
    //         j += 1;
    //     }
    // }
    true
}
