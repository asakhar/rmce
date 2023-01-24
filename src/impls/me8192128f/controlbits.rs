/* This file is for implementing the Nassimi-Sahni algorithm */
/* See David Nassimi, Sartaj Sahni "Parallel algorithms to set up the Benes permutationnetwork" */
/* See also https://cr.yp.to/papers/controlbits-20200923.pdf */

use crate::impls::{
  int32_sort,
  subroutines::{crypto_declassify::crypto_declassify, crypto_int::CryptoInt},
};

use super::params::{COND_BYTES, GFBITS};

/* parameters: 1 <= w <= 14; n = 2^w */
/* input: permutation pi of {0,1,...,n-1} */
/* output: (2m-1)n/2 control bits at positions 0,1,... */
/* output position pos is by definition 1&(out[pos/8]>>(pos&7)) */
pub fn control_bits_from_permutation(
  out: &mut [u8; COND_BYTES],
  pi: &[i16; 1 << GFBITS]
) {
  const N: usize = 1<<GFBITS;
  let mut temp = vec![0i32; 2 * N];
  let mut pi_test = vec![0i16; N];
  loop {
    out.fill(0);
    cbrecursion(out, 0, 1, pi, GFBITS, N, &mut temp);

    // check for correctness

    for i in 0..N {
      pi_test[i] = i as i16;
    }
    let mut ooff = 0;
    for i in 0..GFBITS {
      layer(&mut pi_test, &out[ooff..], i, N);
      ooff += N >> 4;
    }

    for i in (0..=GFBITS - 2).rev() {
      layer(&mut pi_test, &out[ooff..], i, N);
      ooff += N >> 4;
    }

    let mut diff = 0;
    for i in 0..N {
      diff |= pi[i] ^ pi_test[i];
    }

    diff = CryptoInt(diff).nonzero_mask().0;
    crypto_declassify(&mut diff);
    if diff == 0 {
      break;
    }
  }
}

/* parameters: 1 <= w <= 14; n = 2^w */
/* input: permutation pi of {0,1,...,n-1} */
/* output: (2m-1)n/2 control bits at positions pos,pos+step,... */
/* output position pos is by definition 1&(out[pos/8]>>(pos&7)) */
/* caller must 0-initialize positions first */
/* temp must have space for int32[2*n] */
#[allow(non_snake_case)]
fn cbrecursion(
  out: &mut [u8],
  mut pos: usize,
  step: usize,
  pi: &[i16],
  w: usize,
  n: usize,
  temp: &mut [i32],
) {
  use cfor::cfor;
  macro_rules! A {
    () => {
      temp
    };
    [$idx:expr] => {
      temp[$idx]
    }
  }
  macro_rules! B {
    () => {
      temp[n..]
    };
    [$idx:expr] => {
      temp[n..][$idx]
    }
  }

  if w == 1 {
    out[pos >> 3] ^= (pi[0] << (pos & 7)) as u8;
    return;
  }

  cfor! (let mut x = 0;x < n;x+=1; {A![x] = (((pi[x]^1) as i32) << 16)|pi[x^1] as i32});
  int32_sort::sort(&mut A![..n]);

  cfor! (let mut x = 0;x < n;x+=1; {
    let Ax = A![x];
    let px = Ax&0xffff;
    let cx = CryptoInt(px).min(CryptoInt(x as i32)).0;
    B![x] = (px<<16)|cx;
  });

  cfor! (let mut x = 0;x < n;x+=1; {A![x] = (A![x]<<16)|x as i32});
  int32_sort::sort(&mut A![..n]);

  cfor! (let mut x = 0;x < n;x+=1; {A![x] = (A![x]<<16)+(B![x]>>16)});
  int32_sort::sort(&mut A![..n]);

  if w <= 10 {
    cfor! (let mut x = 0;x < n;x+=1; {B![x] = ((A![x]&0xffff)<<10)|(B![x]&0x3ff)});

    cfor! (let mut i = 1;i < w-1;i+=1; {


      cfor! (let mut x = 0;x < n;x+=1; {A![x] = ((B![x]&!0x3ff)<<6)|x as i32});
      int32_sort::sort(&mut A![..n]);

      cfor! (let mut x = 0;x < n;x+=1; {A![x] = (A![x]<<20)|B![x]});
      int32_sort::sort(&mut A![..n]);

      cfor! (let mut x = 0;x < n;x+=1; {
        let ppcpx = A![x]&0xfffff;
        let ppcx = (A![x]&0xffc00)|(B![x]&0x3ff);
        B![x] = CryptoInt(ppcx).min(CryptoInt(ppcpx)).0;
      });
    });
    cfor! (let mut x = 0;x < n;x+=1; {B![x] &= 0x3ff});
  } else {
    cfor! (let mut x = 0;x < n;x+=1; {B![x] = (A![x]<<16)|(B![x]&0xffff)});

    cfor! (let mut i = 1;i < w-1;i+=1; {


      cfor! (let mut x = 0;x < n;x+=1; {A![x] = (B![x]&!0xffff)|x as i32});
      int32_sort::sort(&mut A![..n]);

      cfor! (let mut x = 0;x < n;x+=1; {A![x] = (A![x]<<16)|(B![x]&0xffff)});


      if i < w-2 {
        cfor! (let mut x = 0;x < n;x+=1; {B![x] = (temp[x]&!0xffff)|(temp[x+n]>>16)});

        int32_sort::sort(&mut B![..n]);
        cfor! (let mut x = 0;x < n;x+=1; {B![x] = (B![x]<<16)|(A![x]&0xffff)});

      }

      int32_sort::sort(&mut A![..n]);

      cfor! (let mut x = 0;x < n;x+=1; {
        let cpx = (B![x]&!0xffff)|(A![x]&0xffff);
        temp[x+n] = CryptoInt(B![x]).min(CryptoInt(cpx)).0;
      });
    });
    cfor! (let mut x = 0;x < n;x+=1; {B![x] &= 0xffff});
  }

  cfor! (let mut x = 0;x < n;x+=1; {A![x] = ((pi[x] as i32)<<16)+(x as i32)});
  int32_sort::sort(&mut A![..n]);

  cfor! (let mut j = 0;j < n/2;j+=1; {
    let x = 2*j;
    let fj = B![x]&1;
    let Fx = x as i32 + fj;
    let Fx1 = Fx^1;

    out[pos>>3] ^= (fj<<(pos&7)) as u8;
    pos += step;

    B![x] = (A![x]<<16)|Fx;
    B![x+1] = (A![x+1]<<16)|Fx1;
  });

  int32_sort::sort(&mut B![..n]);

  pos += (2 * w - 3) * step * (n / 2);

  cfor! (let mut k = 0;k < n/2;k+=1; {
    let y = 2*k;
    let lk = B![y]&1;
    let Ly = y as i32 + lk;
    let Ly1 = Ly^1;

    out[pos>>3] ^= (lk<<(pos&7)) as u8;
    pos += step;

    A![y] = (Ly<<16)|(B![y]&0xffff);
    A![y+1] = (Ly1<<16)|(B![y+1]&0xffff);
  });

  int32_sort::sort(&mut A![..n]);

  pos -= (2 * w - 2) * step * (n / 2);

  // part below looks very bad, TODO: implement in another way
  // C analogue:
  //   #define q ((int16 *) (temp+n+n/4))
  //
  // q can start anywhere between temp+n and temp+n/2

  cfor! (let mut j = 0;j < n/2;j+=1; {
    // q[j] = (temp[2*j]&0xffff)>>1
    let val =
    (temp[2*j]&0xffff)>>1;
    let offset = &mut temp[n+n/4..];
    // Safety: i32 and i16 are primitive so cast between their slices is fine, length doubles
    let reinterpreted = unsafe {std::slice::from_raw_parts_mut(offset.as_mut_ptr() as *mut i16, offset.len() * std::mem::size_of::<i32>()/std::mem::size_of::<i16>()) };
    reinterpreted[j] = val as i16;

    // q[j+n/2] = (temp[2*j+1]&0xffff)>>1;
    let val = (temp[2*j+1]&0xffff)>>1;
    let offset = &mut temp[n+n/4..];
    let reinterpreted = unsafe {std::slice::from_raw_parts_mut(offset.as_mut_ptr() as *mut i16, offset.len() * std::mem::size_of::<i32>()/std::mem::size_of::<i16>()) };
    reinterpreted[j+n/2] = val as i16;
  });

  let (r, l) = temp.split_at_mut(n + n / 4);
  let q = unsafe {
    std::slice::from_raw_parts(
      l.as_mut_ptr() as *const i16,
      l.len() * std::mem::size_of::<i32>() / std::mem::size_of::<i16>(),
    )
  };
  cbrecursion(out, pos, step * 2, q, w - 1, n / 2, r);
  cbrecursion(out, pos + step, step * 2, &q[n / 2..], w - 1, n / 2, r);
}

/* input: p, an array of int16 */
/* input: n, length of p */
/* input: s, meaning that stride-2^s cswaps are performed */
/* input: cb, the control bits */
/* output: the result of apply the control bits to p */
fn layer(p: &mut [i16], cb: &[u8], s: usize, n: usize) {
  use cfor::cfor;
  let stride = 1 << s;
  let mut index = 0;
  let mut d;
  let mut m;

  cfor! (let mut i = 0; i < n; i += stride*2;
  {
    cfor! (let mut j = 0; j < stride; j+=1;
    {
      d = p[ i+j ] ^ p[ i+j+stride ];
      m = ((cb[ index >> 3 ] >> (index & 7)) & 1) as i16;
      m = m.wrapping_neg();
      d &= m as i16;
      p[ i+j ] ^= d;
      p[ i+j+stride ] ^= d;
      index += 1;
    });
  });
}
