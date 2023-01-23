use crate::impls::{
  int32_sort,
  subroutines::{crypto_declassify::crypto_declassify, crypto_int::CryptoInt},
};

/* parameters: 1 <= w <= 14; n = 2^w */
/* input: permutation pi of {0,1,...,n-1} */
/* output: (2m-1)n/2 control bits at positions 0,1,... */
/* output position pos is by definition 1&(out[pos/8]>>(pos&7)) */
pub fn control_bits_from_permutation(out: &mut [u8], pi: &[i16], w: usize, n: usize) {
  assert_eq!(out.len(), (((2 * w - 1) * n / 2) + 7) / 8);
  assert_eq!(n, 1 << w);
  assert_eq!(pi.len(), n);
  let mut temp = vec![0i32; 2 * n];
  let mut pi_test = vec![0i16; n];
  loop {
    out.fill(0);
    cbrecursion(out, 0, 1, pi, w, n, &mut temp);

    // check for correctness

    for i in 0..n {
      pi_test[i] = i as i16;
    }
    let mut ooff = 0;
    for i in 0..w {
      layer(&mut pi_test, &out[ooff..], i, n);
      ooff += n >> 4;
    }

    for i in (0..=w - 2).rev() {
      layer(&mut pi_test, &out[ooff..], i, n);
      ooff += n >> 4;
    }

    let mut diff = 0;
    for i in 0..n {
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
  // #define A temp
  // #define B (temp+n)
  // #define q ((int16 *) (temp+n+n/4))
  /* q can start anywhere between temp+n and temp+n/2 */

  // long long x,i,j,k;

  if w == 1 {
    out[pos >> 3] ^= (pi[0] << (pos & 7)) as u8;
    return;
  }

  cfor! (let mut x = 0;x < n;x+=1; {temp[x] = (((pi[x]^1) as i32) << 16)|pi[x^1] as i32});
  int32_sort::sort(temp, n); /* A = (id<<16)+pibar */

  cfor! (let mut x = 0;x < n;x+=1; {
    let Ax = temp[x];
    let px = Ax&0xffff;
    let cx = CryptoInt(px).min(CryptoInt(x as i32)).0;
    //B
    temp[n+x] = (px<<16)|cx;
  });
  /* B = (p<<16)+c */

  cfor! (let mut x = 0;x < n;x+=1; {temp[x] = (temp[x]<<16)|x as i32}); /* A = (pibar<<16)+id */
  int32_sort::sort(temp, n); /* A = (id<<16)+pibar^-1 */

  cfor! (let mut x = 0;x < n;x+=1; {temp[x] = (temp[x]<<16)+(/*B*/temp[x+n]>>16)}); /* A = (pibar^(-1)<<16)+pibar */
  int32_sort::sort(temp, n); /* A = (id<<16)+pibar^2 */

  if w <= 10 {
    cfor! (let mut x = 0;x < n;x+=1; {temp[x+n] = ((temp[x]&0xffff)<<10)|(temp[x+n]&0x3ff)});

    cfor! (let mut i = 1;i < w-1;i+=1; {
      /* B = (p<<10)+c */

      cfor! (let mut x = 0;x < n;x+=1; {temp[x] = ((temp[x+n]&!0x3ff)<<6)|x as i32}); /* A = (p<<16)+id */
      int32_sort::sort(temp, n); /* A = (id<<16)+p^{-1} */

      cfor! (let mut x = 0;x < n;x+=1; {temp[x] = (temp[x]<<20)|temp[x+n]}); /* A = (p^{-1}<<20)+(p<<10)+c */
      int32_sort::sort(temp, n); /* A = (id<<20)+(pp<<10)+cp */

      cfor! (let mut x = 0;x < n;x+=1; {
        let ppcpx = temp[x]&0xfffff;
        let ppcx = (temp[x]&0xffc00)|(temp[x+n]&0x3ff);
        temp[x+n] = CryptoInt(ppcx).min(CryptoInt(ppcpx)).0; // B[x] = int32_min(ppcx,ppcpx);
      });
    });
    cfor! (let mut x = 0;x < n;x+=1; {temp[x+n] &= 0x3ff});
  } else {
    cfor! (let mut x = 0;x < n;x+=1; {temp[x+n] = (temp[x]<<16)|(temp[x+n]&0xffff)});

    cfor! (let mut i = 1;i < w-1;i+=1; {
      /* B = (p<<16)+c */

      cfor! (let mut x = 0;x < n;x+=1; {temp[x] = (temp[x+n]&!0xffff)|x as i32});
      int32_sort::sort(temp,n); /* A = (id<<16)+p^(-1) */

      cfor! (let mut x = 0;x < n;x+=1; {temp[x] = (temp[x]<<16)|(temp[x+n]&0xffff)});
      /* A = p^(-1)<<16+c */

      if i < w-2 {
        cfor! (let mut x = 0;x < n;x+=1; {temp[x+n] = (temp[x]&!0xffff)|(temp[x+n]>>16)});
        /* B = (p^(-1)<<16)+p */
        int32_sort::sort(&mut temp[n..],n); /* B = (id<<16)+p^(-2) */
        cfor! (let mut x = 0;x < n;x+=1; {temp[x+n] = (temp[x+n]<<16)|(temp[x]&0xffff)});
        /* B = (p^(-2)<<16)+c */
      }

      int32_sort::sort(temp,n);
      /* A = id<<16+cp */
      cfor! (let mut x = 0;x < n;x+=1; {
        let cpx = (temp[x+n]&!0xffff)|(temp[x]&0xffff);
        temp[x+n] = CryptoInt(temp[x+n]).min(CryptoInt(cpx)).0; // B[x] = int32_min(B[x],cpx);
      });
    });
    cfor! (let mut x = 0;x < n;x+=1; {temp[x+n] &= 0xffff});
  }

  cfor! (let mut x = 0;x < n;x+=1; {temp[x] = ((pi[x] as i32)<<16)+(x as i32)});
  int32_sort::sort(temp, n); /* A = (id<<16)+pi^(-1) */

  cfor! (let mut j = 0;j < n/2;j+=1; {
    let x = 2*j;
    let fj = temp[x+n]&1; /* f[j] */
    let Fx = x as i32 + fj; /* F[x] */
    let Fx1 = Fx^1; /* F[x+1] */

    out[pos>>3] ^= (fj<<(pos&7)) as u8;
    pos += step;

    temp[x+n] = (temp[x]<<16)|Fx;
    temp[x+1+n] = (temp[x+1]<<16)|Fx1;
  });
  /* B = (pi^(-1)<<16)+F */

  int32_sort::sort(&mut temp[n..], n); /* B = (id<<16)+F(pi) */

  pos += (2 * w - 3) * step * (n / 2);

  cfor! (let mut k = 0;k < n/2;k+=1; {
    let y = 2*k;
    let lk = temp[y+n]&1; /* l[k] */
    let Ly = y as i32 + lk; /* L[y] */
    let Ly1 = Ly^1; /* L[y+1] */

    out[pos>>3] ^= (lk<<(pos&7)) as u8;
    pos += step;

    temp[y] = (Ly<<16)|(temp[y+n]&0xffff);
    temp[y+1] = (Ly1<<16)|(temp[y+1+n]&0xffff);
  });
  /* A = (L<<16)+F(pi) */

  int32_sort::sort(temp, n); /* A = (id<<16)+F(pi(L)) = (id<<16)+M */

  pos -= (2 * w - 2) * step * (n / 2);

  cfor! (let mut j = 0;j < n/2;j+=1; {
    //q[j] = (temp[2*j]&0xffff)>>1
    let val =
    (temp[2*j]&0xffff)>>1;
    let offset = &mut temp[n+n/4..];
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
