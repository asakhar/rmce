/*
  This file is for matrix transposition
*/

pub fn transpose_64x64(out: &mut [u64; 64], inp: &[u64; 64]) {
  const MASKS: [[u64; 2]; 6] = [
    [0x5555555555555555, 0xAAAAAAAAAAAAAAAA],
    [0x3333333333333333, 0xCCCCCCCCCCCCCCCC],
    [0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0],
    [0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00],
    [0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000],
    [0x00000000FFFFFFFF, 0xFFFFFFFF00000000],
  ];

  out.copy_from_slice(inp);
  let mut s;
  let mut x;
  let mut y;

  for d in (0..=5).rev() {
    s = 1 << d;

    let mut i = 0;
    while i < 64 {
      for j in i..i + s {
        x = (out[j] & MASKS[d][0]) | ((out[j + s] & MASKS[d][0]) << s);
        y = ((out[j] & MASKS[d][1]) >> s) | (out[j + s] & MASKS[d][1]);

        out[j + 0] = x;
        out[j + s] = y;
      }
      i += s * 2;
    }
  }
}
