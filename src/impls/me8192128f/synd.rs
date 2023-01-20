use super::{params::{SYS_T, SYS_N}, gf::Gf, root::eval};

/* input: Goppa polynomial f, support L, received word r */
/* output: out, the syndrome of length 2t */
pub fn synd(out: &mut [Gf; SYS_T*2], f: &[Gf; SYS_T+1], l: [Gf; SYS_N], r: &[u8; SYS_N/8]) {
  out.fill(Gf(0));
  for i in 0..SYS_N {
    let c = (r[i/8] >> (i%8)) & 1;
    let c = Gf(c as u16);
    let e = eval(f, l[i]);
    let mut e_inv = e.mul(e).inv();

    for j in 0..SYS_T*2 {
      out[j] = out[j].add(e_inv.mul(c));
      e_inv = e_inv.mul(l[i]);
    }
  }
}