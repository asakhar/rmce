use super::{
  gf::Gf,
  params::{SYS_N, SYS_T},
};

/* input: polynomial f and field element a */
/* return f(a) */
pub fn eval(f: &[Gf; SYS_T + 1], a: Gf) -> Gf {
  let mut r = f[SYS_T];
  for i in (0..SYS_T).rev() {
    r = r.mul(a);
    r = r.add(f[i]);
  }
  r
}

/* input: polynomial f and list of field elements L */
/* output: out = [ f(a) for a in L ] */
pub fn root(out: &mut [Gf; SYS_N], f: &[Gf; SYS_T + 1], l: &[Gf; SYS_N]) {
  for i in 0..SYS_N {
    out[i] = eval(f, l[i]);
  }
}
