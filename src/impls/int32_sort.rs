use cfor::cfor;

macro_rules! int32_minmax {
    ($a:expr, $b:expr) => {{
        let ab = $b ^ $a;
        let mut c = $b - $a;
        c ^= ab & (c ^ $b);
        c >>= 31;
        c &= ab;
        $a ^= c;
        $b ^= c;
    }};
}

pub fn sort(x: &mut [i32], n: usize) {
    if n < 2 {
        return;
    };
    let mut top = 1;
    while top < n - top {
        top += top
    }

    cfor! (let mut p = top;p > 0;p >>= 1; {
      cfor! (let mut i = 0;i < n - p;i += 1; {
        if (i & p) == 0 {
          int32_minmax!(x[i],x[i+p]);
        }
      });
      let mut i = 0;
      cfor!(let mut q = top;q > p;q >>= 1; {
        cfor!(; i < n - q; i+=1; {
          if (i & p) == 0 {
            let mut a = x[i + p];
            cfor! (let mut r = q;r > p;r >>= 1; {
              int32_minmax!(a,x[i+r]);
            });
            x[i + p] = a;
          }
        });
      });
    })
}
