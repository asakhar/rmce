use super::params::{GFBITS, GFMASK, SYS_T};

#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Gf(pub u16);

impl Gf {
    pub fn is_zero(self) -> Self {
        let mut t = self.0 as u32;
        t -= 1;
        t >>= 19;

        Self(t as u16)
    }
    pub fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
    pub fn mul(self, other: Self) -> Self {
        let t0 = self.0 as u64;
        let t1 = other.0 as u64;
        let mut tmp = t0 * (t1 & 1);
        for i in 1..GFBITS {
            tmp ^= t0 * (t1 & (1 << i));
        }

        let t = tmp & 0x1FF0000;
        tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

        let t = tmp & 0x000E000;
        tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

        Self((tmp & GFMASK) as u16)
    }
    pub fn frac(self, num: Self) -> Self {
        let tmp_11 = self.sqmul(self); //gf_sqmul(den, den); // ^11
        let tmp_1111 = tmp_11.sq2mul(tmp_11); //gf_sq2mul(tmp_11, tmp_11); // ^1111
        let mut out = tmp_1111.sq2();
        out = out.sq2mul(tmp_1111); //gf_sq2mul(out, tmp_1111); // ^11111111
        out = out.sq2(); //gf_sq2(out);
        out = out.sq2mul(tmp_1111); //gf_sq2mul(out, tmp_1111); // ^111111111111

        out.sqmul(num) //gf_sqmul(out, num); // ^1111111111110 = ^-1
    }
    pub fn inv(self) -> Self {
        self.frac(Gf(1))
    }
    fn sq2(self) -> Self {
        const B: [u64; 4] = [
            0x1111111111111111,
            0x0303030303030303,
            0x000F000F000F000F,
            0x000000FF000000FF,
        ];

        const M: [u64; 4] = [
            0x0001FF0000000000,
            0x000000FF80000000,
            0x000000007FC00000,
            0x00000000003FE000,
        ];
        let mut x = self.0 as u64;
        let mut t;
        x = (x | (x << 24)) & B[3];
        x = (x | (x << 12)) & B[2];
        x = (x | (x << 6)) & B[1];
        x = (x | (x << 3)) & B[0];

        for i in 0..4 {
            t = x & M[i];
            x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
        }
        Self((x & GFMASK) as u16)
    }
    fn sqmul(self, other: Self) -> Self {
        const M: [u64; 3] = [0x0000001FF0000000, 0x000000000FF80000, 0x000000000007E000];

        let mut t0 = self.0 as u64;
        let t1 = other.0 as u64;
        let mut t;

        let mut x = (t1 << 6) * (t0 & (1 << 6));

        t0 ^= t0 << 7;

        x ^= t1 * (t0 & (0x04001));
        x ^= (t1 * (t0 & (0x08002))) << 1;
        x ^= (t1 * (t0 & (0x10004))) << 2;
        x ^= (t1 * (t0 & (0x20008))) << 3;
        x ^= (t1 * (t0 & (0x40010))) << 4;
        x ^= (t1 * (t0 & (0x80020))) << 5;

        for i in 0..3 {
            t = x & M[i];
            x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
        }

        Self((x & GFMASK) as u16)
    }
    fn sq2mul(self, other: Self) -> Self {
        const M: [u64; 6] = [
            0x1FF0000000000000,
            0x000FF80000000000,
            0x000007FC00000000,
            0x00000003FE000000,
            0x0000000001FE0000,
            0x000000000001E000,
        ];

        let mut t0 = self.0 as u64;
        let t1 = other.0 as u64;
        let mut t;

        let mut x = (t1 << 18) * (t0 & (1 << 6));

        t0 ^= t0 << 21;

        x ^= t1 * (t0 & (0x010000001));
        x ^= (t1 * (t0 & (0x020000002))) << 3;
        x ^= (t1 * (t0 & (0x040000004))) << 6;
        x ^= (t1 * (t0 & (0x080000008))) << 9;
        x ^= (t1 * (t0 & (0x100000010))) << 12;
        x ^= (t1 * (t0 & (0x200000020))) << 15;

        for i in 0..6 {
            t = x & M[i];
            x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
        }

        Self((x & GFMASK) as u16)
    }
}

pub fn gf_mul(out: &mut [Gf; SYS_T], in0: &[Gf; SYS_T], in1: &[Gf; SYS_T]) {
    let mut prod = [Gf(0); SYS_T * 2 - 1];
    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] = in0[i].mul(in1[j]);
        }
    }

    for i in (SYS_T..=(SYS_T - 1) * 2).rev() {
        prod[i - SYS_T + 7].0 ^= prod[i].0;
        prod[i - SYS_T + 2].0 ^= prod[i].0;
        prod[i - SYS_T + 1].0 ^= prod[i].0;
        prod[i - SYS_T + 0].0 ^= prod[i].0;
    }
    for i in 0..SYS_T {
        out[i] = prod[i];
    }
}
