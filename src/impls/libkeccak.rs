pub fn shake256(out: &mut [u8], input: &[u8]) {
    keccak(1088, 512, input, 0x1f, out);
}

#[allow(non_snake_case)]
fn keccak(r: usize, _c: u32, mut input: &[u8], sfx: u8, mut out: &mut [u8]) {
    // init
    let mut s = [0u8; 200];
    let R = r / 8;
    let mut b = 0;
    // absorb
    let mut in_len = input.len();
    while in_len > 0 {
        b = std::cmp::min(in_len, R);
        for i in 0..b {
            s[i] ^= input[i];
        }
        input = &input[b..];
        in_len -= b;
        if b == R {
            keccakf1600(&mut s);
            b = 0;
        }
    }
    // pad
    s[b] ^= sfx;
    if (sfx & 0x80 != 0) && (b == (R - 1)) {
        keccakf1600(&mut s);
    }
    s[R - 1] ^= 0x80;
    keccakf1600(&mut s);
    // squeeze
    let mut out_len = out.len();
    while out_len > 0 {
        b = std::cmp::min(out_len, R);
        for i in 0..b {
            out[i] = s[i];
        }
        out = &mut out[b..];
        out_len -= b;
        if out_len > 0 {
            keccakf1600(&mut s);
        }
    }
}

fn lfsr86540(rr: &mut u8) -> bool {
    let r = *rr;
    let c = (r & 0x80) >> 7;
    *rr = (r << 1) ^ (c * 0x71);
    (*rr & 2) >> 1 != 0
}

fn rol(a: u64, o: u32) -> u64 {
    (a << o) ^ (a >> (64 - o))
}

fn xor64(x: &mut [u8; 8], mut u: u64) {
    for i in 0..8 {
        x[i] ^= (u & 0xff) as u8;
        u >>= 8;
    }
}

fn r_l(x: usize, y: usize, s: &[u8; 200]) -> u64 {
    let off = 8 * (x + 5 * y);
    u64::from_le_bytes(s[off..off + 8].try_into().unwrap())
}

fn w_l(x: usize, y: usize, l: u64, s: &mut [u8; 200]) {
    let off = 8 * (x + 5 * y);
    s[off..off + 8].copy_from_slice(&l.to_le_bytes());
}

fn x_l(x: usize, y: usize, l: u64, s: &mut [u8; 200]) {
    let off = 8 * (x + 5 * y);
    let ss = (&mut s[off..off + 8]).try_into().unwrap();
    xor64(ss, l)
}

#[allow(non_snake_case)]
fn keccakf1600(s: &mut [u8; 200]) {
    let mut R = 0x01u8;
    let mut C = [0u64; 5];
    let mut D;
    let mut Y;
    for _ in 0..24 {
        // Θ
        for x in 0..5 {
            C[x] = r_l(x, 0, s) ^ r_l(x, 1, s) ^ r_l(x, 2, s) ^ r_l(x, 3, s) ^ r_l(x, 4, s);
        }
        for x in 0..5 {
            D = C[(x + 4) % 5] ^ rol(C[(x + 1) % 5], 1);
            for y in 0..5 {
                x_l(x, y, D, s);
            }
        }
        // ρπ
        let mut x = 1;
        let mut y = 0;
        let mut r = 0;
        D = r_l(x, y, s);
        for j in 0..24 {
            r += j + 1;
            Y = (2 * x + 3 * y) % 5;
            x = y;
            y = Y;
            C[0] = r_l(x, y, s);
            w_l(x, y, rol(D, r % 64), s);
            D = C[0];
        }
        // X
        for y in 0..5 {
            for x in 0..5 {
                C[x] = r_l(x, y, s);
            }
            for x in 0..5 {
                w_l(x, y, C[x] ^ ((!C[(x + 1) % 5]) & C[(x + 2) % 5]), s);
            }
        }
        // ι
        for j in 0..7 {
            if lfsr86540(&mut R) {
                x_l(0, 0, 1 << ((1 << j) - 1), s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_test() {
        let message = b"\x11\x97\x13\xCC\x83\xEE\xEF";
        let expected = b"\xc0\x25\x61\xc1\x2c\xcd\xd1\x67\xca\x95\x9d\x97\x56\xcc\x70\x94\x6f\x7f\xed\x8b\xa7\x05\xe3\xed\xc4\x33\xd3\xc4\x5d\x92\x99\xd0\xae\xfe\x9e\x8e\x25\xd6\x02\xc4\xdb\x0d\x14\xec\xae\xfd\xfd\xfe\xd2\xde\x13\x4a\xc5\xd0\xc4\xdf\xc0\x2a\xbe\xff\xfd\xd7\x66\x7a\x43\x49\x36\x15\x1d\x52\x9a\x93\xcb\x26\x61\x00\xb9\x4a\xd0\x44\x95\x97\xb1\x59\x03\x98\xa1\xa6\x3c\x42\x64\x93\x85\xb4\xcf\xaa\x82\x8c\x89\x03\x7e\x0f\x97\xbe\xda\x84\x50\xa6\x85\x20\x14\x38\x89\xa9\x2c\x25\x86\x45\x66\x4e\xb5\x7c\xba\x01\xc3\xb1\x13\x43\x18\xe1\x1a\x18\x48\xd9\x12\xd0";
        let result = &mut [0u8; 136];
        shake256(result, message);
        assert_eq!(expected, result);
    }
}
