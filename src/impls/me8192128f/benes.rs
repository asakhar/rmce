use super::{
    gf::Gf,
    params::{GFBITS, SYS_N},
    transpose::transpose_64x64,
    util::{bitrev, load8, store8},
};

/* input: r, sequence of bits to be permuted */
/*        bits, condition bits of the Benes network */
/*        rev, 0 for normal application; !0 for inverse */
/* output: r, permuted bits */
pub fn apply_benes(r: &mut [u8], bits: &[u8], rev: bool) {
    let r_ptr = r;

    let mut r_int_v = [[0u64; 64]; 2];
    let mut r_int_h = [[0u64; 64]; 2];
    let mut b_int_v = [0u64; 64];
    let mut b_int_h = [0u64; 64];

    let (mut bits_offset, inc) = if rev { (12288, 1024) } else { (0, 0) };

    for i in 0..64 {
        r_int_v[0][i] = load8((&r_ptr[i * 16 + 0..i * 16 + 8]).try_into().unwrap());
        r_int_v[1][i] = load8((&r_ptr[i * 16 + 8..i * 16 + 16]).try_into().unwrap());
    }
    transpose_64x64(&mut r_int_h[0], &r_int_v[0]);
    transpose_64x64(&mut r_int_h[1], &r_int_v[1]);
    for iter in 0..=6
    //(iter = 0; iter <= 6; iter++)
    {
        for i in 0..64
        //(i = 0; i < 64; i++)
        {
            b_int_v[i] = load8((&bits[bits_offset..bits_offset + 8]).try_into().unwrap());
            bits_offset += 8;
        }

        bits_offset -= inc;

        transpose_64x64(&mut b_int_h, &b_int_v);

        layer_ex(&mut r_int_h[0], &b_int_h, iter);
    }
    transpose_64x64(&mut r_int_v[0], &r_int_h[0]);
    transpose_64x64(&mut r_int_v[1], &r_int_h[1]);

    for iter in 0..=5
    //(iter = 0; iter <= 5; iter++)
    {
        for i in 0..64
        //(i = 0; i < 64; i++)
        {
            b_int_v[i] = load8((&bits[bits_offset..bits_offset + 8]).try_into().unwrap());
            bits_offset += 8;
        }
        bits_offset -= inc;

        layer_in(&mut r_int_v, &b_int_v, iter);
    }

    for iter in (0..=4).rev()
    //(iter = 4; iter >= 0; iter--)
    {
        for i in 0..64
        //(i = 0; i < 64; i++)
        {
            b_int_v[i] = load8((&bits[bits_offset..bits_offset + 8]).try_into().unwrap());
            bits_offset += 8;
        }
        bits_offset -= inc;

        layer_in(&mut r_int_v, &b_int_v, iter);
    }

    transpose_64x64(&mut r_int_h[0], &r_int_v[0]);
    transpose_64x64(&mut r_int_h[1], &r_int_v[1]);

    for iter in (0..=6).rev()
    //(iter = 6; iter >= 0; iter--)
    {
        for i in 0..64
        //(i = 0; i < 64; i++)
        {
            b_int_v[i] = load8((&bits[bits_offset..bits_offset + 8]).try_into().unwrap());
            bits_offset += 8;
        }

        bits_offset += inc;

        transpose_64x64(&mut b_int_h, &b_int_v);

        layer_ex(&mut r_int_h[0], &b_int_h, iter);
    }

    transpose_64x64(&mut r_int_v[0], &r_int_h[0]);
    transpose_64x64(&mut r_int_v[1], &r_int_h[1]);

    for i in 0..64
    //(i = 0; i < 64; i++)
    {
        store8(
            (&mut r_ptr[i * 16 + 0..i * 16 + 8]).try_into().unwrap(),
            r_int_v[0][i],
        );
        store8(
            (&mut r_ptr[i * 16 + 8..i * 16 + 16]).try_into().unwrap(),
            r_int_v[1][i],
        );
    }
}

/* input: condition bits c */
/* output: support s */
#[allow(non_snake_case)]
pub fn support_gen(s: &mut [Gf; SYS_N], c: &[u8]) {
    let mut L = [[0u8; (1 << GFBITS) / 8]; GFBITS];
    let mut a;
    // unsigned char L[ GFBITS ][ (1 << GFBITS)/8 ];

    for i in 0..GFBITS
    //(i = 0; i < GFBITS; i++)
    {
        for j in 0..(1 << GFBITS) / 8
        //(j = 0; j < (1 << GFBITS)/8; j++)
        {
            L[i][j] = 0;
        }
    }

    for i in 0..(1 << GFBITS)
    //(i = 0; i < (1 << GFBITS); i++)
    {
        a = bitrev(Gf(i));

        for j in 0..GFBITS
        //(j = 0; j < GFBITS; j++)
        {
            L[j][i as usize / 8] |= ((((a.0 >> j) & 1) << (i % 8)) & 0xFF) as u8;
        }
    }

    for j in 0..GFBITS
    //(j = 0; j < GFBITS; j++)
    {
        apply_benes(&mut L[j], c, false);
    }

    for i in 0..SYS_N
    //(i = 0; i < SYS_N; i++)
    {
        s[i] = Gf(0);
        for j in (0..GFBITS).rev()
        //(j = GFBITS-1; j >= 0; j--)
        {
            s[i].0 <<= 1;
            s[i].0 |= ((L[j][i / 8] >> (i % 8)) & 1) as u16;
        }
    }
}

/* middle layers of the benes network */
fn layer_in(data: &mut [[u64; 64]; 2], bits: &[u64; 64], lgs: i32) {
    let mut d;

    let s = 1 << lgs;
    let mut i = 0;
    let mut offset = 0;
    while i < 64
    //(i = 0; i < 64; i += s*2)
    {
        for j in i..i + s
        //(j = i; j < i+s; j++)
        {
            d = data[0][j + 0] ^ data[0][j + s];
            d &= bits[offset];
            offset += 1;
            data[0][j + 0] ^= d;
            data[0][j + s] ^= d;

            d = data[1][j + 0] ^ data[1][j + s];
            d &= bits[offset];
            offset += 1;
            data[1][j + 0] ^= d;
            data[1][j + s] ^= d;
        }
        i += s * 2;
    }
}

/* first and last layers of the benes network */
fn layer_ex(data: &mut [u64; 64], bits: &[u64; 64], lgs: i32) {
    let mut d;

    let s = 1 << lgs;
    let mut offset = 0;
    let mut i = 0;

    while i < 128
    //(i = 0; i < 128; i += s*2)
    {
        for j in i..i + s
        //(j = i; j < i+s; j++)
        {
            d = data[j + 0] ^ data[j + s];
            d &= bits[offset];
            offset += 1;
            data[j + 0] ^= d;
            data[j + s] ^= d;
        }
        i += s * 2;
    }
}
