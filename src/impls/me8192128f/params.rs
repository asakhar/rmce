pub const GFBITS: usize = 13;
pub const SYS_N: usize = 8192;
pub const SYS_T: usize = 128;

pub const COND_BYTES: usize = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);
pub const IRR_BYTES: usize = SYS_T * 2;

pub const PK_NROWS: usize = SYS_T * GFBITS;
pub const PK_NCOLS: usize = SYS_N - PK_NROWS;
pub const PK_ROW_BYTES: usize = (PK_NCOLS + 7) / 8;

pub const SYND_BYTES: usize = (PK_NROWS + 7) / 8;

pub const GFMASK: u64 = (1 << GFBITS) - 1;
