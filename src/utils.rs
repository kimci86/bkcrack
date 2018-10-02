pub fn lsb(x: u32) -> u8 {
    x as u8
}

pub fn msb(x: u32) -> u8 {
    (x >> 24) as u8
}

pub const MASK_0_16: u32 = 0x0000ffff;
pub const MASK_26_32: u32 = 0xfc000000;
pub const MASK_24_32: u32 = 0xff000000;
pub const MASK_10_32: u32 = 0xfffffc00;
pub const MASK_8_32: u32 = 0xffffff00;
pub const MASK_2_32: u32 = 0xfffffffc;

// maximum difference between integers A and B[x,32) where A = B + somebyte.
// So:
//  A - B[x,32) = B[0,x) + somebyte
//  A - B[x,32) <= mask[0,x) + 0xff
pub const MAXDIFF_0_24: u32 = 0x00ffffff + 0xff;
pub const MAXDIFF_0_26: u32 = 0x03ffffff + 0xff;