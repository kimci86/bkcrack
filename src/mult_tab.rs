use super::utils::*;

/// Lookup tables for multiplication related computations
pub struct MultTab {

    // lookup tables
    multtab: [u32; 256],
    multinvtab: [u32; 256],
    msbprodfiber2: Vec<Vec<u8>>, //[Vec<u8>; 256],
    msbprodfiber3: Vec<Vec<u8>>, //[Vec<u8>; 256],
}

impl MultTab {
    pub const MULT: u32 = 0x08088405;
    pub const MULTINV: u32 = 0xd94fa8cd;

    pub fn new() -> MultTab {
        let mut multtab = MultTab {
            multtab: [0; 256],
            multinvtab: [0; 256],
            msbprodfiber2: (0..256).map(|_|vec![0u8]).collect::<Vec<_>>(),
            msbprodfiber3: (0..256).map(|_|vec![0u8]).collect::<Vec<_>>(),
        };
        let mut prodinv = 0;
        for x in 0..256 {
            multtab.multinvtab[x] = prodinv;

            multtab.msbprodfiber2[msb(prodinv) as usize].push(x as u8);
            multtab.msbprodfiber2[(msb(prodinv) as usize + 1) % 256].push(x as u8);

            multtab.msbprodfiber3[(msb(prodinv) as usize + 255) % 256].push(x as u8);
            multtab.msbprodfiber3[msb(prodinv) as usize].push(x as u8);
            multtab.msbprodfiber3[(msb(prodinv) as usize + 1) % 256].push(x as u8);

            prodinv = prodinv.wrapping_add(MultTab::MULTINV);
        }
        multtab
    }

    /// return mult^-1 * x using a lookup table
    pub fn get_multinv(&self, x: u8) -> u32 {
        self.multinvtab[x as usize]
    }

    /// return a vector of bytes x such that
    /// msb(x*mult^-1) is equal to msbprod or msbprod-1
    pub fn get_msb_prod_fiber2(&self, msbprodinv: u8) -> Vec<u8> {
        self.msbprodfiber2[msbprodinv as usize].clone()
    }

    /// return a vector of bytes x such that
    /// msb(x*mult^-1) is equal to msbprod, msbprod-1 or msbprod+1
    pub fn get_msb_prod_fiber3(&self, msbprodinv: u8) -> Vec<u8> {
        self.msbprodfiber3[msbprodinv as usize].clone()
    }
}
