use super::utils::*;

/// Lookup tables for CRC32 related computations
pub struct Crc32Tab {
    crctab: [u32; 256],
    crcinvtab: [u32; 256],
}

impl Crc32Tab {
    const CRCPOL: u32 = 0xedb88320;

    // TODO: CrcTab 应该是个"常量"?
    pub fn new() -> Crc32Tab {
        let mut crc32tab = Crc32Tab {
            crctab: [0; 256],
            crcinvtab: [0; 256],
        };

        for b in 0..256 {
            let mut crc = b;

            // compute crc32 from the original definition
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    crc >> 1 ^ Crc32Tab::CRCPOL
                } else {
                    crc >> 1
                };
            }

            // fill lookup tables
            crc32tab.crctab[b as usize] = crc;
            crc32tab.crcinvtab[msb(crc) as usize] = crc << 8 ^ b;
        }

        crc32tab
    }

    /// return CRC32 using a lookup table
    pub fn crc32(&self, pval: u32, b: u8) -> u32 {
        pval >> 8 ^ self.crctab[(lsb(pval) ^ b) as usize]
    }

    /// return CRC32^-1 using a lookup table
    pub fn crc32inv(&self, crc: u32, b: u8) -> u32 {
        crc << 8 ^ self.crcinvtab[msb(crc) as usize] ^ b as u32
    }

    /// return Yi[24,32) from Zi and Z{i-1} using CRC32^-1
    pub fn get_yi_24_32(&self, zi: u32, zim1: u32) -> u32 {
        (self.crc32inv(zi, 0) ^ zim1) << 24
    }

    /// return Z{i-1}[10,32) from Zi[2,32) using CRC32^-1
    pub fn get_zim1_10_32(&self, zi_2_32: u32) -> u32 {
        self.crc32inv(zi_2_32, 0) & MASK_10_32
    }
}

#[cfg(test)]
mod tests {
    use super::Crc32Tab;

    #[test]
    fn get_zim1_10_32() {
        let instance = Crc32Tab::new();
        assert_eq!(1838198784, instance.get_zim1_10_32(33555384));
    }
}