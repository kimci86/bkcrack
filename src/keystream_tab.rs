use super::utils::*;

/// Lookup tables for keystream related computations
pub struct KeystreamTab {
    keystreamtab: [u8; 1 << 14],
    keystreaminvtab: [[u32; 64]; 256],
    keystreaminvfiltertab: Vec<Vec<Vec<u32>>>//[[Vec<u32>; 64]; 256]
}

impl KeystreamTab {
    pub fn new() -> KeystreamTab {
        let mut keystreamtab = KeystreamTab {
            keystreamtab: [0; 1 << 14],
            keystreaminvtab: [[0; 64]; 256],
            keystreaminvfiltertab: (0..256).map(|_|(0..64).map(|_|vec![]).collect::<Vec<_>>()).collect::<Vec<_>>(),
        };

        let mut next = [0; 256];
        for z_2_16 in (0..1<<16).step_by(4) {
            let k = lsb((z_2_16 | 2) * (z_2_16 | 3) >> 8);
            keystreamtab.keystreamtab[(z_2_16 >> 2) as usize] = k;
            keystreamtab.keystreaminvtab[k as usize][next[k as usize]] = z_2_16;
            keystreamtab.keystreaminvfiltertab[k as usize][(z_2_16 >> 10) as usize].push(z_2_16);
            next[k as usize] += 1;
        }

        keystreamtab
    }

    /// **return** the keystream byte ki associated to a Zi value
    /// **note** Only Zi[2,16) is used
    pub fn get_byte(&self, zi: u32) -> u8 {
        self.keystreamtab[((zi & MASK_0_16) >> 2) as usize]
    }

    /// **return** a sorted array of 64 Zi[2,16) values such that
    /// getByte(zi) is equal to ki
    pub fn get_zi_2_16_array(&self, ki: u8) -> [u32; 64] {
        self.keystreaminvtab[ki as usize]
    }

    /// **return** a vector of Zi[2,16) values having given [10,16) bits
    /// such that getByte(zi) is equal to ki
    /// **note** the vector contains one element on average
    pub fn get_zi_2_16_vector(&self, ki: u8, zi_10_16: u32) -> &Vec<u32> {
        &self.keystreaminvfiltertab[ki as usize][((zi_10_16 & MASK_0_16) >> 10) as usize]
    }
}

#[cfg(test)]
mod test {
    use super::KeystreamTab;

    #[test]
    fn get_byte() {
        let instance = KeystreamTab::new();
        assert_eq!(0, instance.get_byte(0));
        assert_eq!(1, instance.get_byte(20));
        assert_eq!(20, instance.get_byte(1 << 10));
        assert_eq!(0, instance.get_byte(1 << 20));
    }

    #[test]
    fn get_zi_2_16_array() {
        let ret = vec![16, 20, 360, 1964, 2244, 2972, 3636, 4648, 5824, 7092];
        assert_eq!(ret, KeystreamTab::new().get_zi_2_16_array(1)[0..10].to_vec());
    }

    #[test]
    fn get_zi_2_16_vector() {
        assert_eq!(&vec![47872], KeystreamTab::new().get_zi_2_16_vector(167, 243712));
    }
}