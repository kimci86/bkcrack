use super::crc32_tab::*;
use super::keystream_tab::KeystreamTab;
use super::mult_tab::MultTab;
use super::utils::*;

/// Keys defining the cipher state
pub struct Keys {
    x: u32,
    y: u32,
    z: u32,
    crc32tab: Crc32Tab,
    keystream: KeystreamTab,
}

impl Keys {
    /// Constructor
    pub fn new() -> Keys {
        Keys {
            x: 0x12345678,
            y: 0x23456789,
            z: 0x34567890,
            crc32tab: Crc32Tab::new(),
            keystream: KeystreamTab::new(),
        }
    }

    pub fn set_keys(&mut self, x: u32, y: u32, z: u32) {
        self.x = x;
        self.y = y;
        self.z = z;
    }

    /// Update the state with a plaintext byte
    pub fn update(&mut self, p: u8) {
        self.x = self.crc32tab.crc32(self.x, p);
        self.y = (self.y + lsb(self.x) as u32) * MultTab::MULT + 1;
        self.z = self.crc32tab.crc32(self.z, msb(self.y));
    }

    /// Update the state backward with a ciphertext byte
    pub fn update_backword(&mut self, c: u8) {
        self.z = self.crc32tab.crc32inv(self.z, msb(self.y));
        self.y = (self.y - 1) * MultTab::MULTINV - lsb(self.x) as u32;
        self.x = self.crc32tab.crc32inv(self.x, c ^ self.keystream.get_byte(self.z));
    }

    /// return X value
    pub fn get_x(&self) -> u32 {
        self.x
    }

    /// return Y value
    pub fn get_y(&self) -> u32 {
        self.y
    }

    /// return Z value
    pub fn get_z(&self) -> u32 {
        self.z
    }
}