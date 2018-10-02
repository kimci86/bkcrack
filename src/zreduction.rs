use super::attack::Attack;
use super::crc32_tab::Crc32Tab;
use super::keystream_tab::KeystreamTab;
use std::mem;

pub struct Zreduction<'a> {
    keystream: &'a Vec<u8>,
    pub zi_2_32_vector: Vec<u32>,
    index: usize,
    keystreamtab: KeystreamTab,
    crc32tab: Crc32Tab,
}


impl<'a> Zreduction<'a> {

    const WAIT_SIZE: usize = 1 << 8;
    const TRACK_SIZE: usize = 1 << 16;

    pub fn new(keystream: &Vec<u8>) -> Zreduction {
        Zreduction {
            zi_2_32_vector: Vec::new(),
            keystream,
            index: 0,
            keystreamtab: KeystreamTab::new(),
            crc32tab: Crc32Tab::new(),
        }
    }

    pub fn generate(&mut self) {
        self.index = self.keystream.len();
        self.zi_2_32_vector.reserve(1 << 22);

        for &zi_2_16 in self.keystreamtab.get_zi_2_16_array(*self.keystream.last().unwrap()).iter() {
            for high in 0..(1<<16) {
                self.zi_2_32_vector.push(high << 16 | zi_2_16);
            }
        }
    }

    pub fn reduce(&mut self) {
        // variables to keep track of the smallest Zi[2,32) vector
        let mut tracking = false;
        let mut best_copy = Vec::new();
        let (mut best_index, mut best_size) = (0usize, Zreduction::TRACK_SIZE);

        // variables to wait for a limited number of steps when a small enough vector is found
        let mut waiting = false;
        let mut wait = 0usize;

        for i in (Attack::SIZE..self.index).rev() {
            let mut zim1_2_32_vector = Vec::new();

            // generate the Z{i-1}[2,32) values
            for &zi_2_32 in &self.zi_2_32_vector {
                // get Z{i-1}[10,32) from CRC32^-1
                let zim1_10_32 = self.crc32tab.get_zim1_10_32(zi_2_32);

                // get Z{i-1}[2,16) values from keystream byte k{i-1} and Z{i-1}[10,16)
                for &zim1_2_16 in self.keystreamtab.get_zi_2_16_vector(self.keystream[i-1], zim1_10_32) {
                    //println!("({} {})", zi_2_32, zim1_10_32);
                    zim1_2_32_vector.push(zim1_10_32 | zim1_2_16);
                }
            }
            //std::process::exit(1);

            // remove duplicates
            zim1_2_32_vector.sort();
            zim1_2_32_vector.dedup();

            // update smallest vector tracking
            if zim1_2_32_vector.len() <= best_size {
                tracking = true;
                best_index = i - 1;
                best_size = zim1_2_32_vector.len();
                waiting = false;
            } else if tracking { // vector is bigger than bestSize
                if best_index == i { // hit a minimum
                    // keep a copy of the vector because size is about to grow
                    best_copy = self.zi_2_32_vector.clone();

                    if best_size <= Zreduction::WAIT_SIZE {
                        // enable waiting
                        waiting = true;
                        wait = best_size * 4;
                    }
                }

                wait -= 1;
                if waiting && wait == 0 {
                    break;
                }
            }

            // put result in z_2_32_vector
            mem::swap(&mut self.zi_2_32_vector, &mut zim1_2_32_vector);
            // self.zi_2_32_vector = zim1_2_32_vector;
            let now = self.keystream.len() - i;
            let total = self.keystream.len() - Attack::SIZE;
            print!("\r{:.2} % ({} / {})", now as f32 / total as f32 * 100.0, now, total);
        }

        if tracking {
            // put bestCopy in z_2_32_vector only if bestIndex is not the index of z_2_32_vector
            if best_index != Attack::SIZE - 1 {
                mem::swap(&mut self.zi_2_32_vector, &mut best_copy);
                //self.zi_2_32_vector = best_copy;
            }
            self.index = best_index;
        } else {
            self.index = Attack::SIZE - 1;
        }
    }

    pub fn size(&self) -> usize {
        self.zi_2_32_vector.len()
    }

    pub fn get_index(&self) -> usize {
        self.index
    }
}