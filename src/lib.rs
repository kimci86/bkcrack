#[macro_use] extern crate failure;

mod attack;
mod crc32_tab;
mod data;
mod file;
mod keys;
mod keystream_tab;
mod mult_tab;
mod utils;
mod zreduction;

pub use self::data::Data;
pub use self::zreduction::Zreduction;
pub use self::attack::Attack;

#[cfg(test)]
mod tests {
    use super::{Attack, Data, Zreduction};

    #[test]
    fn crack() {
        let mut data = Data::new();
        data.offset = 0;
        data.load("./example/cipher.zip", "file", "./example/plain.zip", "file").unwrap();

        let mut zr = Zreduction::new(&data.keystream);
        zr.generate();
        zr.reduce();
        
        let mut attack = Attack::new(&data, zr.get_index() - 11);
        for it in zr.zi_2_32_vector {
            if attack.carry_out(it) {
                println!("\nfound!");
                break;
            }
        }

        let keys = attack.get_keys();

        assert_eq!(0x8879dfed, keys.get_x());
        assert_eq!(0x14335b6b, keys.get_y());
        assert_eq!(0x8dc58b53, keys.get_z());
    }
}