use super::attack::*;
use super::failure::Error;
use super::file::*;

pub struct Data {
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub keystream: Vec<u8>,
    pub offset: i32,
}

impl Data {
    pub fn new() -> Data {
        Data {
            ciphertext: Vec::new(),
            plaintext: Vec::new(),
            keystream: Vec::new(),
            offset: 0,
        }
    }

    pub const HEADER_SIZE: usize = 12;

    pub fn load(
        &mut self,
        cipherarchive: &str,
        cipherfile: &str,
        plainarchive: &str,
        plainfile: &str,
    ) -> Result<(), Error> {
        // check that offset is not too small
        if Data::HEADER_SIZE as i32 + self.offset < 0 {
            return Err(format_err!("offset is too small"));
        }

        // load known plaintext
        self.plaintext = if plainarchive.is_empty() {
            load_file(plainfile, std::usize::MAX)
        } else {
            load_zip_entry(plainarchive, plainfile, std::usize::MAX)
        };

        // check that plaintext is big enough
        if self.plaintext.len() < Attack::SIZE {
            return Err(format_err!("plaintext is too small"));
        }

        // load ciphertext needed by the attack
        let to_read = Data::HEADER_SIZE + self.offset as usize + self.plaintext.len();
        self.ciphertext = if cipherarchive.is_empty() {
            load_file(cipherfile, to_read)
        } else {
            load_zip_entry(cipherarchive, cipherfile, to_read)
        };

        // check that ciphertext is valid
        if self.plaintext.len() > self.ciphertext.len() {
            return Err(format_err!("ciphertext is smaller than plaintext"));
        } else if Data::HEADER_SIZE + self.offset as usize + self.plaintext.len()
            > self.ciphertext.len()
        {
            return Err(format_err!("offset is too large"));
        }

        // compute keystream
        self.keystream = self
            .plaintext
            .iter()
            .zip(
                self.ciphertext
                    .iter()
                    .skip(Data::HEADER_SIZE + self.offset as usize),
            )
            .map(|(x, y)| x ^ y)
            .collect();
        Ok(())
    }
}
