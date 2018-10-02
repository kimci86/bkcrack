#[macro_use]
extern crate clap;
extern crate chrono;

use clap::App;
use chrono::Local;
use bkcrack::{Attack, Data, Zreduction};

fn now() -> String {
    Local::now().format("%T").to_string()
}

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let cipherarchive = matches.value_of("encryptedzip").unwrap();
    let plainarchive = matches.value_of("plainzip").unwrap();

    let cipherfile = matches.value_of("cipherfile").unwrap();
    let plainfile = matches.value_of("plainfile").unwrap();

    // load data
    let mut data = Data::new();
    data.load(cipherarchive, cipherfile, plainarchive, plainfile).unwrap();

    // generate and reduce Zi[2,32) values
    let mut zr = Zreduction::new(&data.keystream);
    zr.generate();
    println!("Generated {} Z values.", zr.size());

    if data.keystream.len() > Attack::SIZE {
        println!("[{}] Z reduction using {} extra bytes of known plaintext", now(), data.keystream.len() - Attack::SIZE);
        zr.reduce();
        println!("\n{} values remaining.", zr.size());
    }

    // iterate over remaining Zi[2,32) values
    let mut attack = Attack::new(&data, zr.get_index() - 11);
    let mut done = 1;
    let size = zr.size();
    println!("[{}] Attack on {} Z values at index {}", now(), size, data.offset + zr.get_index() as i32);

    for it in zr.zi_2_32_vector {
        if attack.carry_out(it) {
            break;
        }
        done += 1;
        print!("\r{:.2} % ({} / {})", done as f32 / size as f32 * 100.0, done, size);
    }
    println!();

    // print the keys
    let x = attack.get_keys();

    println!("[{}] Keys\n{:x} {:x} {:x}", now(), x.get_x(), x.get_y(), x.get_z());
}
