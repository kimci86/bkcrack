use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process;
use std::mem;

fn read<T>(stream: &mut File, x: &mut T) {
    let size = mem::size_of::<T>();
    match size {
        1 => {
            let x = unsafe { mem::transmute::<&mut T, &mut [u8; 1]>(x) };
            stream.read_exact(x).unwrap();
        },
        2 => {
            let x = unsafe { mem::transmute::<&mut T, &mut [u8; 2]>(x) };
            stream.read_exact(x).unwrap();
        },
        4 => {
            let x = unsafe { mem::transmute::<&mut T, &mut [u8; 4]>(x) };
            stream.read_exact(x).unwrap();
        },
        8 => {
            let x = unsafe { mem::transmute::<&mut T, &mut [u8; 8]>(x) };
            stream.read_exact(x).unwrap();
        },
        _ => (),
    }
}

pub fn load_stream(is: &File, size: usize) -> Vec<u8> {
    is.take(size as u64).bytes().map(|c|c.unwrap()).collect::<Vec<_>>()
}

pub fn load_file(filename: &str, size: usize) -> Vec<u8> {
    let is = open_input(filename);
    load_stream(&is, size)
}

pub fn load_zip_entry(archivename: &str, entryname: &str, size: usize) -> Vec<u8> {
    let mut entrysize = 0usize;
    let is = open_input_zip_entry(archivename, entryname, &mut entrysize);
    load_stream(&is, entrysize.min(size))
}

fn open_input(filename: &str) -> File {
    let file = File::open(filename).unwrap_or_else(|e| {
        eprintln!("Could not open input file: {}", e);
        process::exit(1);
    });
    file
}

fn open_input_zip_entry(archivename: &str, entryname: &str, size: &mut usize) -> File {
    let mut is = open_input(archivename);

    // look for end of central directory
    is.seek(io::SeekFrom::End(-22)).unwrap(); // start by assuming there is no comment
    let mut sig = 0u32;
    read(&mut is, &mut sig);
    is.seek(io::SeekFrom::Current(-4)).unwrap();
    while sig != 0x06054b50 {
        is.seek(io::SeekFrom::Current(-1)).unwrap();
        read(&mut is, &mut sig);
        is.seek(io::SeekFrom::Current(-4)).unwrap();
    }

    let eocdoffset = is.seek(io::SeekFrom::Current(0)).unwrap(); // end of central directory offset

    // read central directory offset
    let mut cdoffset = 0u32;
    is.seek(io::SeekFrom::Current(16)).unwrap();
    read(&mut is, &mut cdoffset);

    // iterate on each entry
    is.seek(io::SeekFrom::Start(cdoffset as u64)).unwrap();
    let mut name = String::new();
    let (mut compressed_size, mut offset) = (0u32, 0u32);

    while &name != entryname && is.seek(io::SeekFrom::Current(0)).unwrap() != eocdoffset {
        let (mut name_size, mut extra_size, mut comment_size): (u16, u16, u16) = (0, 0, 0);

        is.seek(io::SeekFrom::Current(20)).unwrap();
        read(&mut is, &mut compressed_size);
        is.seek(io::SeekFrom::Current(4)).unwrap();
        read(&mut is, &mut name_size);
        read(&mut is, &mut extra_size);
        read(&mut is, &mut comment_size);
        is.seek(io::SeekFrom::Current(8)).unwrap();
        read(&mut is, &mut offset);

        let mut bytes = vec![0u8; name_size as usize];
        is.read_exact(&mut bytes).unwrap();
        is.seek(io::SeekFrom::Current((extra_size + comment_size) as i64)).unwrap();

        name = bytes.iter().map(|&b| b as char).collect::<String>();
        //println!("{} {} {}", name, is.seek(io::SeekFrom::Current(0)).unwrap(), eocdoffset);
    }


    // TODO: 应该要抛个异常
    if name != entryname {
        eprintln!("Could not find {}  in archive {}", entryname, archivename);
        process::exit(1);
    }

    // read local file header
    let mut extra_size = 0u16;
    is.seek(io::SeekFrom::Start(offset as u64 + 28)).unwrap();
    read(&mut is, &mut extra_size);
    is.seek(io::SeekFrom::Current(name.len() as i64 + extra_size as i64)).unwrap();

    *size = compressed_size as usize;

    is
}