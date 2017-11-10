use std::str;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::io::Error;
use byteorder::{ReadBytesExt, LittleEndian};

use crypto;
use item;

#[derive(Debug)]
pub struct V3 {
	path: String,
	salt: [u8; 32],
	iter: u32,
}

impl V3 {
	pub fn new(path: &str) -> V3 {
		crypto::init();

		V3 {
			path: path.to_string(),
			salt: [0; 32],
			iter: 0,
		}
    }

	fn check_tag(&self, f: &mut File) -> Result<(), Error> {
		let mut tag: [u8; 4] = [0; 4];
		f.read_exact(&mut tag)?;
		let tag = str::from_utf8(&tag).unwrap();
		if tag != "PWS3" {
			panic!("Wrong file format!");
		}
		Ok(())
	}

	fn check_password(&self, f: &mut File, password: &str) -> [u8; 32] {
		let mut expected: [u8; 32] = [0; 32];
		f.read_exact(&mut expected).unwrap();

		let got = crypto::stretch(password, &self.salt, self.iter);
		assert_eq!(crypto::sha256(&got), expected);
		got
	}

	pub fn unlock(&mut self, _password: &str) -> Result<(), Error> {
		// TODO: add comments

		let mut f = File::open(&self.path)?;

		self.check_tag(&mut f)?;
		f.read_exact(&mut self.salt)?;
		self.iter = f.read_u32::<LittleEndian>().unwrap();

		println!("iter: {}", self.iter);

		let p = self.check_password(&mut f, _password);

		let mut b12: [u8; 32] = [0; 32];
		f.read_exact(&mut b12).unwrap();

		let mut b34: [u8; 32] = [0; 32];
		f.read_exact(&mut b34).unwrap();

		let mut iv: [u8; 16] = [0; 16];
		f.read_exact(&mut iv).unwrap();

		let k = crypto::decrypt_block_ecb(&b12, &p);
		let l = crypto::decrypt_block_ecb(&b34, &p);

		println!("p={:?}", p);
		println!("k={:?}", k);
		println!("expected k=[64, ]");

		let mut d: Vec<u8> = Vec::new();

		f.read_to_end(&mut d).unwrap();


		let eof = d.windows(16).position(|w| w == "PWS3-EOFPWS3-EOF".as_bytes()).unwrap();
		println!("eof={} vs {}", eof, d.len());

		println!("b12={:?}", b12);

		crypto::decrypt_inplace(&mut d[0..eof], &k, &iv);

        let mut mac = crypto::HMAC::new(&l);
		let mut c = Cursor::new(&d[0 .. eof]);

        // header
        match item::parse(&mut mac, &item::HEADER, &mut c) {
            Some(hdr) => println!("header {:?}", hdr),
            None => println!("GOT NOTHING!"), // TODO: fixme
        }

        // entries
		loop {
            match item::parse(&mut mac, &item::DATA, &mut c) {
                Some(item) => println!("data {:?}", item),
                None => break,
            }
		}

		let expected_hmac = &d[eof+16 .. eof+16+32];
        match mac.verify(expected_hmac) {
            Ok(_) => println!("matches"),
            Err(_) => println!("doesn't match"),
        }

		Ok(())
	}
}
