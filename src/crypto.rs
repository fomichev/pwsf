extern crate gcrypt;

pub struct HMAC {
    mac: self::gcrypt::mac::Mac,
}

impl HMAC {
    pub fn new(key: &[u8]) -> HMAC {
        use self::gcrypt::mac::{Mac, Algorithm};

        let mut h = Mac::new(Algorithm::HmacSha256).unwrap();
        h.set_key(key);

        HMAC {
            mac: h,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data).unwrap();
    }

    pub fn verify(&mut self, expected: &[u8]) -> Result<(), gcrypt::Error> {
        return self.mac.verify(expected);
    }

    pub fn prn(&mut self, prefix: &str) {
        let mut buf: [u8; 32] = [0; 32];
        self.mac.get_mac(&mut buf[..]).unwrap();
		println!("{} hmac={:?}", prefix, buf);
    }

    // TODO(sdf): rename to verify and use builtin verify method
    pub fn matches(&mut self, expected: &[u8]) -> bool {
        let mut buf: [u8; 32] = [0; 32];
        self.mac.get_mac(&mut buf[..]).unwrap();
		println!("new hmac={:?}", buf);
        return buf == expected;
    }
}

pub fn init() {
	gcrypt::init(|x| { x.disable_secmem(); });
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
	use self::gcrypt::digest::{MessageDigest,Algorithm};

	let mut output: [u8; 32] = [0; 32];

	let mut h = MessageDigest::new(Algorithm::Sha256).unwrap();
	h.update(&input);
	h.finish();
	output.copy_from_slice(h.get_only_digest().unwrap());

	output
}

pub fn stretch(password: &str, salt: &[u8], iter: u32) -> [u8; 32] {
	use self::gcrypt::digest::{MessageDigest,Algorithm};

	let mut h = MessageDigest::new(Algorithm::Sha256).unwrap();
	h.update(password.as_bytes());
	h.update(salt);
	h.finish();

	let mut b: [u8; 32] = [0; 32];
	b.copy_from_slice(h.get_only_digest().unwrap());

	for _ in 0..iter {
		h.reset();
		h.update(&b);
		b.copy_from_slice(h.get_only_digest().unwrap());
	}

	b.clone()
}

pub fn decrypt_block_ecb(block: &[u8], key: &[u8]) -> [u8; 32] {
	use self::gcrypt::cipher::{Cipher, Algorithm, Mode};

	let mut ct: [u8; 32] = [0; 32];

	let mut c = Cipher::new(Algorithm::Twofish, Mode::Ecb).unwrap();
	c.set_key(&key).unwrap();
	c.decrypt(&block, &mut ct).unwrap();
	ct.clone()
}

pub fn decrypt_inplace(data: &mut [u8], key: &[u8], iv: &[u8]) {
	use self::gcrypt::cipher::{Cipher, Algorithm, Mode};

	let mut c = Cipher::new(Algorithm::Twofish, Mode::Cbc).unwrap();
	c.set_iv(iv).unwrap();
	c.set_key(key).unwrap();
	c.decrypt_inplace(data).unwrap();
}
