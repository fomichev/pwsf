extern crate gcrypt;

pub struct HMAC {
    mac: self::gcrypt::mac::Mac,
}

impl HMAC {
    pub fn new(key: &[u8]) -> HMAC {
        use self::gcrypt::mac::{Mac, Algorithm};

        let mut h = Mac::new(Algorithm::HmacSha256).expect("Couldn't initialize HMAC");
        h.set_key(key).expect("Couldn't set HMAC key");

        return HMAC {mac: h};
    }

    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data).expect("Couldn't update HMAC");
    }

    pub fn verify(&mut self, expected: &[u8]) -> Result<(), gcrypt::Error> {
        return self.mac.verify(expected);
    }
}

pub fn init() {
    gcrypt::init(|x| { x.disable_secmem(); });
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    use self::gcrypt::digest::{MessageDigest,Algorithm};

    let mut output: [u8; 32] = [0; 32];
    let mut h = MessageDigest::new(Algorithm::Sha256).expect("Couldn't initialize SHA256");
    h.update(&input);
    h.finish();
    output.copy_from_slice(h.get_only_digest().expect("Couldn't get SHA256 digest"));

    return output;
}

pub fn stretch(password: &str, salt: &[u8], iter: u32) -> [u8; 32] {
    use self::gcrypt::digest::{MessageDigest,Algorithm};

    let mut h = MessageDigest::new(Algorithm::Sha256).expect("Couldn't initialize SHA256");
    h.update(password.as_bytes());
    h.update(salt);
    h.finish();

    let mut b: [u8; 32] = [0; 32];
    b.copy_from_slice(h.get_only_digest().expect("Couldn't get SHA256 digest"));

    for _ in 0..iter {
        h.reset();
        h.update(&b);
        b.copy_from_slice(h.get_only_digest().expect("Couldn't get SHA256 digest"));
    }

    return b.clone();
}

pub fn decrypt_block_ecb(block: &[u8], key: &[u8]) -> [u8; 32] {
    use self::gcrypt::cipher::{Cipher, Algorithm, Mode};

    let mut ct: [u8; 32] = [0; 32];
    let mut c = Cipher::new(Algorithm::Twofish, Mode::Ecb).expect("Couldn't initialize ECB Twofish");
    c.set_key(&key).expect("Couldn't set ECB Twofish key");
    // TODO: handle and return decryption error
    c.decrypt(&block, &mut ct).unwrap();
    return ct.clone();
}

pub fn decrypt_inplace(data: &mut [u8], key: &[u8], iv: &[u8]) {
    use self::gcrypt::cipher::{Cipher, Algorithm, Mode};

    let mut c = Cipher::new(Algorithm::Twofish, Mode::Cbc).expect("Couldn't initialize CBC Twofish");
    c.set_iv(iv).expect("Couldn't set CBC Twofish IV");
    c.set_key(key).expect("Couldn't set CBC Twofish key");
    // TODO: handle and return decryption error
    c.decrypt_inplace(data).unwrap();
}
