use std;
use std::str;
use std::error::Error;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use byteorder::{ReadBytesExt, LittleEndian};
use regex::Regex;

use crypto;
use item;

#[derive(Debug)]
pub struct V3 {
    path: String,
    salt: [u8; 32],
    iter: u32,
    header: Option<item::Item>,
    items: Vec<item::Item>,
}

impl V3 {
    pub fn new(path: &str, password: &str) -> Option<V3> {
        crypto::init();

        let mut kc = V3 {
            path: path.to_string(),
            salt: [0; 32],
            iter: 0,
            header: None,
            items: Vec::new(),
        };

        match kc.unlock(password) {
            true => return Some(kc),
            false => return None,
        };
    }

    fn has_tag(&self, f: &mut File) -> bool {
        let mut tag: [u8; 4] = [0; 4];

        match f.read_exact(&mut tag) {
            Err(e) => {
                eprintln!("Can't read tag: {}", e.description());
                return false;
            }
            _ => (),
        };

        match str::from_utf8(&tag) {
            Err(e) => {
                eprintln!("Can't convert tag to UTF8: {}", e.description());
                return false;
            }
            Ok(tag) => {
                if tag != "PWS3" {
                    eprintln!("Got invalid tag: {}", tag);
                    return false;
                }
                return true;
            }
        }
    }

    fn stretch_password(&self, f: &mut File, password: &str) -> Option<[u8; 32]> {
        let mut expected: [u8; 32] = [0; 32];
        match f.read_exact(&mut expected) {
            Ok(_) => {
                let got = crypto::stretch(password, &self.salt, self.iter);
                if crypto::sha256(&got) != expected {
                    return None;
                }
                return Some(got);
            }
            _ => return None,
        }
    }

    fn unlock(&mut self, password: &str) -> bool {
        let mut f = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Can't open database at '{}': {}", self.path, e.description());
                return false;
            }
        };

        // make sure we are reading expected file format
        if !self.has_tag(&mut f) {
            return false;
        }

        // read salt and iv
        match f.read_exact(&mut self.salt) {
            Err(e) => {
                eprintln!("Can't open database: {}", e.description());
                return false;
            },
            _ => (),
        }

        self.iter = match f.read_u32::<LittleEndian>() {
            Err(e) => {
                eprintln!("Can't read number of password iterations: {}", e.description());
                return false;
            },
            Ok(i) => i,
        };

        // stretch password
        let stretched = match self.stretch_password(&mut f, password) {
            Some(p) => p,
            None => {
                eprintln!("Invalid password");
                return false;
            },
        };

        // read and decrypt all initial settings
        let mut b12: [u8; 32] = [0; 32];
        match f.read_exact(&mut b12) {
            Err(e) => {
                eprintln!("Can't read B12: {}", e.description());
                return false;
            },
            _ => (),
        }

        let mut b34: [u8; 32] = [0; 32];
        match f.read_exact(&mut b34) {
            Err(e) => {
                eprintln!("Can't read B34: {}", e.description());
                return false;
            },
            _ => (),
        }

        let mut iv: [u8; 16] = [0; 16];
        match f.read_exact(&mut iv) {
            Err(e) => {
                eprintln!("Can't read IV: {}", e.description());
                return false;
            },
            _ => (),
        }

        let k = match crypto::decrypt_block_ecb(&b12, &stretched) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Can't decrypt K, probably invalid password: {}", e.description());
                return false;
            },
        };
        let l = match crypto::decrypt_block_ecb(&b34, &stretched) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Can't decrypt L, probably invalid password: {}", e.description());
                return false;
            },
        };

        // read the remainder into vector and find the EOF marker
        let mut d: Vec<u8> = Vec::new();

        f.read_to_end(&mut d).expect("Can't read whole database file");

        let eof_pos = match d.windows(16).position(|w| w == "PWS3-EOFPWS3-EOF".as_bytes()) {
            Some(pos) => pos,
            None => {
                eprintln!("Can't find EOF marker");
                return false;
            },
        };

        match crypto::decrypt_inplace(&mut d[0..eof_pos], &k, &iv) {
            Err(e) => {
                eprintln!("Can't decrypt data: {}", e.description());
                return false;
            }
            _ => (),
        }

        let mut mac = crypto::HMAC::new(&l);
        let mut c = Cursor::new(&d[0 .. eof_pos]);

        // header
        match item::parse(&mut mac, &item::HEADER, &mut c) {
            Some(hdr) => self.header = Some(hdr),
            None => {
                eprintln!("Can't read header item");
                return false;
            },
        }

        // entries
        loop {
            match item::parse(&mut mac, &item::DATA, &mut c) {
                Some(item) => self.items.push(item),
                None => break,
            }
        }

        // verify mac
        let expected_hmac = &d[eof_pos+16 .. eof_pos+16+32];
        match mac.verify(expected_hmac) {
            Err(e) => {
                eprintln!("Can't verify HMAC: {}", e.description());
                return false;
            },
            _ => (),
        }

        return true;
    }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.items.len() }

    pub fn iter(&self) -> std::slice::Iter<item::Item> { self.items.iter() }

    pub fn each(&self, f: &mut FnMut(&str, &item::Item)) {
        for i in self.iter() {
            let mut name = String::new();

            match i.get(item::Kind::Group) {
                Some(g) => {
                    match g {
                        &item::Data::Text(ref v) => {
                            name.push_str(v);
                            name.push('.');
                        },
                        _ => panic!("Unexpected group type"),
                    }
                },
                _ => (),
            }

            match i.get(item::Kind::Title) {
                Some(t) => {
                    match t {
                        &item::Data::Text(ref v) => name.push_str(v),
                        _ => panic!("Unexpected title type"),
                    }
                },
                _ => (),
            }

            f(&name, &i);
        }
    }

    pub fn each_re(&self, re: &Regex, f: &mut FnMut(&str, &item::Item)) {
        self.each(&mut|name: &str, i: &item::Item| {
            if re.is_match(&name) {
                f(name, i);
            }
        });
    }
}
