use std::io::Cursor;
use std::io::SeekFrom;
use std::io::Read;
use std::io::prelude::*;
use std::collections::HashMap;
use byteorder::{ReadBytesExt, LittleEndian};

use crypto;

#[derive(PartialEq,Eq,Hash,Debug,Clone,Copy)]
pub enum Kind {
	Unknown,
	Version,
	UUID,
	End,
	Group,
	Title,
	Username,
	Notes,
	Password,
}

#[derive(PartialEq,Eq,Hash,Debug,Clone,Copy)]
pub enum Type {
	Raw,
	Short,
	Text,
}

#[derive(Debug,Clone)]
pub struct Def {
    pub kind: Kind,
	pub tp: Type,
}

lazy_static! {
    pub static ref HEADER: HashMap<u8,Def> = {
        let mut m = HashMap::new();
        m.insert(0x00, Def{kind: Kind::Version, tp: Type::Short });
        m.insert(0x01, Def{kind: Kind::UUID,    tp: Type::Raw   });
        m.insert(0xff, Def{kind: Kind::End,     tp: Type::Raw   });
        m
    };

    pub static ref DATA: HashMap<u8,Def> = {
        let mut m = HashMap::new();
        m.insert(0x01, Def{kind: Kind::UUID,     tp: Type::Raw  });
        m.insert(0x02, Def{kind: Kind::Group,    tp: Type::Text });
        m.insert(0x03, Def{kind: Kind::Title,    tp: Type::Text });
        m.insert(0x04, Def{kind: Kind::Username, tp: Type::Text });
        m.insert(0x05, Def{kind: Kind::Notes,    tp: Type::Text });
        m.insert(0x06, Def{kind: Kind::Password, tp: Type::Text });
        m.insert(0xff, Def{kind: Kind::End,      tp: Type::Raw  });
        m
    };
}

#[derive(Debug)]
pub enum Data {
	Raw(Vec<u8>),
	Short(u16),
	Text(String),
}

#[derive(Debug)]
pub struct Field {
    pub def: Def,
    pub data: Data,
}

#[derive(Debug)]
pub struct Item {
    pub field: HashMap<Kind, Field>,
}

pub fn new(map: &HashMap<u8,Def>, val: u8, data: &[u8]) -> Field {
    match map.get(&val) {
        None => return Field{
            def: Def {
                kind: Kind::Unknown,
                tp: Type::Raw,
            },
            data: Data::Raw(data.to_vec()),
        },
        Some(def) => {
            match def.tp {
                Type::Short =>
                    return Field{
                        def: def.clone(),
                        data: Data::Short(((data[1] as u16) << 8) | (data[0] as u16)),
                    },

                Type::Text =>
                    return Field{
                        def: def.clone(),
                        data: Data::Text(String::from_utf8_lossy(data).into_owned()),
                    },

                Type::Raw =>
                    return Field{
                        def: def.clone(),
                        data: Data::Raw(data.to_vec()),
                    },
            }
        }
    }
}

fn skip_padding(c: &mut Cursor<&[u8]>, len: u32) {
    let rem = (5 + len) % 16;
    if rem != 0 {
        c.seek(SeekFrom::Current(16 - rem as i64)).unwrap();
    }
}

pub fn parse_field(mac: &mut crypto::HMAC, map: &HashMap<u8,Def>, c: &mut Cursor<&[u8]>) -> Option<Field> {
    let len = match c.read_u32::<LittleEndian>() {
        Ok(v) => v,
        Err(_) => return None,
    };

    let tp = c.read_u8().unwrap();

    let mut v = Vec::new();
    v.resize(len as usize, 0);
    c.read_exact(&mut v).unwrap();

    mac.update(&v[..]);

    let i = Some(new(map, tp, &v[..]));
    skip_padding(c, len);
    return i;
}

pub fn parse(mac: &mut crypto::HMAC, map: &HashMap<u8, Def>, c: &mut Cursor<&[u8]>) -> Option<Item> {
    let mut m = HashMap::new();

    loop {
        match parse_field(mac, map, c) {
            Some(f) => {
                if f.def.kind == Kind::End {
                    break;
                }
                if f.def.kind != Kind::Unknown {
                    m.insert(f.def.kind, f);
                }
            },
            None => {
                assert!(m.len() == 0);
                return None;
            },
        }
    }
    return Some(Item{
        field: m,
    });
}
