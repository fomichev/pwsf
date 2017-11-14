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
    PasswordHistory,
    PasswordPolicy,
    PasswordSymbols,
    CreateTime,
    AccessTime,
    ExpiryTime,
    ModifyTime,
    SClickAction,
    DClickAction,
    Autotype,
    RunCommand,
    Protected,
    Email,
}

#[derive(PartialEq,Eq,Hash,Debug,Clone,Copy)]
pub enum Type {
    Raw,
    Byte,
    Short,
    Int,
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
        m.insert(0x01, Def{kind: Kind::UUID,            tp: Type::Raw   });
        m.insert(0x02, Def{kind: Kind::Group,           tp: Type::Text  });
        m.insert(0x03, Def{kind: Kind::Title,           tp: Type::Text  });
        m.insert(0x04, Def{kind: Kind::Username,        tp: Type::Text  });
        m.insert(0x05, Def{kind: Kind::Notes,           tp: Type::Text  });
        m.insert(0x06, Def{kind: Kind::Password,        tp: Type::Text  });
        m.insert(0x07, Def{kind: Kind::CreateTime,      tp: Type::Int   });
        m.insert(0x09, Def{kind: Kind::AccessTime,      tp: Type::Int   });
        m.insert(0x0a, Def{kind: Kind::ExpiryTime,      tp: Type::Int   });
        m.insert(0x0c, Def{kind: Kind::ModifyTime,      tp: Type::Int   });
        m.insert(0x0e, Def{kind: Kind::Autotype,        tp: Type::Text  });
        m.insert(0x0f, Def{kind: Kind::PasswordHistory, tp: Type::Text  });
        m.insert(0x10, Def{kind: Kind::PasswordPolicy,  tp: Type::Text  });
        m.insert(0x12, Def{kind: Kind::RunCommand,      tp: Type::Text  });
        m.insert(0x13, Def{kind: Kind::DClickAction,    tp: Type::Short });
        m.insert(0x14, Def{kind: Kind::Email,           tp: Type::Text  });
        m.insert(0x15, Def{kind: Kind::Protected,       tp: Type::Byte  });
        m.insert(0x16, Def{kind: Kind::PasswordSymbols, tp: Type::Text  });
        m.insert(0x17, Def{kind: Kind::SClickAction,    tp: Type::Short });
        m.insert(0xff, Def{kind: Kind::End,             tp: Type::Raw   });
        m
    };
}

#[derive(PartialEq,Eq,Hash,Debug,Clone)]
pub enum Data {
    Raw(Vec<u8>),
    Byte(u8),
    Short(u16),
    Int(u32),
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

impl Item {
    pub fn get(&self, k: Kind) -> Option<&Data> {
        match self.field.get(&k) {
            None => return None,
            Some(v) => return Some(&v.data),
        }
    }
}

fn new_field(map: &HashMap<u8,Def>, val: u8, data: &[u8]) -> Field {
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
                Type::Byte =>
                    return Field{
                        def: def.clone(),
                        data: Data::Byte(data[0]),
                    },

                Type::Short =>
                    return Field{
                        def: def.clone(),
                        data: Data::Short(((data[1] as u16) << 8) | (data[0] as u16)),
                    },

                Type::Int =>
                    return Field{
                        def: def.clone(),
                        data: Data::Int(((data[3] as u32) << 24) | ((data[2] as u32) << 16) | ((data[1] as u32) << 8) | (data[0] as u32)),
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
        c.seek(SeekFrom::Current(16 - rem as i64)).expect("Corrupted field, can't skip padding");
    }
}

pub fn parse_field(mac: &mut crypto::HMAC, map: &HashMap<u8,Def>, c: &mut Cursor<&[u8]>) -> Option<Field> {
    let len = match c.read_u32::<LittleEndian>() {
        Ok(v) => v,
        Err(_) => return None,
    };

    let tp = c.read_u8().expect("Corrupted field, can't read type");

    let mut v = Vec::new();
    v.resize(len as usize, 0);
    c.read_exact(&mut v).expect("Corrupted field, can't read contents");

    mac.update(&v[..]);

    let i = Some(new_field(map, tp, &v[..]));
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
    return Some(Item{field: m});
}
