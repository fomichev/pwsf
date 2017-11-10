mod keychain;
mod crypto;
mod item;

#[macro_use]
extern crate lazy_static;

extern crate byteorder;

fn main() {
	let mut kc = keychain::V3::new("./simple.psafe3");
	kc.unlock("bogus12345").unwrap();
}
