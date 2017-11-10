mod keychain;
mod crypto;
mod item;

#[macro_use]
extern crate lazy_static;

extern crate byteorder;

#[cfg(test)]
mod tests;

// TODO:
// - figure out error handling
// - cli wrapper
// - remove all debug prints

fn main() {
	let mut kc = keychain::V3::new("./simple.psafe3");
	kc.unlock("bogus12345").unwrap();
    for i in kc.iter() {
        println!("{:?}", i);
    }
}
