mod keychain;
mod crypto;
mod item;

#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate getopts;
extern crate rpassword;
extern crate regex;
#[macro_use]
extern crate log;

#[cfg(test)]
mod tests;

use getopts::Options;
use std::env;
use std::io;
use regex::Regex;

fn print_usage(exe: &str, opts: Options) {
    let brief = format!("Usage: {0} [options] <list|copy|show>

  {0} list [<name regexp>]
    list all entries or entries matching given regexp

  {0} copy <name regexp>
    copy password to clipboard, after user presses any key, copy username and exit

  {0} show <name regexp>
    print all fields for matching entries

  Examples:
    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S list
    Test eight
    Test Four
    Test.Test One
    Test seven
    Test Two
    Test.Test Nine
    Test six
    Test.Test One
    Test Five

    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S list \\.Test
    Test.Test One
    Test.Test Nine
    Test.Test One

    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S copy 'Test six'
    Password is now in your clipboard, press ENTER to copy username", exe);

    print!("{}", opts.usage(&brief));
}

fn op_list(kc: &keychain::V3, args: &[String]) {
    let re = Regex::new(&args.join("")).expect("Can't parse regular expression");

    kc.each_re(&re, &|name: &str, _: &item::Item| {
        println!("{}", name);
    });
}

fn op_copy(kc: &keychain::V3, args: &[String]) {
    let re = Regex::new(&args.join("")).expect("Can't parse regular expression");

    kc.each_re(&re, &|name: &str, _: &item::Item| {
        println!("{}", name);
    });
}

fn op_show(kc: &keychain::V3, args: &[String]) {
    let re = Regex::new(&args.join("")).expect("Can't parse regular expression");

    kc.each_re(&re, &|name: &str, i: &item::Item| {
        println!("{}:", name);
        for (k, v) in i.iter() {
            if *k != item::Kind::UUID {
                println!("\t{:?}: {}", k, v.to_string());
            }
        }
        println!("");
    });
}

fn run_op(kc: &keychain::V3, op: &Vec<String>) -> bool {
    match op[0].as_ref() {
        "list" => op_list(kc, &op[1..]),
        "copy" => op_copy(kc, &op[1..]),
        "show" => op_show(kc, &op[1..]),
        _ => return false,
    }

    return true;
}

fn main() {
    let mut opts = Options::new();
    opts.optopt("p", "db-path", "path to the database", "PATH");
    opts.optflag("S", "stdin", "read password from stdin");
    opts.optflag("h", "help", "print this help menu");

    let args: Vec<String> = env::args().collect();
    let exe = args[0].clone();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("h") || matches.free.is_empty() {
        print_usage(&exe, opts);
        return;
    }

    let db_path = match matches.opt_str("p") {
        Some(p) => p,
        None => "~/.pwsafe/default.psafe3".to_string(),
    };

    let mut password = String::new();
    if matches.opt_present("S") {
        io::stdin().read_line(&mut password).expect("Can't read password from stdin!");
    } else {
        password = rpassword::prompt_password_stdout("Password: ").expect("Can't query password");
    }

    match keychain::V3::new(&db_path, &password) {
        Some(kc) => {
            if !run_op(&kc, &matches.free) {
                print_usage(&exe, opts);
            }
        },
        None => {},
    }
}
