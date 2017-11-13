mod keychain;
mod crypto;
mod item;

#[macro_use]
extern crate lazy_static;
extern crate byteorder;
extern crate getopts;
extern crate rpassword;
extern crate regex;

#[cfg(test)]
mod tests;

use getopts::Options;
use std::env;
use std::io;
use regex::Regex;

fn print_usage(exe: &str, opts: Options) {
    let brief = format!("Usage: {0} [options] <list|copy|query>

  {0} list [<name regexp>]
    list all entries or entries matching given regexp

  {0} copy <name regexp>
    copy password to clipboard, after user presses any key, copy username and exit

  {0} query <field> [<field>~<regexp>]
    print given field for each entry where field matches given regexp

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

    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S query username
    user8
    user4
    user2
    user7
    user3
    user9
    user6
    user1
    user5

    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S query username name~six

    $ echo -n bogus12345 | {0} -p ./simple.psafe3 -S copy 'Test six'
    Password is now in your clipboard, press ENTER to copy username", exe);

    print!("{}", opts.usage(&brief));
}

fn op_list(kc: &mut keychain::V3, args: &[String]) {
    let re = args.join("");
    let re = Regex::new(&re).unwrap();

    println!("TODO {}", re);

    for i in kc.iter() {
        let mut title: String = String::new();

        match i.get(item::Kind::Group) {
            Some(g) => {
                match g {
                    &item::Data::Text(ref v) => {
                        title.push_str(v);
                        title.push('.');
                    },
                    _ => panic!("WTF TODO"),
                }
            },
            None => (),
        }

        match i.get(item::Kind::Title) {
            Some(t) => {
                match t {
                    &item::Data::Text(ref v) => title.push_str(v),
                    _ => panic!("WTF TODO"),
                }
            },
            None => (),
        }

        if re.is_match(&title) {
            println!("{}", title);
        }
    }
}

fn run_op(kc: &mut keychain::V3, op: &Vec<String>) -> bool {
    match op[0].as_ref() {
        "list" => op_list(kc, &op[1..]),
        "copy" => println!("TODO"),
        "query" => println!("TODO"),
        "show" => println!("TODO"),
        _ => return false,
    }

    // TODO: switch on op[0]
    /*
    for i in kc.iter() {
        println!("{:?}", i);
    }
    */

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
        password = rpassword::prompt_password_stdout("Password: ").unwrap();
    }

	let mut kc = keychain::V3::new(&db_path);
	kc.unlock(&password).unwrap();
    if !run_op(&mut kc, &matches.free) {
        print_usage(&exe, opts);
    }
}
