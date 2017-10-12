extern crate log;
extern crate env_logger;

extern crate base64;
extern crate rand;
extern crate ring;
extern crate trust_dns;

extern crate xipolib;

use std::io::{self, Read};

// mod autoconf;

fn print_help(program: &str) {
    eprintln!("{} <dns server ip> <secret> <read | write <text>>", program);
}

enum Op {
    Read,
    Write,
}

fn main() {
    env_logger::init().expect("env_logger::init");

    let mut args = std::env::args();
    let program = args.next().expect("program name");
    let addr = match args.next() {
        Some(a) => format!("{}:53", a),
        None => {
            print_help(&program);
            std::process::exit(1)
        }
    };
    let server = addr.parse().expect("server parse");

    let secret = match args.next() {
        Some(a) => a.into_bytes(),
        None => {
            print_help(&program);
            std::process::exit(1)
        }
    };

    let op = match args.next() {
        Some(ref text) => {
            match text as &str {
                "read" => Op::Read,
                "write" => Op::Write,
                _ => {
                    print_help(&program);
                    std::process::exit(1)
                }
            }
        }
        None => {
            print_help(&program);
            std::process::exit(1)
        }
    };

    let mut xipo = xipolib::Xipology::from_secret(server, &secret).expect("Xipology::from_secret");

    match op {
        Op::Read => {
            eprint!("Reading...");
            let bytes = xipo.read_bytes().expect("xipo.read_bytes");
            eprintln!("Done!");
            let result = std::str::from_utf8(&bytes).expect("from_utf8");
            eprintln!("Received:");
            println!("{}", result);
        }
        Op::Write => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer).expect(
                "stdin.read_to_string",
            );
            eprint!("Writing...");
            let _ = xipo.write_bytes(buffer.as_bytes());
            eprintln!("Done!");
        }
    }
}
