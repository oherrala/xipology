extern crate log;
extern crate env_logger;

extern crate base64;
extern crate chrono;
extern crate rand;
extern crate ring;
extern crate trust_dns;

extern crate xipolib;

use std::thread;
use chrono::prelude::*;

use xipolib::ReadError;

fn print_help(program: &str) {
    eprintln!("{} <dns server ip> <nick>", program);
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

    let nick = match args.next() {
        Some(a) => a,
        None => {
            print_help(&program);
            std::process::exit(1)
        }
    };

    let base_secret = "rendezvous";
    let mut xipo = xipolib::Xipology::from_secret(server, From::from(base_secret));
    let mut secret = SecretGen::from(base_secret);

    loop {
        let next = secret.secret();
        println!(
            "Using secret {}",
            std::str::from_utf8(&next).expect("from_utf8")
        );
        xipo.change_secret(next);

        match xipo.read_bytes() {
            Ok(found_nick) => {
                let as_str = std::str::from_utf8(&found_nick).expect("from_utf8");
                println!("Found nick: {}", as_str);
                continue;
            }
            Err(ReadError::Free) => {
                println!("Rendezvous point was free. Will take the next one");
                let next = secret.secret();
                xipo.change_secret(next);
                let _ = xipo.write_bytes(nick.as_bytes());
                println!("Sleeping for 30 seconds");
                thread::sleep(std::time::Duration::from_secs(30));
            }
            Err(ReadError::Consumed) => {
                println!("Rendezvous point was already consumed");
                continue;
            }
            Err(err) => {
                eprintln!("ERROR: Read error: {:?}", err);
            }
        }
    }
}

struct SecretGen<'a> {
    secret: &'a str,
    counter: usize,
}

impl<'a> SecretGen<'a> {
    pub fn from(secret: &'a str) -> Self {
        Self {
            secret: secret,
            counter: 0,
        }
    }

    pub fn secret(self: &mut Self) -> Vec<u8> {
        let utc: DateTime<Utc> = Utc::now();
        let time = utc.format("%FT%R"); // YYYY-mm-DDTHH-MM
        let secret = format!("{}-{}-{}", self.secret, time, self.counter);
        self.counter += 1;
        secret.into_bytes()
    }
}
