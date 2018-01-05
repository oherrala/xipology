extern crate log;
extern crate env_logger;

extern crate base64;
extern crate chrono;
extern crate rand;
extern crate ring;
extern crate trust_dns;

extern crate xipolib;

use std::collections::HashSet;
use std::ops::Div;
use std::str;
use std::thread;

use chrono::prelude::*;
use rand::{Rng, OsRng};

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

    let mut rng = OsRng::new().expect("OsRng::new");
    let mut encounters: HashSet<String> = HashSet::new();

    loop {
        let next = secret.secret();
        println!(
            "Reading rendezvous point {}",
            std::str::from_utf8(&next).expect("from_utf8")
        );
        xipo.change_secret(next);

        match xipo.read_bytes() {
            Ok(found_nicks) => {
                if let Ok(as_str) = std::str::from_utf8(&found_nicks) {
                    eprintln!("Read something: {}", as_str);
                    encounters.extend(decode_nicks(as_str.as_bytes()));
                }
                continue;
            }
            Err(ReadError::Free) => {
                println!("Rendezvous point was free. Will take the next one");

                // Write back all our encountered nicks and our own
                encounters.insert(nick.clone());
                xipo.change_secret(secret.secret());
                let nicks = encode_nicks(&encounters);
                let _ = xipo.write_bytes(&nicks);
                eprintln!("Scribbled on ether: {:?}", encounters);
                let sleep = rng.gen_range(55, 65);
                println!("Sleeping for {} seconds", sleep);
                thread::sleep(std::time::Duration::from_secs(sleep));
            }
            Err(ReadError::Consumed) => {
                println!("Rendezvous point was already consumed. Moving to next one.");
                continue;
            }
            Err(err) => {
                eprintln!("ERROR: Read error: {:?}", err);
            }
        }

        encounters.clear();
    }
}

struct SecretGen<'a> {
    secret: &'a str,
    used_time: String,
    counter: usize,
}

impl<'a> SecretGen<'a> {
    pub fn from(secret: &'a str) -> Self {
        let time = Self::get_time();
        Self {
            secret: secret,
            used_time: time,
            counter: 0,
        }
    }

    pub fn secret(self: &mut Self) -> Vec<u8> {
        let time = Self::get_time();
        if time != self.used_time {
            self.counter = 0;
            self.used_time = time.clone();
        }
        let secret = format!("{}-{}-{}", self.secret, time, self.counter);
        self.counter += 1;
        secret.into_bytes()
    }

    pub fn get_time() -> String {
        // Seconds since UNIX epoch divided by n minutes
        let epoch = Utc::now().timestamp();
        let n = 5;
        let time = epoch.div(n * 60);
        format!("{}", time)
    }
}


fn encode_nicks(nicks: &HashSet<String>) -> Vec<u8> {
    let nicks: String = nicks.iter().cloned().collect::<Vec<_>>().join(", ");
    nicks.into_bytes()
}

/// ```rust
/// let nicks = "foo, bar, baz";
/// let decoded = decode_nicks(&nicks).expect("decode_nicks");
/// let encoded = encode_nicks(decoded);
/// assert_eq!(nicks, encoded);
/// ```
fn decode_nicks(buf: &[u8]) -> HashSet<String> {
    let as_str = str::from_utf8(buf).expect("from_utf8");
    as_str.split(',').map(str::trim).map(From::from).collect()
}
