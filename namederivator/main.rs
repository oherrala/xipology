extern crate xipolib;
use std::thread;
use std::time::Duration;

fn main() {
    let mut args = std::env::args();
    let _program = args.next().expect("program name");

    let secret = match args.next() {
        Some(a) => a,
        None => {
            std::process::exit(1)
        }
    };

    let mut nd = xipolib::NameDerivator::from_secret(secret.as_bytes());
    println!("Secret: {}", secret);
    (0..10).for_each(|n| {
        println!("{}: {}", n, nd.next_name());
        thread::sleep(Duration::from_millis(200));
    });
}
