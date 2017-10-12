#[macro_use]
extern crate log;
extern crate env_logger;

extern crate base64;
extern crate rand;
extern crate rayon;
extern crate ring;
extern crate trust_dns;

use std::time;

mod xipology;
pub use xipology::Xipology;
