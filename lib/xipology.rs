use std::f64;
use std::io;
use std::net::SocketAddr;
use std::ops::Not;
use std::str::FromStr;
use std::time;

use base64;

use rand::{Rng, OsRng};
use rayon::prelude::*;
use ring::digest;
use ring::hkdf;
use ring::hmac::SigningKey;

use trust_dns::client::{Client, SyncClient};
use trust_dns::rr::{DNSClass, RecordType, Name};
use trust_dns::udp::UdpClientConnection;

use super::{duration_to_micros, get_bit, set_bit};

/// How many decoy bits per one byte of output
const DECOY_BITS: usize = 0;

type Xipo = (XipoBits, Name);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XipoBits {
    Data(u8),
    Decoy,
    Guard,
    Parity,
    Reservation,
}

#[derive(Debug)]
pub enum ReadError {
    Free,
    Consumed,
    Parity,
    IO(io::Error),
}

pub struct Xipology {
    derivator: NameDerivator,
    decoy: NameDerivator,
    secret: Vec<u8>,
    server: SocketAddr,
    query_times: Option<super::autoconf::QueryTimes>,
}

impl Xipology {
    pub fn from_secret(server: SocketAddr, secret: Vec<u8>) -> Self {
        let mut derivator = NameDerivator::from_secret(&secret);
        let query_times = None;

        let decoy = {
            let mut decoy = [0u8; 32];
            derivator.hkdf_extract_and_expand(&mut decoy);
            NameDerivator::from_secret(&decoy)
        };

        Self {
            derivator,
            decoy,
            secret,
            server,
            query_times,
        }
    }

    pub fn change_secret(self: &mut Self, secret: Vec<u8>) {
        self.secret = secret;
        self.reset();
    }

    pub fn reset(self: &mut Self) {
        self.derivator = NameDerivator::from_secret(&self.secret);
        self.query_times = None;
        self.decoy = {
            let mut decoy = [0u8; 32];
            self.derivator.hkdf_extract_and_expand(&mut decoy);
            NameDerivator::from_secret(&decoy)
        };
    }

    fn byte_output(self: &mut Self, byte: u8) -> Vec<Xipo> {
        info!("write_byte({:?})", byte);

        let mut output = Vec::new();
        let mut parity = false;

        // Reservation
        output.push((XipoBits::Reservation, self.derivator.next_name()));

        // Guard (do not touch it on write)
        let _ = self.derivator.next_name();

        // Payload
        for bit in 0..8 {
            let name = self.derivator.next_name();
            if get_bit(byte, bit) > 0 {
                output.push((XipoBits::Data(bit), name));
                parity = parity.not();
            }
        }

        // Parity (even)
        let name = self.derivator.next_name();
        if parity {
            output.push((XipoBits::Parity, name));
        }

        let mut rng = OsRng::new().expect("OsRng::new");
        if DECOY_BITS > 0 {
            let decoy_flips = rng.gen_range(0, DECOY_BITS);
            let decoy_flops = DECOY_BITS - decoy_flips;
            // Flip up some decoy bits.
            (0..decoy_flips).into_iter().for_each(|_| {
                let _ = output.push((XipoBits::Decoy, self.decoy.next_name()));
            });
            // Next we advance decoy name generator to consume total of DECOY_BITS
            // of names.
            (0..decoy_flops).into_iter().for_each(|_| {
                let _ = self.decoy.next_name();
            });
        }

        output
    }

    fn write_bits(self: &Self, output: &[Xipo]) -> io::Result<usize> {
        output.par_iter().for_each(|&(ref bit, ref name)| {
            match self.poke_name(name) {
                Ok(_) => {
                    debug!("Wrote bit {:?} into name {}", bit, name);
                }
                Err(err) => {
                    debug!("Error writing bit {:?} into name {}: {}", bit, name, err);
                }
            }
        });

        Ok(output.len())
    }

    pub fn write_byte(self: &mut Self, byte: u8) -> io::Result<usize> {
        let output = self.byte_output(byte);
        self.write_bits(&output)
    }

    pub fn write_bytes(self: &mut Self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        assert!(len > 0 && len < 255);
        let mut output = Vec::new();

        // Length
        let mut len_byte = self.byte_output(len as u8);
        output.append(&mut len_byte);

        // Payload
        for byte in buf {
            let mut b = self.byte_output(*byte);
            output.append(&mut b);
        }

        self.write_bits(&output)
    }


    fn byte_input(self: &mut Self) -> Vec<Xipo> {
        let mut input = Vec::new();

        input.push((XipoBits::Reservation, self.derivator.next_name()));
        input.push((XipoBits::Guard, self.derivator.next_name()));

        for bit in 0..8 {
            input.push((XipoBits::Data(bit), self.derivator.next_name()));
        }

        input.push((XipoBits::Parity, self.derivator.next_name()));

        let mut rng = OsRng::new().expect("OsRng::new");
        if DECOY_BITS > 0 {
            let decoy_flips = rng.gen_range(0, DECOY_BITS);
            let decoy_flops = DECOY_BITS - decoy_flips;
            (0..decoy_flips).into_iter().for_each(|_| {
                let _ = input.push((XipoBits::Decoy, self.decoy.next_name()));
            });
            (0..decoy_flops).into_iter().for_each(|_| {
                let _ = self.decoy.next_name();
            });
        }

        input
    }

    fn read_bits(self: &Self, input: &[Xipo]) -> Result<u8, ReadError> {
        let query_times = self.query_times.expect("query_times");
        let is_hit = |delay: f64| {
            let md = f64::abs(query_times.miss - delay);
            let hd = f64::abs(query_times.hit - delay);
            hd < md
        };

        let bits: Vec<XipoBits> = input
            .par_iter()
            .map(|&(ref bit, ref name)| {
                let delay = match self.poke_name(name) {
                    Ok(d) => d,
                    Err(err) => {
                        debug!("Error read bit {:?} from name {}: {}", bit, name, err);
                        f64::NAN
                    }
                };
                if is_hit(delay) {
                    *bit
                } else {
                    // 0 bits are read as "Decoy" and ignored
                    XipoBits::Decoy
                }
            })
            .collect();

        if !bits.contains(&XipoBits::Reservation) {
            return Err(ReadError::Free);
        }

        if bits.contains(&XipoBits::Guard) {
            return Err(ReadError::Consumed);
        }

        let mut parity = false;
        let mut byte = 0u8;
        for b in &bits {
            if let XipoBits::Data(n) = *b {
                set_bit(&mut byte, n);
                parity = parity.not();
            }
        }

        if (parity && !bits.contains(&XipoBits::Parity)) ||
            (!parity && bits.contains(&XipoBits::Parity))
        {
            return Err(ReadError::Parity);
        }

        info!("Read byte {}", byte);
        Ok(byte)
    }

    pub fn read_byte(self: &mut Self) -> Result<u8, ReadError> {
        if self.query_times.is_none() {
            debug!("Measuring query times");
            let query_times = super::autoconf::test_query_time_differences(self.server)
                .map_err(ReadError::IO)?;
            info!("{:?}", query_times);
            self.query_times = Some(query_times);
        }

        let input = self.byte_input();
        self.read_bits(&input)
    }

    pub fn read_bytes(self: &mut Self) -> Result<Vec<u8>, ReadError> {
        if self.query_times.is_none() {
            debug!("Measuring query times");
            let query_times = super::autoconf::test_query_time_differences(self.server)
                .map_err(ReadError::IO)?;
            info!("{:?}", query_times);
            self.query_times = Some(query_times);
        }

        let len = self.read_byte()?;
        debug!("read_bytes len = {}", len);

        let inputs: Vec<_> = (0..len).map(|_| self.byte_input()).collect();

        let buf = inputs
            .par_iter()
            .map(|input| match self.read_bits(input) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("ERROR: read_bytes: {:?}", e);
                    b' '
                }
            })
            .collect();

        Ok(buf)
    }

    fn poke_name(self: &Self, name: &Name) -> io::Result<f64> {
        let class = DNSClass::IN;
        let rtype = RecordType::SRV;
        let conn = UdpClientConnection::new(self.server)?;
        let client = SyncClient::new(conn);

        let t1 = time::Instant::now();
        let _ = client.query(name, class, rtype)?;
        let delay = t1.elapsed();

        Ok(duration_to_micros(delay))
    }
}

pub struct NameDerivator {
    salt: SigningKey,
    secret: Vec<u8>,
}

impl NameDerivator {
    pub fn from_secret(secret: &[u8]) -> Self {
        let salt = SigningKey::new(&digest::SHA512, b"");
        Self {
            salt,
            secret: secret.to_vec(),
        }
    }

    fn hkdf_extract_and_expand(self: &mut Self, out: &mut [u8]) {
        let prk = hkdf::extract(&self.salt, &self.secret);
        hkdf::expand(&prk, b"", out);
        self.salt = prk;
    }

    pub fn next_name(self: &mut Self) -> Name {
        let mut buf = [0u8; 32];
        self.hkdf_extract_and_expand(&mut buf);
        let label1 = base64::encode(&buf[0..15]);
        let label2 = base64::encode(&buf[16..31]);
        let name = format!("{}.{}.xipology.example.com.", label1, label2);
        Name::from_str(&name).expect("Name::from_str")
    }
}
