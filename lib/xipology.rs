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
const DECOY_BITS: usize = 11;

type Xipo = (XipoBits, Name);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XipoBits {
    Data(u8),
    Decoy,
    Guard,
    Parity,
    Reservation,
}

pub struct Xipology<'a> {
    derivator: NameDerivator,
    decoy: NameDerivator,
    secret: &'a [u8],
    server: SocketAddr,
}

impl<'a> Xipology<'a> {
    pub fn from_secret(server: SocketAddr, secret: &'a [u8]) -> io::Result<Self> {
        let mut derivator = NameDerivator::from_secret(secret);

        let decoy = {
            let mut decoy = [0u8; 32];
            derivator.hkdf_extract_and_expand(&mut decoy);
            NameDerivator::from_secret(&decoy)
        };

        Ok(Self {
            derivator,
            decoy,
            secret,
            server,
        })
    }

    pub fn reset(self: &mut Self) {
        self.derivator = NameDerivator::from_secret(self.secret);
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

        // Flip up some decoy bits.
        let decoy_flips = rng.gen_range(0, DECOY_BITS);
        for _ in 0..decoy_flips {
            output.push((XipoBits::Decoy, self.decoy.next_name()));
        }

        // Next we advance decoy name generator to consume total of DECOY_BITS
        // of names.
        let decoy_flops = DECOY_BITS - decoy_flips;
        for _ in 0..decoy_flops {
            self.decoy.next_name();
        }

        output
    }

    fn write_bits(self: &Self, bits: &[Xipo]) -> io::Result<usize> {
        let mut rng = OsRng::new()?;
        let mut output = Vec::from(bits);
        rng.shuffle(&mut output);

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
        let decoy_flips = rng.gen_range(0, DECOY_BITS);
        let decoy_flops = DECOY_BITS - decoy_flips;
        for _ in 0..decoy_flips {
            input.push((XipoBits::Decoy, self.decoy.next_name()));
        }
        for _ in 0..decoy_flops {
            self.decoy.next_name();
        }

        input
    }

    fn read_bits(self: &Self, xipo: &[Xipo]) -> io::Result<Option<u8>> {
        let mut rng = OsRng::new()?;
        let mut input = Vec::from(xipo);
        rng.shuffle(&mut input);

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
                if delay < 10_000_f64 {
                    *bit
                } else {
                    // 0 bits are read as "Decoy" and ignored
                    XipoBits::Decoy
                }
            })
            .collect();

        if !bits.contains(&XipoBits::Reservation) {
            return Ok(None);
        }

        if bits.contains(&XipoBits::Guard) {
            return Ok(None);
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
            return Ok(None);
        }

        Ok(Some(byte))
    }

    pub fn read_byte(self: &mut Self) -> io::Result<Option<u8>> {
        let input = self.byte_input();
        self.read_bits(&input)
    }

    pub fn read_bytes(self: &mut Self) -> io::Result<Vec<u8>> {
        let len = self.read_byte()?.unwrap_or(0);
        debug!("read_bytes len = {}", len);

        let inputs: Vec<_> = (0..len).map(|_| self.byte_input()).collect();
        let buf = inputs
            .par_iter()
            .map(|input| match self.read_bits(input) {
                Ok(Some(b)) => b,
                Ok(None) | Err(_) => {
                    debug!("Missing byte");
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

struct NameDerivator {
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

    fn next_name(self: &mut Self) -> Name {
        let mut buf = [0u8; 32];
        self.hkdf_extract_and_expand(&mut buf);
        let label1 = base64::encode(&buf[0..15]);
        let label2 = base64::encode(&buf[16..31]);
        let name = format!("{}.{}.xipology.example.com.", label1, label2);
        Name::from_str(&name).expect("Name::from_str")
    }
}
