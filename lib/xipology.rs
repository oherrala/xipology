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

#[derive(Debug)]
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

    fn byte_output(self: &mut Self, byte: u8) -> io::Result<Vec<(XipoBits, Name)>> {
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

        let mut rng = OsRng::new()?;

        // Add some decoy bits
        let decoy_bits = rng.gen_range(0, 7);
        for _ in 0..decoy_bits {
            output.push((XipoBits::Decoy, self.decoy.next_name()));
        }

        Ok(output)
    }

    fn write_bits(self: &mut Self, bits: Vec<(XipoBits, Name)>) -> io::Result<usize> {
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
        let output = self.byte_output(byte)?;
        self.write_bits(output)
    }

    pub fn write_bytes(self: &mut Self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        assert!(len > 0 && len < 255);
        let mut output: Vec<(XipoBits, Name)> = Vec::new();

        // Length
        let mut len_byte = self.byte_output(len as u8)?;
        output.append(&mut len_byte);

        // Payload
        for byte in buf {
            let mut b = self.byte_output(*byte)?;
            output.append(&mut b);
        }

        self.write_bits(output)
    }

    pub fn read_byte(self: &mut Self) -> io::Result<Option<u8>> {
        let mut parity = false;

        // Reservation
        let name = self.derivator.next_name();
        debug!("read_byte checking reservation name {}", name);
        let delay = self.poke_name(&name)?;
        debug!("read_byte reservation delay = {}", delay);
        if delay > 10_000_f64 {
            debug!("read_byte reservation delay exit");
            return Ok(None);
        }

        // Guard
        let name = self.derivator.next_name();
        let delay = self.poke_name(&name)?;
        debug!("read_byte guard delay = {}", delay);
        if delay < 10_000_f64 {
            debug!("read_byte guard delay exit");
            return Ok(None);
        }

        // Payload
        let mut byte = 0u8;
        for bit in 0..8 {
            let name = self.derivator.next_name();
            let delay = self.poke_name(&name)?;
            if delay < 10_000_f64 {
                debug!("read one bit({}) from {}", bit, name);
                set_bit(&mut byte, bit);
                parity = parity.not();
            }
        }
        // Parity (even)
        let name = self.derivator.next_name();
        let delay = self.poke_name(&name)?;
        debug!("read_byte parity delay = {}", delay);
        if (delay < 10_000_f64 && !parity) || (delay > 10_000_f64 && parity) {
            return Ok(None);
        }

        info!("read_byte() = {:?}", byte);
        Ok(Some(byte))
    }

    pub fn read_bytes(self: &mut Self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();

        let len = self.read_byte()?.unwrap_or(0);
        debug!("read_bytes len = {}", len);

        for _ in 0..len {
            if let Some(byte) = self.read_byte()? {
                buf.push(byte);
            } else {
                return Ok(None);
            }
        }

        Ok(Some(buf))
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
