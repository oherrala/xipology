use std::io;
use std::net::SocketAddr;
use std::ops::Not;
use std::str::FromStr;
use std::time;

use base64;

use ring::hkdf;
use ring::hmac::SigningKey;
use ring::digest;

use trust_dns::client::{Client, SyncClient};
use trust_dns::rr::{DNSClass, RecordType, Name};
use trust_dns::udp::UdpClientConnection;

use super::{duration_to_micros, get_bit, set_bit};

pub struct Xipology<'a> {
    derivator: NameDerivator<'a>,
    secret: &'a [u8],
    client: SyncClient,
}

impl<'a> Xipology<'a> {
    pub fn from_secret(server: SocketAddr, secret: &'a [u8]) -> io::Result<Self> {
        let derivator = NameDerivator::from_secret(secret);
        let conn = UdpClientConnection::new(server)?;
        let client = SyncClient::new(conn);

        Ok(Self {
            derivator,
            secret,
            client,
        })
    }

    pub fn reset(self: &mut Self) {
        self.derivator = NameDerivator::from_secret(self.secret);
    }

    pub fn write_byte(self: &mut Self, byte: u8) -> io::Result<()> {
        info!("write_byte({:?})", byte);
        let mut parity = false;

        // Reservation
        let name = self.derivator.next_name();
        debug!("write_byte reserving name {}", name);
        let _ = self.poke_name(&name)?;

        // Guard (do not touch it on write)
        let _ = self.derivator.next_name();

        // Payload
        for bit in 0..8 {
            let name = self.derivator.next_name();
            if get_bit(byte, bit) > 0 {
                let _ = self.poke_name(&name)?;
                parity = parity.not();
            }
        }

        // Parity (even)
        let name = self.derivator.next_name();
        if parity {
            let _ = self.poke_name(&name)?;
        }

        Ok(())
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

    pub fn write_bytes(self: &mut Self, buf: &[u8]) -> io::Result<()> {
        let len = buf.len();
        assert!(len > 0 && len < 255);

        // Length
        self.write_byte(len as u8)?;

        // Payload
        for byte in buf {
            self.write_byte(*byte)?;
        }

        Ok(())
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
        let t1 = time::Instant::now();
        let _ = self.client.query(&name, class, rtype)?;
        let delay = t1.elapsed();
        Ok(duration_to_micros(delay))
    }
}


struct NameDerivator<'a> {
    salt: SigningKey,
    secret: &'a [u8],
}

impl<'a> NameDerivator<'a> {
    pub fn from_secret(secret: &'a [u8]) -> Self {
        let salt = SigningKey::new(&digest::SHA512, b"");

        Self { salt, secret }
    }

    fn hkdf_extract_and_expand(self: &mut Self, out: &mut [u8]) {
        let prk = hkdf::extract(&self.salt, self.secret);
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
