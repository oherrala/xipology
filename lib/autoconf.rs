use std::net::SocketAddr;
use std::str::FromStr;
use std::io;
use std::thread;
use std::time;

use base64;
use rand::{Rng, OsRng};

use trust_dns::udp::UdpClientConnection;
use trust_dns::tcp::TcpClientConnection;
use trust_dns::client::{Client, SyncClient};
use trust_dns::op::Message;
use trust_dns::rr::{DNSClass, Name, RecordType};
use trust_dns::rr::resource::Record;

use super::duration_to_micros;

/// Good known hostname
const KNOWN_DNS_HIT: &str = "www.google.com";
const KNOWN_DNS_MISS: &str = "xipoconf.example.com";

#[derive(Debug)]
pub struct AutoConfig {
    /// The server under test (SUT)
    server: SocketAddr,
    /// True if server supports DNS over UDP
    supports_udp: io::Result<bool>,
    /// True if server supports DNS over TCP
    supports_tcp: io::Result<bool>,
    /// True if DNS answer's TTL decreases between two queries
    ttl_countdown: io::Result<bool>,
    /// True if NXDOMAIN response returns domain SOA record
    nxdomain_soa: io::Result<bool>,
    /// True if NXDOMAIN response returns domain SOA record
    nxdomain_soa_cache: io::Result<bool>,
}

impl AutoConfig {
    pub fn interrogate(server: SocketAddr) -> io::Result<Self> {
        let supports_udp = test_supports_udp(server);
        let supports_tcp = test_supports_tcp(server);
        let ttl_countdown = test_ttl_countdown(server);
        let nxdomain_soa = test_nxdomain_soa(server);
        let nxdomain_soa_cache = test_nxdomain_soa_cache(server);

        Ok(Self {
            server,
            supports_udp,
            supports_tcp,
            ttl_countdown,
            nxdomain_soa,
            nxdomain_soa_cache,
        })
    }
}

/// Generic DNS query using UDP
fn query_udp(server: SocketAddr, name: &Name) -> io::Result<Message> {
    let conn = UdpClientConnection::new(server)?;
    let client = SyncClient::new(conn);
    client.query(name, DNSClass::IN, RecordType::A).map_err(
        From::from,
    )
}

/// Generic DNS query using TCP
fn query_tcp(server: SocketAddr, name: &Name) -> io::Result<Message> {
    let conn = TcpClientConnection::new(server)?;
    let client = SyncClient::new(conn);
    client.query(name, DNSClass::IN, RecordType::A).map_err(
        From::from,
    )
}

/// Generate random dns name to query from `KNOWN_DNS_MISS` domain.
fn random_name() -> Name {
    let mut rng = OsRng::new().expect("OsRng::new");
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    let label = base64::encode(&buf);
    let name = format!("{}.{}", label, KNOWN_DNS_MISS);
    Name::from_str(&name).expect("Name::from_str")
}


/// Test if server supports communication using UDP protocol
pub fn test_supports_udp(server: SocketAddr) -> io::Result<bool> {
    let name = Name::from_str(KNOWN_DNS_HIT)?;
    let result = query_udp(server, &name);
    debug!("{:?}", result);
    let support = match result {
        Ok(_) => true,
        Err(_) => false,
    };
    info!("UDP Support: {}", support);
    Ok(support)
}

/// Test if server supports communication using TCP protocol
pub fn test_supports_tcp(server: SocketAddr) -> io::Result<bool> {
    let name = Name::from_str(KNOWN_DNS_HIT)?;
    let result = query_tcp(server, &name);
    debug!("{:?}", result);
    let support = match result {
        Ok(_) => true,
        Err(_) => false,
    };
    info!("TCP Support: {}", support);
    Ok(support)
}

/// Test if DNS answer TTL decreseases between two queries
pub fn test_ttl_countdown(server: SocketAddr) -> io::Result<bool> {
    fn query_ttl(server: SocketAddr) -> io::Result<u32> {
        let name = Name::from_str(KNOWN_DNS_HIT)?;
        let mut result = query_udp(server, &name)?;
        debug!("{:?}", result);
        let mut answers = result.take_answers();
        answers.sort();
        match answers.len() {
            0 => panic!("No answer"),
            _ => Ok(answers[0].ttl()),
        }
    }

    let ttl1 = query_ttl(server)?;
    debug!("First TTL: {:?}", ttl1);

    // Sleeping 1.001 seconds and network latency should be enough for TTL to
    // decrease by one second.
    thread::sleep(time::Duration::from_millis(1001));
    let ttl2 = query_ttl(server)?;
    debug!("Second TTL: {:?}", ttl2);

    Ok(ttl2 < ttl1)
}

pub fn test_nxdomain_soa(server: SocketAddr) -> io::Result<bool> {
    let name = random_name();
    let mut result = query_udp(server, &name)?;
    assert!(result.answers().is_empty());

    let ns = result.take_name_servers();
    let soa: Vec<&Record> = ns.iter()
        .filter(|r| r.rr_type() == RecordType::SOA)
        .collect();

    Ok(!soa.is_empty())
}

pub fn test_nxdomain_soa_cache(server: SocketAddr) -> io::Result<bool> {
    fn query_soa(server: SocketAddr, name: &Name) -> io::Result<Vec<Record>> {
        let mut result = query_udp(server, name)?;
        assert!(result.answers().is_empty());
        let ns = result.take_name_servers();
        Ok(
            ns.iter()
                .filter(|r| r.rr_type() == RecordType::SOA)
                .cloned()
                .collect(),
        )
    }

    let name = random_name();
    let soa1 = query_soa(server, &name)?;
    let soa2 = query_soa(server, &name)?;

    Ok(!soa1.is_empty() && !soa2.is_empty())
}


#[derive(Clone, Copy, Debug)]
pub struct QueryTimes {
    pub miss: f64,
    pub hit: f64,
}

pub fn test_query_time_differences(server: SocketAddr) -> io::Result<QueryTimes> {
    let mut misses = Vec::new();
    let mut hits = Vec::new();
    let tests = 20;
    for _ in 0..tests {
        let (miss, hit) = measure_query(server)?;
        misses.push(miss);
        hits.push(hit);
    }

    let miss_avg = misses.iter().sum::<f64>() / f64::from(tests);
    let hit_avg = hits.iter().sum::<f64>() / f64::from(tests);

    Ok(QueryTimes {
        miss: miss_avg,
        hit: hit_avg,
    })
}

fn measure_query(server: SocketAddr) -> io::Result<(f64, f64)> {
    let name = random_name();
    let t1 = time::Instant::now();
    let _ = query_udp(server, &name);
    let t2 = time::Instant::now();
    let _ = query_udp(server, &name);
    let time_hit = duration_to_micros(t2.elapsed());
    let time_miss = duration_to_micros(t2.duration_since(t1));

    Ok((time_miss, time_hit))
}
