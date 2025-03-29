use percent_encoding::{percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_bencode;
use url::Url;

use crate::http::http_get;
use crate::torrent::Torrent;

pub use peers::Peers;

// TODO: UDP protocol: https://www.bittorrent.org/beps/bep_0015.html

pub struct TrackerRequest {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub port: u16,
    pub uploaded: usize,
    pub downloaded: usize,
    pub left: usize,
    pub compact: u8,
    // TODO: no_peer_id, event, ip, numwant, key, trackerid
}
#[derive(Debug, Clone, Deserialize)]
pub struct TrackerResponse {
    #[serde(default)]
    pub failure_reason: String,
    pub interval: usize,
    #[serde(default)]
    pub tracker_id: String,
    #[serde(default)]
    pub complete: u32,
    #[serde(default)]
    pub incomplete: u32,
    pub peers: Peers,
}

pub mod peers {
    use serde::de::{self, Deserialize, Deserializer, Visitor};
    use serde::ser::{Serialize, Serializer};
    use std::fmt;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::ops::Deref;

    #[derive(Debug, Clone, PartialEq)]
    pub enum SocketType {
        IPv4(SocketAddrV4),
        IPv6(SocketAddrV6),
    }

    impl SocketType {
        pub fn as_socket_addr(&self) -> SocketAddr {
            match self {
                SocketType::IPv4(a) => SocketAddr::V4(*a),
                SocketType::IPv6(a) => SocketAddr::V6(*a),
            }
        }
    }

    impl IntoIterator for Peers {
        type Item = SocketType;
        type IntoIter = std::vec::IntoIter<SocketType>;

        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl Deref for Peers {
        type Target = Vec<SocketType>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Peers(pub Vec<SocketType>);

    impl<'de> Deserialize<'de> for Peers {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct PeersVisitor;

            impl<'de> Visitor<'de> for PeersVisitor {
                type Value = Peers;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a list of peers, each represented by either 6 bytes (IPv4) or 18 bytes (IPv6)")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    let mut peers = Vec::new();
                    let mut i = 0;

                    while i < v.len() {
                        if v.len() - i >= 18 {
                            // try IPv6 first
                            let ip = Ipv6Addr::new(
                                u16::from_be_bytes([v[i], v[i + 1]]),
                                u16::from_be_bytes([v[i + 2], v[i + 3]]),
                                u16::from_be_bytes([v[i + 4], v[i + 5]]),
                                u16::from_be_bytes([v[i + 6], v[i + 7]]),
                                u16::from_be_bytes([v[i + 8], v[i + 9]]),
                                u16::from_be_bytes([v[i + 10], v[i + 11]]),
                                u16::from_be_bytes([v[i + 12], v[i + 13]]),
                                u16::from_be_bytes([v[i + 14], v[i + 15]]),
                            );
                            let port = u16::from_be_bytes([v[i + 16], v[i + 17]]);
                            peers.push(SocketType::IPv6(SocketAddrV6::new(ip, port, 0, 0)));
                            i += 18;
                        } else if v.len() - i >= 6 {
                            let ip = Ipv4Addr::new(v[i], v[i + 1], v[i + 2], v[i + 3]);
                            let port = u16::from_be_bytes([v[i + 4], v[i + 5]]);
                            peers.push(SocketType::IPv4(SocketAddrV4::new(ip, port)));
                            i += 6;
                        } else {
                            return Err(E::custom("invalid peer length"));
                        }
                    }

                    Ok(Peers(peers))
                }
            }

            deserializer.deserialize_bytes(PeersVisitor)
        }
    }

    impl Serialize for Peers {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut single_slice = Vec::new();

            for peer in &self.0 {
                match peer {
                    SocketType::IPv4(addr) => {
                        single_slice.extend_from_slice(&addr.ip().octets());
                        single_slice.extend_from_slice(&addr.port().to_be_bytes());
                    }
                    SocketType::IPv6(addr) => {
                        for segment in addr.ip().segments() {
                            single_slice.extend_from_slice(&segment.to_be_bytes());
                        }
                        single_slice.extend_from_slice(&addr.port().to_be_bytes());
                    }
                }
            }

            serializer.serialize_bytes(&single_slice)
        }
    }
}

impl TrackerRequest {
    pub fn announce(req: &TrackerRequest, torrent: &Torrent) -> anyhow::Result<TrackerResponse> {
        let url = req.to_url(&torrent.announce)?;
        let response = http_get(url.as_str())?;
        if response.status_code != 200 {
            anyhow::bail!("HTTP error {}", response.status_code);
        }

        let decoded: TrackerResponse = serde_bencode::from_bytes(&response.body)?;
        log::debug!("tracker response: {:?}", decoded);
        if !decoded.failure_reason.is_empty() {
            anyhow::bail!("tracker error: {}", decoded.failure_reason);
        }
        if decoded.interval == 0 {
            anyhow::bail!("tracker error: interval is 0");
        }
        if decoded.peers.0.is_empty() {
            anyhow::bail!("tracker error: no peers");
        }
        Ok(decoded)
    }

    pub fn to_url(&self, base_url: &str) -> anyhow::Result<Url> {
        let encoded_info_hash = percent_encode(&self.info_hash, NON_ALPHANUMERIC).to_string();
        let encoded_peer_id = percent_encode(&self.peer_id, NON_ALPHANUMERIC).to_string();
        let query = format!(
            "info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact={}",
            encoded_info_hash,
            encoded_peer_id,
            self.port,
            self.uploaded,
            self.downloaded,
            self.left,
            self.compact
        );
        log::debug!("tracker query: {}", query);
        let full_url = format!("{}?{}", base_url.trim_end_matches('/'), query);
        let parsed = Url::parse(&full_url)?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SAMPLE_PATH;
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_peers_deserialize() {
        let mut raw = Vec::new();
        let segments = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).segments();
        for segment in &segments {
            raw.extend_from_slice(&segment.to_be_bytes());
        }
        raw.extend_from_slice(&6881u16.to_be_bytes());
        raw.extend_from_slice(&[127, 0, 0, 1]);
        raw.extend_from_slice(&6881u16.to_be_bytes());
        use serde_bencode::value::Value;
        let bencoded = serde_bencode::to_bytes(&Value::Bytes(raw.clone())).unwrap();
        let deserialized_peers: Peers = serde_bencode::from_bytes(&bencoded).unwrap();
        let expected = Peers(vec![
            peers::SocketType::IPv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 6881, 0, 0)),
            peers::SocketType::IPv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6881)),
        ]);
        assert_eq!(deserialized_peers, expected);
    }

    #[test]
    fn test_peers_serialize() {
        let peers = Peers(vec![
            peers::SocketType::IPv6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 6881, 0, 0)),
            peers::SocketType::IPv4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6881)),
        ]);
        let serialized = serde_bencode::to_bytes(&peers).unwrap();
        let deserialized: Peers = serde_bencode::from_bytes(&serialized).unwrap();
        assert_eq!(peers, deserialized);
    }

    #[test]
    fn test_parse_torrent_file() {
        let bytes = std::fs::read(SAMPLE_PATH).expect("failed to read .torrent file");
        let _: Torrent = serde_bencode::from_bytes(&bytes).expect("failed to parse");
    }

    #[test]
    fn test_announce_real_torrent() {
        let _ = env_logger::builder().is_test(true).try_init();
        let bytes = fs::read(SAMPLE_PATH).expect("failed to read .torrent file");
        let torrent: Torrent = serde_bencode::from_bytes(&bytes).expect("invalid torrent file");
        let req = TrackerRequest {
            info_hash: torrent.info_hash(),
            peer_id: *b"-RU0001-123456789012", // 20-byte ID
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            compact: 1,
        };
        let response = TrackerRequest::announce(&req, &torrent).expect("failed to announce");
        assert!(!response.peers.0.is_empty(), "no peers returned");
    }
}
