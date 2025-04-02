use sha1::{Digest, Sha1};
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::time::Duration;

use crate::bitfield::BitField;
use crate::download::Piece;

const BT_PROTOCOL: &str = "BitTorrent protocol";
const BT_PROTOCOL_LEN: u8 = 19;
const HANDSHAKE_LEN: usize = 68;
const RESERVED_LEN: usize = 8;
const BLOCK_SIZE: u32 = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(3);
const BACKOFF: Duration = Duration::from_millis(100);
#[derive(Debug)]
pub struct Peer {
    pub addr: SocketAddr,
    pub stream: TcpStream,
    pub bitfield: Option<BitField>,
    pub choked: bool,
    pub interested: bool,
}

impl Peer {
    pub fn new(addr: SocketAddr, info_hash: &[u8; 20], peer_id: &[u8; 20]) -> anyhow::Result<Self> {
        log::debug!("connecting to peer: {:?}", addr);

        let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;

        let mut handshake = Vec::with_capacity(HANDSHAKE_LEN);
        handshake.push(BT_PROTOCOL_LEN);
        handshake.extend_from_slice(BT_PROTOCOL.as_bytes());
        handshake.extend_from_slice(&[0; RESERVED_LEN]);
        handshake.extend_from_slice(info_hash);
        handshake.extend_from_slice(peer_id);

        stream.write_all(&handshake)?;

        let mut response = [0u8; HANDSHAKE_LEN];
        stream.read_exact(&mut response)?;

        let recv_pstrlen = response[0] as usize;
        let recv_info_hash = &response[28..48];

        anyhow::ensure!(
            recv_pstrlen == BT_PROTOCOL_LEN as usize,
            "invalid pstrlen: {}",
            recv_pstrlen
        );
        anyhow::ensure!(
            recv_info_hash == info_hash,
            "invalid info_hash: {:?}",
            recv_info_hash
        );

        log::debug!("handshake successful");

        let bitfield = Self::read_bitfield(&mut stream)?;
        // log::debug!("bitfield: {:?}", bitfield);

        Ok(Peer {
            addr,
            stream,
            bitfield: Some(bitfield),
            choked: true,
            interested: false,
        })
    }

    pub fn send_message(&mut self, message: &PeerMessage) -> anyhow::Result<()> {
        let buf = message.serialize();
        self.stream.write_all(&buf)?;
        Ok(())
    }

    pub fn read_message(&mut self) -> anyhow::Result<PeerMessage> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let length = u32::from_be_bytes(len_buf);

        log::debug!("message length: {}", length);

        if length == 0 {
            return Ok(PeerMessage::KeepAlive);
        }

        let mut id_buf = [0u8; 1];
        self.stream.read_exact(&mut id_buf)?;
        let message_id = id_buf[0];

        log::debug!("message id: {}", message_id);

        match message_id {
            0 => Ok(PeerMessage::Choke),
            1 => Ok(PeerMessage::Unchoke),
            2 => Ok(PeerMessage::Interested),
            3 => Ok(PeerMessage::NotInterested),
            4 => {
                let mut index_buf = [0u8; 4];
                self.stream.read_exact(&mut index_buf)?;
                let index = u32::from_be_bytes(index_buf);
                Ok(PeerMessage::Have(index))
            }
            5 => {
                let mut payload = vec![0u8; (length - 1) as usize];
                self.stream.read_exact(&mut payload)?;
                Ok(PeerMessage::Bitfield(payload))
            }
            6 => {
                let mut index_buf = [0u8; 4];
                self.stream.read_exact(&mut index_buf)?;
                let index = u32::from_be_bytes(index_buf);

                let mut begin_buf = [0u8; 4];
                self.stream.read_exact(&mut begin_buf)?;
                let begin = u32::from_be_bytes(begin_buf);

                let mut length_buf = [0u8; 4];
                self.stream.read_exact(&mut length_buf)?;
                let length = u32::from_be_bytes(length_buf);

                Ok(PeerMessage::Request {
                    index,
                    begin,
                    length,
                })
            }
            7 => {
                let mut index_buf = [0u8; 4];
                self.stream.read_exact(&mut index_buf)?;
                let index = u32::from_be_bytes(index_buf);

                let mut begin_buf = [0u8; 4];
                self.stream.read_exact(&mut begin_buf)?;
                let begin = u32::from_be_bytes(begin_buf);

                let block_len = length - 9; // 1 byte for message id, 4 bytes for index, 4 bytes for begin

                if block_len > BLOCK_SIZE {
                    anyhow::bail!("block length exceeds maximum size");
                }

                let mut block = vec![0u8; block_len as usize];
                self.stream.read_exact(&mut block)?;

                Ok(PeerMessage::Piece {
                    index,
                    begin,
                    block,
                })
            }
            8 => {
                let mut index_buf = [0u8; 4];
                self.stream.read_exact(&mut index_buf)?;
                let index = u32::from_be_bytes(index_buf);

                let mut begin_buf = [0u8; 4];
                self.stream.read_exact(&mut begin_buf)?;
                let begin = u32::from_be_bytes(begin_buf);

                let mut length_buf = [0u8; 4];
                self.stream.read_exact(&mut length_buf)?;
                let length = u32::from_be_bytes(length_buf);

                Ok(PeerMessage::Cancel {
                    index,
                    begin,
                    length,
                })
            }
            _ => anyhow::bail!("unhandled message id: {}", message_id),
        }
    }

    pub fn request_piece(
        &mut self,
        piece_index: u32,
        block_offset: u32,
        block_length: u32,
    ) -> anyhow::Result<()> {
        let req = PeerMessage::Request {
            index: piece_index,
            begin: block_offset,
            length: block_length,
        };
        self.send_message(&req)
    }

    pub fn run(
        mut self,
        piece_length: u32,
        total_length: u64,
        piece_hash_fn: Arc<dyn Fn(u32) -> [u8; 20] + Send + Sync>,
        pending_pieces: Arc<Mutex<VecDeque<u32>>>,
        result_sender: Sender<(u32, Vec<u8>)>,
    ) {
        let _ = self.send_message(&PeerMessage::Interested);
        self.interested = true;

        let mut pieces = HashMap::<u32, Piece>::new();
        let total_pieces = ((total_length + piece_length as u64 - 1) / piece_length as u64) as u32;
        let mut rejected: HashSet<u32> = HashSet::new();

        loop {
            if self.choked {
                match self.read_message() {
                    Ok(PeerMessage::Unchoke) => self.choked = false,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }

            // get the next piece to download
            let maybe_index = {
                let mut queue = pending_pieces.lock().unwrap();
                queue.pop_front()
            };

            let index = match maybe_index {
                Some(i) => i,
                None => break, // no more pieces to download
            };

            log::info!("Requesting piece {} from {}", index, self.addr);

            // check if we already have the piece
            if pieces.contains_key(&index) {
                log::debug!("Already have piece {}, skipping", index);
                continue;
            }

            if rejected.contains(&index) {
                // requeue for another peer, but we won't try it again
                let mut q = pending_pieces.lock().unwrap();
                q.push_back(index);
                continue;
            }

            // check if we have all pieces
            if index >= total_pieces {
                log::debug!("All pieces downloaded, exiting");
                break;
            }

            // skip if peer doesn't have the piece, and requeue it
            if let Some(bitfield) = &self.bitfield {
                if !bitfield.has_piece(index as usize) {
                    log::debug!(
                        "Peer {} does not have piece {}, requeuing",
                        self.addr,
                        index
                    );
                    rejected.insert(index);
                    std::thread::sleep(BACKOFF); // backoff
                    let mut queue = pending_pieces.lock().unwrap();
                    queue.push_back(index);
                    continue;
                }
            }

            // request all blocks for the piece
            let piece_len = if (index + 1) as u64 * piece_length as u64 > total_length {
                (total_length - index as u64 * piece_length as u64) as u32
            } else {
                piece_length
            };

            let mut offset = 0;
            while offset < piece_len {
                let block_size = BLOCK_SIZE.min(piece_len - offset);
                if self.request_piece(index, offset, block_size).is_err() {
                    break;
                }
                offset += block_size;
            }

            // collect blocks
            while let Ok(msg) = self.read_message() {
                match msg {
                    PeerMessage::Piece {
                        index: idx,
                        begin,
                        block,
                    } if idx == index => {
                        let entry = pieces
                            .entry(index)
                            .or_insert_with(|| Piece::new(index, piece_len, BLOCK_SIZE));
                        entry.add_block(begin, block);

                        if entry.is_complete() {
                            if let Some(data) = entry.assemble() {
                                let expected = piece_hash_fn(index);
                                let actual = Sha1::digest(&data);
                                if actual[..] == expected[..] {
                                    let _ = result_sender.send((index, data));
                                }
                            }
                            break;
                        }
                    }
                    PeerMessage::Choke => {
                        self.choked = true;
                        break;
                    }
                    _ => continue,
                }
            }
        }
    }

    fn read_bitfield(stream: &mut TcpStream) -> anyhow::Result<BitField> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let length = u32::from_be_bytes(len_buf);

        log::debug!("bitfield length: {}", length);

        if length == 0 {
            anyhow::bail!("keep-alive received instead of bitfield");
        }

        let mut id_buf = [0u8; 1];
        stream.read_exact(&mut id_buf)?;
        let message_id = id_buf[0];

        log::debug!("message id: {}", message_id);

        anyhow::ensure!(
            message_id == 5,
            "expected bitfield, got message_id {}",
            message_id
        );

        let mut payload = vec![0u8; (length - 1) as usize];
        stream.read_exact(&mut payload)?;
        Ok(BitField::new(payload))
    }
}

#[derive(Debug)]
pub enum PeerMessage {
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(Vec<u8>),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    KeepAlive,
}

impl PeerMessage {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            PeerMessage::KeepAlive => {
                buf.extend_from_slice(&0u32.to_be_bytes());
            }
            PeerMessage::Choke => {
                buf.extend_from_slice(&1u32.to_be_bytes());
                buf.push(0);
            }
            PeerMessage::Unchoke => {
                buf.extend_from_slice(&1u32.to_be_bytes());
                buf.push(1);
            }
            PeerMessage::Interested => {
                buf.extend_from_slice(&1u32.to_be_bytes());
                buf.push(2);
            }
            PeerMessage::NotInterested => {
                buf.extend_from_slice(&1u32.to_be_bytes());
                buf.push(3);
            }
            PeerMessage::Have(index) => {
                buf.extend_from_slice(&5u32.to_be_bytes());
                buf.push(4);
                buf.extend_from_slice(&index.to_be_bytes());
            }
            PeerMessage::Bitfield(bitfield) => {
                let len = 1 + bitfield.len() as u32;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.push(5);
                buf.extend_from_slice(bitfield);
            }
            PeerMessage::Request {
                index,
                begin,
                length,
            } => {
                buf.extend_from_slice(&13u32.to_be_bytes());
                buf.push(6);
                buf.extend_from_slice(&index.to_be_bytes());
                buf.extend_from_slice(&begin.to_be_bytes());
                buf.extend_from_slice(&length.to_be_bytes());
            }
            PeerMessage::Piece {
                index,
                begin,
                block,
            } => {
                let len = 1 + 4 + 4 + block.len() as u32;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.push(7);
                buf.extend_from_slice(&index.to_be_bytes());
                buf.extend_from_slice(&begin.to_be_bytes());
                buf.extend_from_slice(block);
            }
            PeerMessage::Cancel {
                index,
                begin,
                length,
            } => {
                buf.extend_from_slice(&13u32.to_be_bytes());
                buf.push(8);
                buf.extend_from_slice(&index.to_be_bytes());
                buf.extend_from_slice(&begin.to_be_bytes());
                buf.extend_from_slice(&length.to_be_bytes());
            }
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use crate::peer::Peer;
    use crate::torrent::Torrent;
    use crate::tracker::{peers::SocketType, TrackerRequest};
    use crate::util::init_logging;
    use crate::SAMPLE_PATH;
    use sha1::Digest;
    use std::collections::VecDeque;
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_real_peer_ipv4_handshake() {
        init_logging();

        let bytes = std::fs::read(SAMPLE_PATH).expect("failed to read .torrent");
        let torrent: Torrent = serde_bencode::from_bytes(&bytes).expect("invalid .torrent");

        let req = TrackerRequest {
            info_hash: torrent.info_hash(),
            peer_id: *b"-RU0001-123456789012",
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: torrent.total_length(),
            compact: 1,
        };

        let resp = TrackerRequest::announce(&req, &torrent).expect("announce failed");

        match resp
            .peers
            .iter()
            .filter_map(|p| match p {
                SocketType::IPv4(addr) => Some(*addr),
                _ => None,
            })
            .find_map(|addr| {
                Peer::new(std::net::SocketAddr::V4(addr), &req.info_hash, &req.peer_id).ok()
            }) {
            Some(peer) => {
                log::info!("handshake successful with peer {}", peer.addr);
            }
            None => {
                log::error!("no usable IPv4 peer could be connected to");
            }
        }
        log::error!("no usable peer found");
    }

    #[test]
    fn test_real_peer_ipv6_handshake() {
        init_logging();

        let bytes = std::fs::read(SAMPLE_PATH).expect("failed to read .torrent");
        let torrent: Torrent = serde_bencode::from_bytes(&bytes).expect("invalid .torrent");

        let req = TrackerRequest {
            info_hash: torrent.info_hash(),
            peer_id: *b"-RU0001-123456789012",
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: torrent.total_length(),
            compact: 1,
        };

        let resp = TrackerRequest::announce(&req, &torrent).expect("announce failed");

        // try to connect to handshake with all ipv6 peers
        for peer in resp.peers.iter() {
            if let SocketType::IPv6(addr) = peer {
                match Peer::new(
                    std::net::SocketAddr::V6(*addr),
                    &req.info_hash,
                    &req.peer_id,
                ) {
                    Ok(_) => {
                        log::info!("handshake successful with {}", addr);
                        return;
                    }
                    Err(e) => {
                        log::error!("failed to connect to {}: {}", addr, e);
                    }
                }
            }
        }
        log::error!("no usable IPv6 peer could be connected to");
    }

    #[test]
    fn test_real_peer_ipv4_run_download() {
        init_logging();

        let bytes = std::fs::read(SAMPLE_PATH).expect("failed to read .torrent file");
        let torrent: Torrent = serde_bencode::from_bytes(&bytes).expect("invalid torrent");
        let torrent = Arc::new(torrent); // wrap in Arc

        let req = TrackerRequest {
            info_hash: torrent.info_hash(),
            peer_id: *b"-RU0001-123456789012",
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: torrent.total_length(),
            compact: 1,
        };

        let resp = TrackerRequest::announce(&req, &torrent).expect("announce failed");
        let peer_addr = resp
            .peers
            .iter()
            .filter_map(|p| match p {
                SocketType::IPv4(addr) => Some(addr),
                _ => None,
            })
            .next()
            .expect("no IPv4 peers found");

        let peer = match Peer::new(
            std::net::SocketAddr::V4(*peer_addr),
            &req.info_hash,
            &req.peer_id,
        ) {
            Ok(peer) => peer,
            Err(e) => {
                log::error!(
                    "skipping test: failed to connect to peer {}: {}",
                    peer_addr,
                    e
                );
                return;
            }
        };

        let mut queue = VecDeque::new();
        queue.push_back(0); // try downloading piece 0
        let piece_queue = Arc::new(Mutex::new(queue));
        let (tx, rx) = mpsc::channel();
        let torrent_clone = Arc::clone(&torrent);
        let piece_hash_fn = Arc::new(move |i| torrent_clone.piece_hash(i));
        let peer_piece_length = torrent.piece_length();
        let peer_total_length = torrent.total_length();

        let handle = thread::spawn({
            let piece_queue = Arc::clone(&piece_queue);
            let piece_hash_fn = Arc::clone(&piece_hash_fn);
            move || {
                peer.run(
                    peer_piece_length as u32,
                    peer_total_length as u64,
                    piece_hash_fn,
                    piece_queue,
                    tx,
                );
            }
        });

        let (index, data) = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("did not receive result");

        let expected_hash = torrent.piece_hash(index);
        let actual_hash = sha1::Sha1::digest(&data);
        assert_eq!(actual_hash[..], expected_hash[..], "piece hash mismatch");

        handle.join().unwrap();
    }

    #[test]
    fn test_real_peer_ipv4_run_skips_missing_piece() {
        init_logging();

        let bytes = std::fs::read(SAMPLE_PATH).expect("failed to read .torrent file");
        let torrent: Torrent = serde_bencode::from_bytes(&bytes).expect("invalid torrent");
        let torrent = Arc::new(torrent);

        let req = TrackerRequest {
            info_hash: torrent.info_hash(),
            peer_id: *b"-RU0001-123456789012",
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: torrent.total_length(),
            compact: 1,
        };

        let resp = TrackerRequest::announce(&req, &torrent).expect("announce failed");

        let peer_addr = resp
            .peers
            .iter()
            .filter_map(|p| match p {
                SocketType::IPv4(addr) => Some(addr),
                _ => None,
            })
            .next()
            .expect("no IPv4 peers found");

        let mut peer = match Peer::new(
            std::net::SocketAddr::V4(*peer_addr),
            &req.info_hash,
            &req.peer_id,
        ) {
            Ok(peer) => peer,
            Err(e) => {
                log::error!(
                    "skipping test: failed to connect to peer {}: {}",
                    peer_addr,
                    e
                );
                return;
            }
        };

        if let Some(ref mut bf) = peer.bitfield {
            bf.unset(0);
        }

        let mut queue = VecDeque::new();
        queue.push_back(0);
        let piece_queue = Arc::new(Mutex::new(queue));
        let (tx, rx) = mpsc::channel();

        let torrent_clone = Arc::clone(&torrent);
        let piece_hash_fn = Arc::new(move |i| torrent_clone.piece_hash(i));

        let handle = thread::spawn({
            let piece_queue = Arc::clone(&piece_queue);
            let piece_hash_fn = Arc::clone(&piece_hash_fn);
            move || {
                peer.run(
                    torrent.piece_length() as u32,
                    torrent.total_length() as u64,
                    piece_hash_fn,
                    piece_queue,
                    tx,
                );
            }
        });

        let result = rx.recv_timeout(Duration::from_secs(5));
        assert!(
            result.is_err(),
            "peer should not have been able to send piece"
        );

        let q = piece_queue.lock().unwrap();
        assert!(
            q.contains(&0),
            "piece 0 should have been requeued by the peer"
        );

        handle.join().unwrap();
    }
}
