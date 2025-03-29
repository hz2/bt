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

        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        let mut handshake = Vec::with_capacity(68);
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

                let block_len = length - 9;
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

            // Get the next piece to download
            let maybe_index = {
                let mut queue = pending_pieces.lock().unwrap();
                queue.pop_front()
            };

            let index = match maybe_index {
                Some(i) => i,
                None => break, // No more work
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
                    std::thread::sleep(Duration::from_millis(100)); // sleep briefly to avoid busy wait
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

    // pub fn exchange(
    //     &mut self,
    //     piece_length: u32,
    //     total_length: u64,
    //     piece_hash_fn: &dyn Fn(u32) -> [u8; 20],
    //     output_path: PathBuf,
    // ) -> anyhow::Result<()> {
    //     self.send_message(&PeerMessage::Interested)?;
    //     self.interested = true;

    //     let mut writer = PieceWriter::new(output_path, piece_length, total_length)?;
    //     let mut pieces: HashMap<u32, Piece> = HashMap::new();

    //     let total_pieces = ((total_length + piece_length as u64 - 1) / piece_length as u64) as u32;
    //     let mut current_piece = 0;
    //     let mut requested = false;
    //     log::debug!("total pieces: {}", total_pieces);
    //     loop {
    //         let msg = match self.read_message() {
    //             Ok(msg) => msg,
    //             Err(e) => {
    //                 log::error!("Failed to read message from peer {}: {}", self.addr, e);
    //                 return Err(e.into());
    //             }
    //         };

    //         log::debug!("Received message from {}: {:?}", self.addr, msg);

    //         match msg {
    //             PeerMessage::Unchoke => {
    //                 self.choked = false;
    //                 log::info!("Peer {} unchoked us", self.addr);
    //             }

    //             PeerMessage::Piece {
    //                 index,
    //                 begin,
    //                 block,
    //             } => {
    //                 log::info!(
    //                     "Received block: piece={}, offset={}, len={}, from={}",
    //                     index,
    //                     begin,
    //                     block.len(),
    //                     self.addr
    //                 );

    //                 let piece_len = if (index + 1) as u64 * piece_length as u64 > total_length {
    //                     (total_length - index as u64 * piece_length as u64) as u32
    //                 } else {
    //                     piece_length
    //                 };

    //                 let entry = pieces
    //                     .entry(index)
    //                     .or_insert_with(|| Piece::new(index, piece_len, BLOCK_SIZE));

    //                 entry.add_block(begin, block);

    //                 if entry.is_complete() {
    //                     log::debug!("assembling and verifying piece {}", index);
    //                     if let Some(data) = entry.assemble() {
    //                         let expected = piece_hash_fn(index);
    //                         let actual = Sha1::digest(&data);

    //                         if actual[..] == expected[..] {
    //                             log::info!("piece {} verified successfully", index);
    //                             writer.write_piece(index, &data)?;
    //                             pieces.remove(&index);
    //                             requested = false;
    //                             current_piece += 1;
    //                             if current_piece >= total_pieces {
    //                                 log::info!("all pieces downloaded from {}", self.addr);
    //                                 break;
    //                             }
    //                         } else {
    //                             log::warn!(
    //                                 "hash mismatch on piece {} (expected: {:02x?}, actual: {:02x?})",
    //                                 index,
    //                                 expected,
    //                                 actual
    //                             );
    //                             pieces.remove(&index);
    //                             requested = false;
    //                         }
    //                     }
    //                 }
    //             }

    //             PeerMessage::Have(index) => {
    //                 log::debug!("peer {} has piece {}", self.addr, index);
    //                 if let Some(bf) = &mut self.bitfield {
    //                     bf.set(index as usize);
    //                 }
    //             }

    //             PeerMessage::Bitfield(payload) => {
    //                 let bf = BitField::new(payload);
    //                 log::debug!("received bitfield from {}: {:?}", self.addr, bf.pieces());
    //                 self.bitfield = Some(bf);
    //             }

    //             PeerMessage::Choke => {
    //                 self.choked = true;
    //                 log::info!("peer {} choked us", self.addr);
    //             }

    //             PeerMessage::KeepAlive => {
    //                 log::debug!("received keep-alive from {}", self.addr);
    //             }

    //             other => {
    //                 log::debug!("received other message from {}: {:?}", self.addr, other);
    //             }
    //         }

    //         if !self.choked && !requested {
    //             if let Some(bitfield) = &self.bitfield {
    //                 if current_piece >= total_pieces {
    //                     continue;
    //                 }

    //                 if !bitfield.has_piece(current_piece as usize) {
    //                     log::debug!(
    //                         "skipping piece {}: peer {} does not have it",
    //                         current_piece,
    //                         self.addr
    //                     );
    //                     current_piece += 1;
    //                     continue;
    //                 }

    //                 log::info!(
    //                     "requesting piece {} from {} (length: {})",
    //                     current_piece,
    //                     self.addr,
    //                     piece_length
    //                 );

    //                 let last_piece_len =
    //                     if (current_piece + 1) as u64 * piece_length as u64 > total_length {
    //                         (total_length - (current_piece as u64 * piece_length as u64)) as u32
    //                     } else {
    //                         piece_length
    //                     };

    //                 let mut offset = 0;
    //                 while offset < last_piece_len {
    //                     let block_size = BLOCK_SIZE.min(last_piece_len - offset);
    //                     log::debug!(
    //                         "requesting block: piece={}, offset={}, size={} from {}",
    //                         current_piece,
    //                         offset,
    //                         block_size,
    //                         self.addr
    //                     );
    //                     self.request_piece(current_piece, offset, block_size)?;
    //                     offset += block_size;
    //                 }

    //                 requested = true;
    //             }
    //         }
    //     }

    //     Ok(())
    // }

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
    use std::fs;
    // use std::io::Read;
    // use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn test_peer_handshake() {
        let _ = init_logging();

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

        let addr = match resp.peers.iter().find_map(|p| match p {
            SocketType::IPv4(addr) => Some(*addr),
            _ => None,
        }) {
            Some(ipv4) => ipv4,
            None => {
                eprintln!("no usable IPv4 peer found");
                return;
            }
        };

        match Peer::new(std::net::SocketAddr::V4(addr), &req.info_hash, &req.peer_id) {
            Ok(_) => {
                println!("handshake successful with peer {}", addr);
            }
            Err(e) => {
                eprintln!("skipping test: failed to connect to peer {}: {}", addr, e);
            }
        }
    }

    // #[test]
    // fn test_peer_download() {
    //     let _ = init_logging();

    //     let sample_path = SAMPLE_PATH;
    //     let bytes = fs::read(sample_path).expect("failed to read .torrent file");
    //     let torrent: Torrent = serde_bencode::from_bytes(&bytes).expect("invalid torrent file");

    //     let req = TrackerRequest {
    //         info_hash: torrent.info_hash(),
    //         peer_id: *b"-RU0001-123456789012",
    //         port: 6881,
    //         uploaded: 0,
    //         downloaded: 0,
    //         left: torrent.total_length(),
    //         compact: 1,
    //     };

    //     let resp = TrackerRequest::announce(&req, &torrent).expect("announce failed");

    //     let peer_addr = resp
    //         .peers
    //         .iter()
    //         .filter_map(|p| match p {
    //             SocketType::IPv4(addr) => Some(addr),
    //             _ => None,
    //         })
    //         .next()
    //         .expect("no peers found");

    //     let mut peer = Peer::new(
    //         std::net::SocketAddr::V4(*peer_addr),
    //         &req.info_hash,
    //         &req.peer_id,
    //     )
    //     .expect("failed to create peer");

    //     let piece_hash_fn = |i| torrent.piece_hash(i);
    //     let output_path = PathBuf::from(TARGET_PATH);

    //     // remove any existing file
    //     let _ = fs::remove_file(&output_path);

    //     peer.exchange(
    //         torrent.piece_length() as u32,
    //         torrent.total_length() as u64,
    //         &piece_hash_fn,
    //         output_path.clone(),
    //     )
    //     .expect("exchange failed");

    //     let mut file = fs::File::open(output_path).expect("failed to open output");
    //     let mut buf = vec![0u8; torrent.piece_length() as usize];
    //     file.read_exact(&mut buf).expect("failed to read piece");

    //     let actual_hash = sha1::Sha1::digest(&buf);
    //     let expected_hash = piece_hash_fn(0);
    //     assert_eq!(actual_hash[..], expected_hash[..], "piece hash mismatch");
    // }

    #[test]
    fn test_peer_run_download() {
        use std::collections::VecDeque;
        use std::sync::{mpsc, Arc, Mutex};
        use std::thread;

        let _ = init_logging();

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
                eprintln!(
                    "skipping test: failed to connect to peer {}: {}",
                    peer_addr, e
                );
                return;
            }
        };

        // Shared state
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
    fn test_peer_run_skips_missing_piece() {
        use std::collections::VecDeque;
        use std::sync::{mpsc, Arc, Mutex};
        use std::thread;

        let _ = init_logging();

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
                eprintln!(
                    "skipping test: failed to connect to peer {}: {}",
                    peer_addr, e
                );
                return;
            }
        };

        // Overwrite the peer's bitfield with one that doesn't have piece 0
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

        // Should timeout because the peer can't help
        let result = rx.recv_timeout(Duration::from_secs(5));
        assert!(
            result.is_err(),
            "peer should not have been able to send piece"
        );

        // The queue should still contain the piece
        let q = piece_queue.lock().unwrap();
        assert!(
            q.contains(&0),
            "piece 0 should have been requeued by the peer"
        );

        handle.join().unwrap();
    }
}
