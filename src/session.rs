use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use crate::download::PieceWriter;
use crate::peer::Peer;
use crate::torrent::Torrent;

pub struct Session {
    torrent: Arc<Torrent>,
    peers: Vec<SocketAddr>,
    peer_id: [u8; 20],
    output_path: PathBuf,
}

pub struct SessionStats {
    pub total_pieces: u32,
    pub completed_pieces: u32,
    pub failed_peers: u32,
    pub successful_peers: u32,
    // TODO: add more stats
}

impl Session {
    pub fn new(
        torrent: Torrent,
        peers: Vec<SocketAddr>,
        peer_id: [u8; 20],
        output_path: PathBuf,
    ) -> Self {
        Session {
            torrent: Arc::new(torrent),
            peers,
            peer_id,
            output_path,
        }
    }

    pub fn start(self) -> SessionStats {
        let piece_len = self.torrent.piece_length() as u32;
        let total_len = self.torrent.total_length() as u64;
        let total_pieces = ((total_len + piece_len as u64 - 1) / piece_len as u64) as u32;

        let piece_queue: VecDeque<u32> = (0..total_pieces).collect();
        let piece_queue = Arc::new(Mutex::new(piece_queue));

        let (tx, rx) = mpsc::channel::<(u32, Vec<u8>)>();

        let piece_hash_fn = Arc::new({
            let torrent = Arc::clone(&self.torrent);
            move |i| torrent.piece_hash(i)
        });

        let mut handles = vec![];
        let mut failed_peers = 0;
        let mut successful_peers = 0;

        for addr in &self.peers {
            let torrent = Arc::clone(&self.torrent);
            let piece_queue = Arc::clone(&piece_queue);
            let piece_hash_fn = Arc::clone(&piece_hash_fn);
            let tx = tx.clone();
            let peer_id = self.peer_id;
            let addr = *addr;

            let handle = thread::spawn(move || {
                if let Ok(peer) = Peer::new(addr, &torrent.info_hash(), &peer_id) {
                    peer.run(piece_len, total_len, piece_hash_fn, piece_queue, tx);
                    true
                } else {
                    log::warn!("Could not connect to peer: {}", addr);
                    false
                }
            });

            handles.push(handle);
        }

        let mut writer = PieceWriter::new(self.output_path, piece_len, total_len)
            .expect("Failed to create writer");
        let mut completed = 0;

        while completed < total_pieces {
            match rx.recv() {
                Ok((index, data)) => {
                    writer.write_piece(index, &data).expect("write failed");
                    completed += 1;
                    log::info!("Completed piece {} ({}/{})", index, completed, total_pieces);
                }
                Err(e) => {
                    log::error!("Receiver error: {}", e);
                    break;
                }
            }
        }

        for handle in handles {
            match handle.join() {
                Ok(true) => successful_peers += 1,
                Ok(false) => failed_peers += 1,
                Err(_) => failed_peers += 1,
            }
        }

        log::info!("Download complete: {} pieces written", completed);

        SessionStats {
            total_pieces,
            completed_pieces: completed,
            failed_peers,
            successful_peers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::torrent::Torrent;
    use crate::tracker::{peers::SocketType, TrackerRequest};
    use crate::util::init_logging;
    use crate::{SAMPLE_PATH, TARGET_PATH};
    use sha1::Digest;
    use std::fs;
    use std::io::Read;
    use std::net::SocketAddr;

    #[test]
    fn test_real_session_ipv4_full_download() {
        init_logging();

        let bytes = fs::read(SAMPLE_PATH).expect("failed to read .torrent file");
        let torrent: Torrent = serde_bencode::from_bytes(&bytes).expect("invalid torrent");

        let peer_id = *b"-RU0001-123456789012";
        let req = TrackerRequest {
            info_hash: torrent.info_hash(),
            peer_id,
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: torrent.total_length(),
            compact: 1,
        };

        let resp = TrackerRequest::announce(&req, &torrent).expect("announce failed");

        let peer_addrs: Vec<SocketAddr> = resp
            .peers
            .iter()
            .filter_map(|p| match p {
                SocketType::IPv4(addr) => Some(SocketAddr::V4(*addr)),
                _ => None,
            })
            .collect();

        if peer_addrs.is_empty() {
            log::error!("no IPv4 peers available; skipping test.");
            return;
        }

        let output_path = PathBuf::from(TARGET_PATH);
        let _ = fs::remove_file(&output_path);

        let session = Session::new(torrent.clone(), peer_addrs, peer_id, output_path.clone());
        session.start();

        // verify first piece was written correctly
        let mut file = fs::File::open(&output_path).expect("could not open output file");
        let mut buf = vec![0u8; torrent.piece_length() as usize];
        file.read_exact(&mut buf)
            .expect("could not read first piece");

        let actual_hash = sha1::Sha1::digest(&buf);
        let expected_hash = torrent.piece_hash(0);
        assert_eq!(actual_hash[..], expected_hash[..], "piece 0 hash mismatch");
    }

    #[test]
    fn test_real_session_ipv4_download_with_stats() {
        init_logging();

        let bytes = fs::read(SAMPLE_PATH).expect("failed to read .torrent file");
        let torrent: Torrent = serde_bencode::from_bytes(&bytes).expect("invalid torrent");

        let peer_id = *b"-RU0001-123456789012";
        let req = TrackerRequest {
            info_hash: torrent.info_hash(),
            peer_id,
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: torrent.total_length(),
            compact: 1,
        };

        let resp = TrackerRequest::announce(&req, &torrent).expect("announce failed");

        let peer_addrs: Vec<SocketAddr> = resp
            .peers
            .iter()
            .filter_map(|p| match p {
                SocketType::IPv4(addr) => Some(SocketAddr::V4(*addr)),
                _ => None,
            })
            .collect();

        if peer_addrs.is_empty() {
            log::error!("No IPv4 peers available; skipping test.");
            return;
        }

        let output_path = PathBuf::from(TARGET_PATH);
        let _ = fs::remove_file(&output_path);

        let session = Session::new(torrent.clone(), peer_addrs, peer_id, output_path.clone());
        let stats = session.start();

        assert_eq!(
            stats.completed_pieces, stats.total_pieces,
            "not all pieces were downloaded"
        );
        assert!(
            stats.successful_peers > 0,
            "no successful peers participated"
        );

        let mut file = fs::File::open(&output_path).expect("could not open output file");
        for i in 0..stats.total_pieces {
            let piece_len = if (i + 1) as u64 * torrent.piece_length() as u64
                > torrent.total_length() as u64
            {
                (torrent.total_length() as u64 - i as u64 * torrent.piece_length() as u64) as usize
            } else {
                torrent.piece_length()
            };
            let mut buf = vec![0u8; piece_len];
            file.read_exact(&mut buf)
                .expect("failed to read piece data");
            let actual_hash = sha1::Sha1::digest(&buf);
            let expected_hash = torrent.piece_hash(i);
            assert_eq!(
                actual_hash[..],
                expected_hash[..],
                "piece {} hash mismatch",
                i
            );
        }

        log::info!(
            "Download stats: {} pieces completed, {} successful peers",
            stats.completed_pieces,
            stats.successful_peers
        );
    }
}
