use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};

const HASH_SIZE: usize = 20;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Torrent {
    /// URL of the tracker
    pub announce: String,
    /// maps to a dictionary
    pub info: Info,
}

impl Torrent {
    pub fn info_hash(&self) -> [u8; HASH_SIZE] {
        let encoded = serde_bencode::to_bytes(&self.info);
        let mut h = Sha1::new();
        h.update(encoded.unwrap());
        h.finalize().into()
    }

    pub fn piece_length(&self) -> usize {
        match &self.info {
            Info::Single { piece_length, .. } => *piece_length,
            Info::Multi { piece_length, .. } => *piece_length,
        }
    }

    pub fn total_length(&self) -> usize {
        match &self.info {
            Info::Single { length, .. } => *length,
            Info::Multi { files, .. } => files.iter().map(|f| f.length).sum(),
        }
    }

    pub fn piece_hash(&self, index: u32) -> [u8; HASH_SIZE] {
        let pieces = match &self.info {
            Info::Single { pieces, .. } => pieces,
            Info::Multi { pieces, .. } => pieces,
        };

        let start = (index as usize) * HASH_SIZE;
        let end = start + HASH_SIZE;

        assert!(end <= pieces.len(), "piece index out of bounds");

        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&pieces[start..end]);
        hash
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum Mode {
    SingleFile {
        name: String,
        length: usize,
        // TODO: optional md5sum
    },
    MultiFile {
        name: String,
        length: usize,
        files: Vec<File>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct File {
    pub length: usize,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Info {
    Single {
        name: String,
        #[serde(rename = "piece length")]
        piece_length: usize,
        #[serde(with = "serde_bytes")]
        pieces: ByteBuf,
        length: usize,
    },
    Multi {
        name: String,
        #[serde(rename = "piece length")]
        piece_length: usize,
        #[serde(with = "serde_bytes")]
        pieces: ByteBuf,
        files: Vec<File>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SAMPLE_PATH;
    use serde_bencode::from_bytes;

    #[test]
    fn test_ci_torrent_parsing() {
        let bytes = std::fs::read(SAMPLE_PATH).expect("failed to read .torrent file");
        let torrent: Torrent = from_bytes(&bytes).expect("invalid torrent");
        log::info!("Parsed torrent: {:?}", torrent);
        assert_eq!(
            torrent.announce,
            "http://bttracker.debian.org:6969/announce"
        );
        assert_eq!(torrent.info_hash().len(), HASH_SIZE);
    }

    #[test]
    fn test_piece_hash() {
        let bytes = std::fs::read(SAMPLE_PATH).expect("failed to read .torrent file");
        let torrent: Torrent = from_bytes(&bytes).expect("invalid torrent");
        let piece_hash = torrent.piece_hash(0);
        assert_eq!(piece_hash.len(), HASH_SIZE);
        log::info!("Piece hash: {:?}", piece_hash);
    }
}
