use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Torrent {
    /// URL of the tracker
    pub announce: String,
    /// maps to a dictionary
    pub info: Info,
}

impl Torrent {
    pub fn info_hash(&self) -> [u8; 20] {
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

    pub fn piece_hash(&self, index: u32) -> [u8; 20] {
        let pieces = match &self.info {
            Info::Single { pieces, .. } => pieces,
            Info::Multi { pieces, .. } => pieces,
        };

        let start = (index as usize) * 20;
        let end = start + 20;

        assert!(end <= pieces.len(), "piece index out of bounds");

        let mut hash = [0u8; 20];
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
    pub path: Vec<String>, // Bencoded as a list of path components
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

// TODO: testing
