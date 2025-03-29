use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

#[derive(Debug)]
pub struct Piece {
    pub index: u32,
    pub blocks: HashMap<u32, Vec<u8>>, // begin offset -> block data
    pub length: u32,
    pub block_size: u32,
}

impl Piece {
    pub fn new(index: u32, length: u32, block_size: u32) -> Self {
        Self {
            index,
            length,
            block_size,
            blocks: HashMap::new(),
        }
    }

    pub fn is_complete(&self) -> bool {
        let mut total: u32 = 0;
        for block in self.blocks.values() {
            total += block.len() as u32;
        }
        total >= self.length
    }

    pub fn add_block(&mut self, begin: u32, data: Vec<u8>) {
        self.blocks.insert(begin, data);
    }

    pub fn assemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        log::info!("assembling piece {}", self.index);
        let mut assembled = vec![0u8; self.length as usize];
        for (&begin, data) in &self.blocks {
            let end = (begin + data.len() as u32).min(self.length);
            assembled[begin as usize..end as usize]
                .copy_from_slice(&data[..(end - begin) as usize]);
        }
        Some(assembled)
    }
}

#[derive(Debug)]
pub struct PieceWriter {
    pub file: File,
    pub piece_length: u32,
    pub total_length: u64,
}

impl PieceWriter {
    pub fn new(path: PathBuf, piece_length: u32, total_length: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new().write(true).create(true).open(path)?;
        file.set_len(total_length)?;
        Ok(Self {
            file,
            piece_length,
            total_length,
        })
    }

    pub fn write_piece(&mut self, index: u32, data: &[u8]) -> std::io::Result<()> {
        log::info!("writing piece {} to disk", index);
        let offset = (index as u64) * (self.piece_length as u64);
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        Ok(())
    }
}
