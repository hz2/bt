use std::io::{Error, ErrorKind};

#[derive(Debug, PartialEq)]
pub struct BitField {
    pub payload: Vec<u8>,
    pub len: usize,
}

impl BitField {
    pub fn new(payload: Vec<u8>) -> BitField {
        let len = payload.len();
        BitField { payload, len }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BitField, Error> {
        if bytes.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "empty byte array"));
        }
        if bytes[0] as usize != bytes.len() - 1 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "length mismatch in BitField",
            ));
        }
        let len = bytes.len() - 1;
        let bitfield = bytes[1..].to_vec();
        Ok(BitField {
            payload: bitfield,
            len,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; self.len + 1];
        bytes[0] = self.len as u8;
        bytes[1..].copy_from_slice(&self.payload);
        bytes
    }

    /// Returns true if the bit at the given index is set.
    pub fn is_set(&self, index: usize) -> bool {
        let byte = index / 8;
        let bit = index % 8;
        let mask = 1 << (7 - bit);
        self.payload[byte] & mask != 0
    }

    pub fn set(&mut self, index: usize) {
        let byte = index / 8;
        let bit = index % 8;
        let mask = 1 << (7 - bit);
        self.payload[byte] |= mask;
    }

    pub fn unset(&mut self, index: usize) {
        let byte = index / 8;
        let bit = index % 8;
        let mask = 1 << (7 - bit);
        self.payload[byte] &= !mask;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn iter(&self) -> BitfieldIter {
        BitfieldIter {
            bitfield: self,
            index: 0,
        }
    }

    pub fn is_subset(&self, other: &BitField) -> bool {
        self.iter().zip(other.iter()).all(|(a, b)| !a || b)
    }

    pub fn has_piece(&self, index: usize) -> bool {
        self.is_set(index)
    }

    pub fn pieces(&self) -> Vec<usize> {
        self.iter()
            .enumerate()
            .filter(|&(_, b)| b)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.iter().all(|b| b)
    }

    pub fn is_empty(&self) -> bool {
        self.iter().all(|b| !b)
    }
}

pub struct BitfieldIter<'a> {
    bitfield: &'a BitField,
    index: usize,
}

impl<'a> Iterator for BitfieldIter<'a> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.index >= self.bitfield.len {
            return None;
        }
        let bit = self.bitfield.is_set(self.index);
        self.index += 1;
        Some(bit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitfield_new() {
        let bitfield = BitField::new(vec![0b00000001, 0b00000000]);
        assert_eq!(bitfield.len, 2);
        assert_eq!(bitfield.payload, vec![0b00000001, 0b00000000]);
    }

    #[test]
    fn bitfield_has() {
        let bf = BitField {
            payload: vec![0b10101010, 0b01010101],
            len: 16,
        };
        assert!(bf.has_piece(0));
        assert!(!bf.has_piece(1));
        assert!(!bf.has_piece(7));
        assert!(!bf.has_piece(8));
        assert!(bf.has_piece(15));
    }
}
