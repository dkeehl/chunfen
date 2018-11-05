use std::io::{self, Read, Write};
use std::collections::VecDeque;

pub struct VecBuffer {
    chunks: VecDeque<Vec<u8>>,
}

impl VecBuffer {
    pub fn new() -> VecBuffer {
        VecBuffer { chunks: VecDeque::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub fn take_one(&mut self) -> Vec<u8> {
        self.chunks.pop_front().unwrap()
    }

    pub fn append(&mut self, bytes: Vec<u8>) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }
        len
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offset = 0;

        while offset < buf.len() && !self.is_empty() {
            let used = self.chunks[0].as_slice().read(&mut buf[offset..])?;
            if used == self.chunks[0].len() {
                self.take_one();
            } else {
                self.chunks[0] = self.chunks[0].split_off(used);
            }
            offset += used;
        }
        Ok(offset)
    }

    pub fn write_to(&mut self, w: &mut Write) -> io::Result<usize> {
        if self.is_empty() {
            Ok(0)
        } else {
            let used = w.write(&self.chunks[0])?;
            if used == self.chunks[0].len() {
                self.take_one();
            } else {
                self.chunks[0] = self.chunks[0].split_off(used);
            }
            Ok(used)
        }
    }
}
