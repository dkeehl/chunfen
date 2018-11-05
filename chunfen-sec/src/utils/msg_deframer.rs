use std::collections::VecDeque;
use std::io::{self, Read};

use crate::data::{ContentType, CipherText};
use crate::utils::codec::{Codec, Reader};

pub struct MsgDeframer {
    frames: VecDeque<CipherText>, // completed frames for output
    
    // set to true if the peer not talking in the right protocol
    desynced: bool,
    buf: Vec<u8>,
}

const HEADER_SIZE: usize = 1 + 2;
const MAX_MESSAGES: usize = 16384 + 2048 + HEADER_SIZE;

impl MsgDeframer {
    pub fn new() -> MsgDeframer {
        MsgDeframer {
            frames: VecDeque::new(),
            desynced: false,
            buf: Vec::new(),
        }
    }

    pub fn pop_front(&mut self) -> Option<CipherText> {
        self.frames.pop_front()
    }

    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty() || !self.buf.is_empty()
    }

    pub fn read_from(&mut self, r: &mut Read) -> io::Result<usize> {
        let used = self.buf.len();
        self.buf.resize(MAX_MESSAGES, 0u8);

        match r.read(&mut self.buf[used..MAX_MESSAGES]) {
            Ok(new_bytes) => {
                self.buf.truncate(used + new_bytes);
                loop {
                    match self.buf_contains_message() {
                        None => {
                            self.desynced = true;
                            break
                        },
                        Some(true) => {
                            self.deframe_one();
                        },
                        Some(false) => break,
                    }
                }
                Ok(new_bytes)
            },
            Err(e) => {
                self.buf.truncate(used);
                Err(e)
            },
        }
    }

    fn deframe_one(&mut self) {
        let used = {
            let mut r = Reader::init(&self.buf);
            let m = CipherText::read(&mut r).unwrap();
            self.frames.push_back(m);
            r.used()
        };
        self.buf = self.buf.split_off(used);
    }

    fn buf_contains_message(&self) -> Option<bool> {
        if self.buf.len() < HEADER_SIZE {
            return Some(false) 
        }

        check_header(&self.buf).and_then(|len|
            if len >= MAX_MESSAGES - HEADER_SIZE {
                None
            } else {
                let is_full_message = self.buf.len() >= len + HEADER_SIZE;
                Some(is_full_message)
            }
        )
    }
}

fn check_header(buf: &[u8]) -> Option<usize> {
    let mut buf = Reader::init(buf);
    ContentType::read(&mut buf).and_then(|ty| {
        match ty {
            ContentType::Unknown(_) => None,
            _ => u16::read(&mut buf).map(|x| x as usize)
        }
    })
}
