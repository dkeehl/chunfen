/// A very limited subset of TLS
#[macro_use]
extern crate log;
extern crate ring;

#[macro_use]
mod macros;

pub mod stream;
pub mod client;
pub mod server;

mod data;
mod session;
mod encryption;
mod handshake;
mod key_schedule;
mod suites;
mod utils;

#[cfg(test)]
mod test;

pub use crate::data::TLSError;
