/// A very limited subset of TLS
#[macro_use]
extern crate log;
extern crate ring;

#[macro_use]
mod macros;

mod data;
#[macro_use]
mod session;
mod encryption;
mod handshake;
mod key_schedule;
mod suites;
mod utils;

pub mod stream;
pub mod client;
pub mod server;

#[cfg(test)]
mod test;

pub use crate::data::TLSError;
pub use crate::session::Session;
