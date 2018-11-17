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
mod client;
mod server;
#[cfg(test)]
mod test;
pub mod stream;

pub use crate::data::TLSError;
pub use crate::session::Session;
pub use crate::client::ClientSession;
pub use crate::server::ServerSession;
