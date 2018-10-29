#![allow(unused)]

#[macro_use]
extern crate log;
extern crate time;
extern crate ring;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;
extern crate bytes;
#[macro_use]
extern crate nom;

use bytes::Bytes;

#[macro_use]
pub mod utils;
pub mod socks;
pub mod tunnel_port;
pub mod client;
pub mod server;
pub mod protocol;
pub mod framed;
//pub mod security;

type Id = u32;

type DomainName = Bytes;

type Port = u16;
