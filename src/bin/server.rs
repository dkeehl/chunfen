extern crate chunfen;

use chunfen::server::Server;

fn main() {
    let listen_addr = "127.0.0.1:10000";
    let key = b"abc";

    Server::bind(listen_addr, key.to_vec())
}
