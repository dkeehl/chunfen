extern crate chunfen;

use chunfen::client::Client;

fn main() {
    let listen_addr = "127.0.0.1:1080";

    let server_addr = "127.0.0.1:10000";

    let key = b"abc";

    Client::new(listen_addr, server_addr, key.to_vec());
}
