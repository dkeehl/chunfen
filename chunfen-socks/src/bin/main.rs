extern crate chunfen_socks;

use chunfen_socks::Socks5;

fn main() {
    let listen_addr = "127.0.0.1:1080";

    Socks5::bind(listen_addr);
}
