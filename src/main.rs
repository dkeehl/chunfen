extern crate chunfen;

use chunfen::socks::Socks5;

fn main() {
    let listen_addr = "127.0.0.1:1080";

    Socks5::new(listen_addr);
}
