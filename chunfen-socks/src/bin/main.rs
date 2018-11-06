extern crate getopts;
extern crate chunfen_socks;

use std::env;
use std::net::{IpAddr, ToSocketAddrs};
use getopts::Options;
use chunfen_socks::Socks5;

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    let mut opts = Options::new();
    opts.optopt("b", "bind", "Ip address to bind to", "IP")
        .optopt("p", "port", "Port listening on", "PORT")
        .optflag("h", "help", "Show usage");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            println!("{}", opts.short_usage(program));
            return
        },
    };

    if matches.opt_present("help") {
        println!("{}", opts.usage("Socks proxy server"));
        return
    }

    let ip = matches.opt_str("b").unwrap_or("127.0.0.1".to_string());
    let port = matches.opt_str("p").unwrap_or("1080".to_string());
    let ip: IpAddr = match ip.parse() {
        Ok(ip) => ip,
        Err(_) => { println!("Invalid ip address"); return },
    };
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => { println!("Invalid port"); return },
    };

    let listen_addr = (ip, port).to_socket_addrs().unwrap().next().unwrap();
    Socks5::bind(&listen_addr);
}

