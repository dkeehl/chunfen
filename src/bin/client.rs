use std::net::{IpAddr, ToSocketAddrs};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let program = &args[0];

    let mut opts = getopts::Options::new();
    opts.reqopt("s", "server", "Remote server address", "IP:PORT")
        .reqopt("k", "key", "Secret key for connect", "KEY")
        .optopt("b", "bind", "Ip address to bind to", "IP")
        .optopt("p", "port", "Port listening on", "PORT")
        .optflag("h", "help", "Show usage")
        .optflagopt("l", "log", "Enable log", "PATH_TO_FILE");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            println!("{}", opts.short_usage(program));
            return
        },
    };

    if matches.opt_present("help") {
        println!("{}", opts.usage("Tunnel client"));
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

    let addr_str = matches.opt_str("s").unwrap();
    let server_addr =
        match addr_str.to_socket_addrs().ok().and_then(|mut iter| iter.next()) {
            Some(addr) => addr,
            None => {
                println!("Invalid server address. A valid address is like ip:port");
                return
            }
        };

    let key = matches.opt_str("k").unwrap().into_bytes();
    
    if matches.opt_present("log") {
        let _ = match matches.opt_str("l").and_then(|path| {
            fern::log_file(&path).ok()
        }) {
            Some(file) => logger_init(file),
            None => logger_init(std::io::stderr()),
        };
    }
    chunfen::Client::new(&listen_addr, &server_addr, key);
}

fn logger_init<T: Into<fern::Output>>(logger: T) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                    "{}[{}] - {}",
                    chrono::Local::now().format("[%Y-%m-%d %H:%M]"),
                    record.level(),
                    message))
        })
        .level(log::LevelFilter::Info)
        .chain(logger)
        .apply()?;
    Ok(())
}
