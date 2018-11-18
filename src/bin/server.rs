use std::net::{IpAddr, ToSocketAddrs};

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let program = &args[0];

    let mut opts = getopts::Options::new();
    opts.reqopt("k", "key", "Secret key for connect", "KEY")
        .reqopt("b", "bind", "Ip address to bind to", "IP")
        .reqopt("p", "port", "Port listening on", "PORT")
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
        println!("{}", opts.usage("Tunnel server"));
        return
    }

    let ip = matches.opt_str("b").unwrap();
    let port = matches.opt_str("p").unwrap();
    let ip: IpAddr = match ip.parse() {
        Ok(ip) => ip,
        Err(_) => { println!("Invalid ip address"); return },
    };
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(_) => { println!("Invalid port"); return },
    };

    let addr = (ip, port).to_socket_addrs().unwrap().next().unwrap();

    let key_str = matches.opt_str("k").unwrap();
    let key = match chunfen::checked_key::check(key_str) {
        Ok(k) => k,
        Err(e) => { println!("{}", e); return }
    };
    
    if matches.opt_present("log") {
        let _ = match matches.opt_str("l").and_then(|path| {
            fern::log_file(&path).ok()
        }) {
            Some(file) => logger_init(file),
            None => logger_init(std::io::stderr()),
        };
    }
    chunfen::Server::bind(&addr, key)
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
