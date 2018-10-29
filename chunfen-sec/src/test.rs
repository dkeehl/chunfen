use super::{Session, SecureStream};
use super::client::ClientSession;
use super::server::ServerSession;
use super::rand;
use std::net::{TcpStream, TcpListener, Shutdown};
use std::io::{Read, Write};
use std::thread;

use log::{self, Record, Metadata, Level, SetLoggerError};

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _: &Metadata) -> bool { true }

    fn log(&self, record: &Record) {
        println!("{} - {}", record.level(), record.args())
    }

    fn flush(&self) {}
}

impl SimpleLogger {
    fn init() -> Result<(), SetLoggerError> {
        log::set_boxed_logger(Box::new(SimpleLogger))?;
        log::set_max_level(Level::Trace.to_level_filter());
        Ok(())
    }
}

const HOST: &str = "127.0.0.1";
const SHAREKEY: &str = "testkey";

#[test]
fn test_secure_stream() {
    let port: u16 = 10000;
    thread::spawn(move || run_server(port));
    for i in 0..5 {
        let mut req = vec![0u8; 100];
        rand::fill_random(&mut req[..]);
        let resp = run_client(port, &req);
        assert_eq!(req, resp)
    }
}

#[test]
fn test_handshake() {
    //SimpleLogger::init().unwrap();
    let port: u16 = 10001;
    thread::spawn(move || run_server(port));

    let tcp = TcpStream::connect((HOST, port)).unwrap();
    let session = ClientSession::new(SHAREKEY);
    assert!(session.is_handshaking());
    let mut secure_stream = SecureStream::new(session, tcp);
    // do handshake
    secure_stream.complete_prior_io().unwrap();
    assert!(!secure_stream.session.is_handshaking())
}

fn run_client(port: u16, req: &Vec<u8>) -> Vec<u8> {
    let tcp = TcpStream::connect((HOST, port)).unwrap();
    let session = ClientSession::new(SHAREKEY);
    let mut secure_stream = SecureStream::new(session, tcp);
    secure_stream.write_all(req).unwrap();
    let mut resp = Vec::new();
    secure_stream.read_to_end(&mut resp).unwrap();
    resp
}

fn run_server(port: u16) {
    let listening = TcpListener::bind((HOST, port)).unwrap();
    for stream in listening.incoming() {
        if let Ok(s) = stream {
            let session = ServerSession::new(SHAREKEY);
            let mut secure_stream = SecureStream::new(session, s);
            //handshake
            secure_stream.complete_prior_io().unwrap();
            //server task
            let mut buf = Vec::new();
            secure_stream.session.read_tls(&mut secure_stream.socket).unwrap();
            secure_stream.session.process_new_packets().unwrap();
            secure_stream.session.read_to_end(&mut buf).unwrap();
            secure_stream.write_all(&buf).unwrap();
        }
    }
}

