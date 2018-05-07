use super::{Session, SecureStream};
use super::client::ClientSession;
use super::server::ServerSession;
use std::net::{TcpStream, TcpListener, Shutdown};
use std::io::{Read, Write};
use std::thread;
use rand::{Rng, thread_rng};

const HOST: &str = "127.0.0.1:10000";

#[test]
fn test_secure_stream() {
    thread::spawn(|| run_server());
    for i in 0..5 {
        let mut req = vec![0u8; 100];
        thread_rng().fill_bytes(&mut req[..]);
        let resp = run_client(&req);
        assert_eq!(req, resp)
    }
}

fn run_client(req: &Vec<u8>) -> Vec<u8> {
    let tcp = TcpStream::connect(HOST).unwrap();
    let session = ClientSession::new();
    let mut secure_stream = SecureStream::new(session, tcp);
    secure_stream.write_all(req).unwrap();
    let mut resp = Vec::new();
    secure_stream.read_to_end(&mut resp).unwrap();
    resp
}

fn run_server() {
    let listening = TcpListener::bind(HOST).unwrap();
    for stream in listening.incoming() {
        if let Ok(s) = stream {
            let session = ServerSession::new();
            let mut secure_stream = SecureStream::new(session, s);
            let mut buf = Vec::new();
            secure_stream.session.read_tls(&mut secure_stream.socket).unwrap();
            secure_stream.session.process_new_packets().unwrap();
            secure_stream.session.read_to_end(&mut buf).unwrap();
            secure_stream.write_all(&buf).unwrap();
        }
    }
}

