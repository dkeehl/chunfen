use std::net::{TcpStream, TcpListener};
use std::thread;
use std::sync::mpsc::{Sender, Receiver, channel, TryRecvError};
use std::marker::Send;
use std::time::Duration;
use time::{Timespec, get_time};

use {Talker, communicate, Addr, TcpConnection, Result};
use client::socks::SocksConnection;
use protocol::*;

pub mod socks;

enum TunnelMsg {
    HeartBeat,
    Connect(Addr),
    Write(Vec<u8>),
    ShutdownWrite,

    Close,
}

enum SocksMsg {
}

struct Tunnel {
    //connection with the server,
    //set to None when no connection established.
    tcp: TcpConnection,  
    
    timer: Sender<TimerMsg>,
}

impl Tunnel {
    pub fn new(server: &str) -> Tunnel {
        
        //crash if connection failed
        let stream = TcpStream::connect(server).unwrap();
        let tcp = TcpConnection(stream.try_clone().unwrap());

        let (timer, receiver) = channel();
        heart_beat_start(receiver, TcpConnection(stream));

        Tunnel { tcp, timer, }
    }
}

enum TimerMsg {
    Update,
    Close,
}

fn heart_beat_start<T>(receiver: Receiver<TimerMsg>, mut tcp: T)
    where T: WriteTcp<TunnelMsg> + Send + 'static
{
    thread::spawn(move || {
        let t = Duration::from_millis(HEARTBEAT_INTERVAL_MS as u64);
        loop {
            thread::sleep(t);

            match receiver.try_recv() {
                Ok(TimerMsg::Update) => continue,

                Err(TryRecvError::Empty) =>
                    tcp.response(TunnelMsg::HeartBeat).unwrap(),

                _ => break,
            }
        }
    });
}

trait WriteTcp<T> {
    fn response(&mut self, resp: T) -> Result<()>;
}

impl WriteTcp<TunnelMsg> for TcpConnection {
    fn response(&mut self, resp: TunnelMsg) -> Result<()> {
        Ok(())
    }
}

impl Talker<SocksMsg, TunnelMsg> for Tunnel {
    fn tell<T, W>(&mut self, other: &mut T) where T: Talker<W, SocksMsg> {

    }

    fn told(&mut self, msg: TunnelMsg) {
    }
}

pub struct Client; 

impl Client {
    pub fn new(listen_addr: &str, server_addr: &str) {
        let listening = TcpListener::bind(listen_addr).unwrap();
        let mut tunnel = Tunnel::new(server_addr);

        for s in listening.incoming() {
            if let Ok(stream) = s {     //stream: TcpStream
                let mut socks_connection = SocksConnection::new(stream);
                communicate(&mut socks_connection, &mut tunnel);
            }
        }
    }
}

