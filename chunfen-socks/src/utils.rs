use std::io;
use futures::Future;

pub fn not_connected() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "not connected")
}

pub fn boxup<T: Future + 'static>(x: T) -> Box<Future<Item=T::Item, Error=T::Error>> {
    Box::new(x)
}

