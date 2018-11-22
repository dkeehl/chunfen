use std::io;
use futures::Future;

pub fn boxup<T: Future + Send + 'static>(x: T)
    -> Box<Future<Item=T::Item, Error=T::Error> + Send> { Box::new(x) }

pub fn invalid<T: AsRef<str>>(desc: T) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, desc.as_ref())
}

