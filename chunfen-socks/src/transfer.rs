use std::io;

use futures::future;
use futures::Future;
use tokio_core::reactor::Handle;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_io::io::copy;

use crate::utils::boxup;

pub fn pipe<T, S>(a: T, b: S, handle: Handle)
    -> Box<Future<Item = (usize, usize), Error = io::Error>>
    where
        T: AsyncRead + AsyncWrite + 'static,
        S: AsyncRead + AsyncWrite + 'static
{
    let (a_read, a_write) = a.split();
    let (b_read, b_write) = b.split();

    let hdl = handle.clone();
    let half1 = copy(a_read, b_write)
        .map(|res| shutdown_and_return(res, hdl));
    let half2 = copy(b_read, a_write)
        .map(|res| shutdown_and_return(res, handle));
    boxup(half1.join(half2))
}

fn shutdown_and_return<R, W>(res: (u64, R, W), handle: Handle) -> usize where
    W: AsyncWrite + 'static
{ 
    let (n, _, mut wt) = res;
    let shutdown = future::poll_fn(move || wt.shutdown())
        .map_err(|_| ());
    handle.spawn(shutdown);
    n as usize
}

