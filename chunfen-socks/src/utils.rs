use futures::Future;

pub fn boxup<T: Future + Send + 'static>(x: T)
    -> Box<Future<Item=T::Item, Error=T::Error> + Send> { Box::new(x) }

