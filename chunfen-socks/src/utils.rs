use futures::Future;

pub fn boxup<T: Future + 'static>(x: T) -> Box<Future<Item=T::Item, Error=T::Error>> {
    Box::new(x)
}

