use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

//use tokio::sync::RwLock;
// TODO we can't easily use this because tokio's RwLock requires Sized right now
// which means we have to do:
// pub type ShareableData<T> = Arc<RwLock<Box<T>>>;
// which makes casting to Arc<RwLock<Box<dyn Trait>>> a *nightmare*

/// Async closures are complicated, so this type allows for a Future to exist
/// in multiple async contexts.
pub type PinFutureObj<Output> = Pin<Box<dyn Future<Output = Output>>>;

/// Convenience type to allow for mutability in routes.  Since service routes
/// only provide immutable access to AppData across threads, we need an Arc to
/// hold onto the data, and inside we need RwLock to limit write access to one
/// operation.
pub type ShareableData<T> = Arc<RwLock<T>>;

/// Simple function to create ShareableData
pub fn shareable_data<T>(data: T) -> ShareableData<T> {
    Arc::new(RwLock::new(data))
}
