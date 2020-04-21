use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

//use tokio::sync::RwLock;
// TODO we can't easily use this because tokio's RwLock requires Sized right now
// which means we have to do:
// pub type ShareableData<T> = Arc<RwLock<Box<T>>>;
// which makes casting to Arc<RwLock<Box<dyn Trait>>> a *nightmare*

// async closures are complicated.
pub type PinFutureObj<Output> = Pin<Box<dyn Future<Output = Output>>>;

pub type ShareableData<T> = Arc<RwLock<T>>;
