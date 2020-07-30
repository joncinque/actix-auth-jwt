use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;

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
