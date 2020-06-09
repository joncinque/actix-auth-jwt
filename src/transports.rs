use lettre::{SendableEmail, Transport};

pub type ResultTransport<T, E> = dyn Transport<'static, Result = Result<T, E>>;
pub type EmptyResult = Result<(), ()>;

/// Convenience type because the lettre Transport trait does not expose bounds
/// on the Result type until version 0.10
pub type EmptyResultTransport = ResultTransport<(), ()>;

/// A more easily-testable transport.  Instead of doing nothing, it stores
/// all emails internally, allowing tests to investigate them later.
pub struct InMemoryTransport {
    /// All messages submitted to the transport
    pub emails: Vec<SendableEmail>,
    /// Response to always be returned from send, allows testing error situations
    response: EmptyResult,
}

impl InMemoryTransport {
    pub fn new(response: EmptyResult) -> Self {
        let emails = Vec::new();
        InMemoryTransport {
            emails,
            response,
        }
    }

    pub fn new_positive() -> Self {
        Self::new(Ok(()))
    }
}

impl<'a> Transport<'a> for InMemoryTransport {
    type Result = EmptyResult;

    fn send(&mut self, email: SendableEmail) -> Self::Result {
        self.emails.push(email);
        self.response
    }
}
