use {
    lettre::{address::Envelope, Transport},
    std::cell::RefCell,
};

pub type ResultTransport<T, E> = dyn Transport<Ok = T, Error = E>;
pub type EmptyResult = Result<(), ()>;

/// Convenience type because the lettre Transport trait does not expose bounds
/// on the Result type until version 0.10
pub type EmptyResultTransport = ResultTransport<(), ()>;

/// A more easily-testable transport.  Instead of doing nothing, it stores
/// all emails internally, allowing tests to investigate them later.
pub struct InMemoryTransport {
    /// All messages submitted to the transport
    pub emails: RefCell<Vec<(Envelope, Vec<u8>)>>,
    /// Response to always be returned from send, allows testing error situations
    response: EmptyResult,
}

impl InMemoryTransport {
    pub fn new(response: EmptyResult) -> Self {
        let emails = RefCell::new(vec![]);
        InMemoryTransport { emails, response }
    }
}

impl Default for InMemoryTransport {
    fn default() -> Self {
        Self::new(Ok(()))
    }
}

impl Transport for InMemoryTransport {
    type Ok = ();
    type Error = ();

    fn send_raw(&self, envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.emails
            .borrow_mut()
            .push((envelope.clone(), email.to_vec()));
        self.response
    }
}
