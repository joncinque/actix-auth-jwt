use lettre::{SendableEmail, Transport};

pub type ResultTransport<T, E> = dyn Transport<'static, Result = Result<T, E>>;
pub type EmptyResult = Result<(), ()>;
pub type EmptyResultTransport = ResultTransport<(), ()>;

pub struct InMemoryTransport {
    pub emails: Vec<SendableEmail>,
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
