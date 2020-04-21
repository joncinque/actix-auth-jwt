use lettre_email::EmailBuilder;

use crate::errors::{self, AuthApiError};
use crate::transports::EmptyResultTransport;
use crate::types::ShareableData;

pub struct EmailSender {
    from: String,
    transport: ShareableData<EmptyResultTransport>,
}

impl EmailSender {
    pub fn new(from: String, transport: ShareableData<EmptyResultTransport>) -> Self {
        EmailSender {
            from,
            transport
        }
    }

    pub async fn send(&mut self, builder: EmailBuilder) -> Result<(), AuthApiError> {
        let email = builder
            .from(self.from.as_str())
            .build()
            .map_err(errors::from_lettre)?;

        self.transport.write().unwrap().send(email.into()).map_err(errors::from_empty)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};
    //use tokio::sync::RwLock; // once RwLock is Sized? we'll be good

    use crate::transports::InMemoryTransport;
    use super::*;

    #[actix_rt::test]
    async fn inmemory_sender() {
        let transport = Arc::new(RwLock::new(InMemoryTransport::new_positive()));
        let base_transport: ShareableData<EmptyResultTransport> = transport.clone();
        let from = String::from("admin@example.com");
        let to = "test@example.com";
        let body = "Message body!";
        let mut sender = EmailSender::new(from, base_transport);
        let email = EmailBuilder::new().to(to).body(body);
        sender.send(email).await.unwrap();

        let transport = transport.read().unwrap();
        assert_eq!(transport.emails.len(), 1);
    }
}
