use lettre_email::EmailBuilder;
use lettre::Transport;

use crate::errors::{self, AuthApiError};
use crate::transports::{InMemoryTransport, EmptyResultTransport};
use crate::types::{shareable_data, ShareableData};

pub struct EmailSender {
    from: String,
    transport: ShareableData<EmptyResultTransport>,
}

#[derive(Clone)]
pub enum EmailTransportType {
    InMemory,
    Stub,
}

#[derive(Clone)]
pub struct EmailConfig {
    pub from: String,
    pub transport_type: EmailTransportType,
}

impl EmailSender {
    pub fn new(from: String, transport: ShareableData<EmptyResultTransport>) -> Self {
        EmailSender { from, transport }
    }

    pub fn from(config: &EmailConfig) -> Self {
        let transport = match config.transport_type {
            _ => shareable_data(InMemoryTransport::new_positive())
        };
        let from = config.from.clone();
        EmailSender { from, transport }
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
    use crate::transports::InMemoryTransport;
    use super::*;

    #[actix_rt::test]
    async fn inmemory_sender() {
        let transport = shareable_data(InMemoryTransport::new_positive());
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
