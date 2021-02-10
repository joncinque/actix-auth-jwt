use {
    crate::{
        errors::{self, AuthApiError},
        transports::{EmptyResultTransport, InMemoryTransport},
        types::{shareable_data, ShareableData},
    },
    lettre_email::EmailBuilder,
};

/// Wrapper around lettre transport to generalize transports for the app, and
/// not needing to parametrize every single function by the transport's Result
/// type.
pub struct EmailSender {
    pub from: String,
    pub transport: ShareableData<EmptyResultTransport>,
}

impl EmailSender {
    pub fn new(from: String, transport: ShareableData<EmptyResultTransport>) -> Self {
        EmailSender { from, transport }
    }

    /// Main send function.  Note that this isn't actually async at the moment!
    pub async fn send(&mut self, builder: EmailBuilder) -> Result<(), AuthApiError> {
        let email = builder
            .from(self.from.as_str())
            .build()
            .map_err(errors::from_lettre)?;

        self.transport
            .write()
            .await
            .send(email.into())
            .map_err(errors::from_empty)
    }
}

impl Default for EmailSender {
    fn default() -> Self {
        let transport: ShareableData<InMemoryTransport> = shareable_data(Default::default());
        let from = String::from("admin@example.com");
        EmailSender { from, transport }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::InMemoryTransport;

    #[actix_rt::test]
    async fn inmemory_sender() {
        let transport: ShareableData<InMemoryTransport> = shareable_data(Default::default());
        let base_transport: ShareableData<EmptyResultTransport> = transport.clone();
        let mut sender = EmailSender::new(String::from("admin@example.com"), base_transport);
        let to = "test@example.com";
        let body = "Message body!";
        let email = EmailBuilder::new().to(to).body(body);
        sender.send(email).await.unwrap();

        let transport = transport.read().await;
        assert_eq!(transport.emails.len(), 1);
    }
}
