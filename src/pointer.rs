use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use nostr_sdk::prelude::*;
use nostr_sdk::Client;

use crate::manifest::Manifest;

pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nostr.wine",
    "wss://relay.nostr.band",
];
pub const MANIFEST_SIZE_LIMIT: usize = 48 * 1024; // 48 KiB — safe margin below most relay limits (64 KiB std)
const D_TAG_VALUE: &str = "zerodrive/manifest";
const KIND_30078: u16 = 30078;

/// Wraps Nostr communication for reading/writing the manifest.
#[derive(Clone)]
pub struct ManifestPointer {
    keys: Keys,
    client: Client,
}

impl ManifestPointer {
    /// Create a new pointer, connecting to Nostr relays.
    pub async fn new(secret_key_bytes: &[u8; 32], relays: &[String]) -> Result<Self> {
        let sk = SecretKey::from_slice(secret_key_bytes)
            .context("invalid Nostr secret key")?;
        let keys = Keys::new(sk);
        let relays = if relays.is_empty() {
            DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            relays.to_vec()
        };

        let client = Client::builder().signer(keys.clone()).build();
        for relay in &relays {
            client.add_relay(relay).await?;
        }
        client.connect().await;

        Ok(Self { keys, client })
    }

    /// Publish the manifest as a kind 30078 replaceable event.
    pub async fn publish(&self, manifest: &Manifest, enc_key: &[u8; 32]) -> Result<String> {
        let ciphertext = manifest.encrypt(enc_key).await?;
        let content = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
        if content.len() > MANIFEST_SIZE_LIMIT {
            anyhow::bail!(
                "manifest too large ({} bytes, limit ~{} KiB). Add relays with higher limits or remove files.",
                content.len(), MANIFEST_SIZE_LIMIT / 1024,
            );
        }

        let builder = EventBuilder::new(Kind::Custom(KIND_30078), content)
            .tag(Tag::identifier(D_TAG_VALUE));

        let event_id = self
            .client
            .send_event_builder(builder)
            .await
            .context("publishing manifest event")?;

        Ok(event_id.to_string())
    }

    /// Resolve the latest manifest from relays.
    pub async fn resolve(&self, enc_key: &[u8; 32]) -> Result<Option<Manifest>> {
        let filter = Filter::new()
            .author(self.keys.public_key())
            .kind(Kind::Custom(KIND_30078))
            .identifier(D_TAG_VALUE)
            .limit(1);

        let events = self
            .client
            .fetch_events(vec![filter], Duration::from_secs(10))
            .await?;

        let best = events.into_iter().max_by_key(|e| e.created_at.as_u64());
        match best {
            Some(event) => {
                let ciphertext = base64::engine::general_purpose::STANDARD
                    .decode(event.content.as_bytes())?;
                let manifest = Manifest::decrypt(&ciphertext, enc_key).await?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }

    /// Publish manifest and update its prev_event_id.
    pub async fn publish_and_update(
        &self,
        manifest: &mut Manifest,
        enc_key: &[u8; 32],
    ) -> Result<String> {
        let event_id = self.publish(manifest, enc_key).await?;
        manifest.prev_event_id = Some(event_id.clone());
        Ok(event_id)
    }

}
