use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use nostr_sdk::prelude::*;
use nostr_sdk::Client;

use crate::manifest::Manifest;

pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
];

/// Attempt to discover relays from known registry APIs, falling back to DEFAULT_RELAYS.
pub async fn discover_relays() -> Vec<String> {
    let registries = &[
        "https://api.nostr.watch/v1/online",
        "https://relay.nostr.band/all",
        "https://nostr.watch/api/relays",
    ];
    for url in registries {
        match reqwest::get(*url).await {
            Ok(resp) => {
                if let Ok(body) = resp.text().await {
                    // Try to parse as JSON array of strings (simple relay URLs)
                    if let Ok(urls) = serde_json::from_str::<Vec<String>>(&body) {
                        let relays: Vec<String> = urls.into_iter()
                            .filter(|u| u.starts_with("wss://"))
                            .collect();
                        if !relays.is_empty() {
                            return relays;
                        }
                    }
                    // Try to parse as array of objects with a "url" field (nostr.watch style)
                    #[derive(serde::Deserialize)]
                    struct RelayEntry { url: String }
                    if let Ok(entries) = serde_json::from_str::<Vec<RelayEntry>>(&body) {
                        let relays: Vec<String> = entries.into_iter()
                            .map(|e| e.url)
                            .filter(|u| u.starts_with("wss://"))
                            .collect();
                        if !relays.is_empty() {
                            return relays;
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }
    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
}
pub const MANIFEST_SIZE_LIMIT: usize = 48 * 1024; // 48 KiB — safe margin below most relay limits (64 KiB std)
pub const D_TAG_PREFIX: &str = "zerodrive/manifest";
const KIND_30078: u16 = 30078;

/// Wraps Nostr communication for reading/writing manifests.
#[derive(Clone)]
pub struct ManifestPointer {
    keys: Keys,
    client: Client,
}

impl ManifestPointer {
    pub async fn new(secret_key_bytes: &[u8; 32], relays: &[String]) -> Result<Self> {
        let sk = SecretKey::from_slice(secret_key_bytes)
            .context("invalid Nostr secret key")?;
        let keys = Keys::new(sk);
        let relays = if relays.is_empty() {
            discover_relays().await
        } else {
            relays.to_vec()
        };

        let client = Client::builder().signer(keys.clone()).build();
        for relay in &relays {
            client.add_relay(relay).await?;
        }
        client.connect_with_timeout(Duration::from_secs(15)).await;

        Ok(Self { keys, client })
    }

    /// Publish a manifest with a specific d-tag.
    pub async fn publish_with_tag(&self, manifest: &Manifest, enc_key: &[u8; 32], d_tag: &str) -> Result<String> {
        let ciphertext = manifest.encrypt(enc_key).await?;
        let content = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
        if content.len() > MANIFEST_SIZE_LIMIT {
            anyhow::bail!(
                "manifest too large ({} bytes, limit ~{} KiB). \
                 The drive will be moved to a new manifest automatically.",
                content.len(), MANIFEST_SIZE_LIMIT / 1024,
            );
        }

        let builder = EventBuilder::new(Kind::Custom(KIND_30078), content)
            .tag(Tag::identifier(d_tag));

        let event_id = self
            .client
            .send_event_builder(builder)
            .await
            .context("publishing manifest event")?;

        Ok(event_id.to_string())
    }

    /// Publish with the default d-tag (backward compat).
    pub async fn publish(&self, manifest: &Manifest, enc_key: &[u8; 32]) -> Result<String> {
        self.publish_with_tag(manifest, enc_key, D_TAG_PREFIX).await
    }

    /// Resolve the default manifest only (backward compat).
    pub async fn resolve(&self, enc_key: &[u8; 32]) -> Result<Option<Manifest>> {
        let filter = Filter::new()
            .author(self.keys.public_key())
            .kind(Kind::Custom(KIND_30078))
            .identifier(D_TAG_PREFIX)
            .limit(1);

        let events = self
            .client
            .fetch_events(vec![filter], Duration::from_secs(15))
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

    /// Resolve ALL manifests with d-tag starting with "zerodrive/manifest".
    /// Returns a map of d_tag → Manifest.
    pub async fn resolve_all(&self, enc_key: &[u8; 32]) -> Result<BTreeMap<String, Manifest>> {
        let filter = Filter::new()
            .author(self.keys.public_key())
            .kind(Kind::Custom(KIND_30078))
            .limit(1000);

        let events = self
            .client
            .fetch_events(vec![filter], Duration::from_secs(15))
            .await?;

        // Group events by d-tag, keeping only the NEWEST event per d-tag
        let mut events_by_tag: BTreeMap<String, Event> = BTreeMap::new();
        for event in events {
            let d_tag = event.tags.iter()
                .find_map(|tag| {
                    let parts = tag.clone().to_vec();
                    if parts.len() >= 2 && parts[0] == "d" {
                        Some(parts[1].clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            if d_tag != D_TAG_PREFIX && !d_tag.starts_with(&format!("{}/", D_TAG_PREFIX)) {
                continue;
            }
            match events_by_tag.entry(d_tag) {
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if event.created_at > entry.get().created_at {
                        entry.insert(event);
                    }
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(event);
                }
            }
        }

        // Decrypt only the newest event per d-tag
        let mut result = BTreeMap::new();
        for (d_tag, event) in events_by_tag {
            let ciphertext = match base64::engine::general_purpose::STANDARD
                .decode(event.content.as_bytes())
            {
                Ok(c) => c,
                Err(_) => continue,
            };
            match Manifest::decrypt(&ciphertext, enc_key).await {
                Ok(manifest) => { result.insert(d_tag, manifest); }
                Err(_) => continue,
            }
        }

        Ok(result)
    }

    /// Publish manifest with a d-tag and update its prev_event_id.
    pub async fn publish_and_update_with_tag(
        &self,
        manifest: &mut Manifest,
        enc_key: &[u8; 32],
        d_tag: &str,
    ) -> Result<String> {
        let event_id = self.publish_with_tag(manifest, enc_key, d_tag).await?;
        manifest.prev_event_id = Some(event_id.clone());
        Ok(event_id)
    }

    /// Publish default manifest and update prev_event_id (backward compat).
    pub async fn publish_and_update(
        &self,
        manifest: &mut Manifest,
        enc_key: &[u8; 32],
    ) -> Result<String> {
        self.publish_and_update_with_tag(manifest, enc_key, D_TAG_PREFIX).await
    }
}

/// Generate the next available manifest d-tag (e.g. "zerodrive/manifest/0", "/1", etc.)
pub fn next_manifest_tag(manifests: &BTreeMap<String, Manifest>) -> String {
    let prefix = format!("{}/", D_TAG_PREFIX);
    let mut max_idx: i32 = -1;
    for d_tag in manifests.keys() {
        if let Some(suffix) = d_tag.strip_prefix(&prefix) {
            if let Ok(idx) = suffix.parse::<i32>() {
                max_idx = max_idx.max(idx);
            }
        }
    }
    format!("{}/{}", D_TAG_PREFIX, max_idx + 1)
}
