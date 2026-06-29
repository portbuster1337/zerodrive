use std::collections::BTreeMap;

use anyhow::{bail, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::crypto_stream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub schema: String,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default)]
    pub drives: BTreeMap<String, Drive>,
    pub prev_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    pub created_at: i64,
    #[serde(default)]
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub hash: String,
    pub size: u64,
    #[serde(default)]
    pub providers: Vec<String>,
    pub added_at: i64,
}

impl Manifest {
    pub fn new() -> Self {
        let now = Utc::now().timestamp();
        Self {
            version: 1,
            schema: "zerodrive-manifest".to_string(),
            created_at: now,
            updated_at: now,
            drives: BTreeMap::new(),
            prev_event_id: None,
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        if manifest.schema != "zerodrive-manifest" {
            anyhow::bail!("unknown manifest schema: {}", manifest.schema);
        }
        if manifest.version != 1 {
            anyhow::bail!("unsupported manifest version: {}", manifest.version);
        }
        Ok(manifest)
    }

    pub async fn encrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let json = self.to_json()?;
        let mut ciphertext = Vec::with_capacity(json.len() + 64);
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(json));
        let mut writer = tokio::io::BufWriter::new(&mut ciphertext);
        crypto_stream::encrypt_stream(reader, &mut writer, key).await?;
        Ok(ciphertext)
    }

    pub async fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Self> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(ciphertext));
        let mut writer = tokio::io::BufWriter::new(&mut plaintext);
        crypto_stream::decrypt_stream(reader, &mut writer, key).await?;
        drop(writer);
        Self::from_json(&plaintext)
    }

    /// Get a drive by name, returns error if not found.
    pub fn get_drive(&self, name: &str) -> Result<&Drive> {
        self.drives
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("drive '{name}' not found"))
    }

    /// Get a mutable drive by name.
    pub fn get_drive_mut(&mut self, name: &str) -> Result<&mut Drive> {
        self.drives
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("drive '{name}' not found"))
    }

    /// Create a new drive.
    pub fn create_drive(&mut self, name: &str) -> &mut Drive {
        let now = Utc::now().timestamp();
        self.drives.entry(name.to_string()).or_insert(Drive {
            created_at: now,
            files: Vec::new(),
        });
        self.updated_at = now;
        self.drives.get_mut(name).unwrap()
    }

    /// Add a file entry to a drive (node_addr is the full NodeAddr serialization).
    pub fn add_file(
        &mut self,
        drive_name: &str,
        name: &str,
        hash: &str,
        size: u64,
        node_addr: &str,
    ) -> Result<()> {
        let drive = self.get_drive_mut(drive_name)?;
        drive.files.retain(|f| f.name != name);
        drive.files.push(FileEntry {
            name: name.to_string(),
            hash: hash.to_string(),
            size,
            providers: vec![node_addr.to_string()],
            added_at: Utc::now().timestamp(),
        });
        self.updated_at = Utc::now().timestamp();
        Ok(())
    }

    /// Remove a file from a drive.
    pub fn remove_file(&mut self, drive_name: &str, name: &str) -> Result<()> {
        let drive = self.get_drive_mut(drive_name)?;
        let len_before = drive.files.len();
        drive.files.retain(|f| f.name != name);
        if drive.files.len() == len_before {
            bail!("file '{name}' not found in drive '{drive_name}'");
        }
        self.updated_at = Utc::now().timestamp();
        Ok(())
    }

    /// List drives or files in a drive.
    pub fn list_drives(&self) -> Vec<&str> {
        self.drives.keys().map(|s| s.as_str()).collect()
    }

    pub fn list_files(&self, drive_name: &str) -> Result<&Vec<FileEntry>> {
        Ok(&self.get_drive(drive_name)?.files)
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}
