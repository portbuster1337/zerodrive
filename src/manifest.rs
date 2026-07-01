use std::collections::BTreeMap;

use anyhow::{bail, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use zeroize::Zeroize;
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
        let mut json = self.to_json()?;
        let mut ciphertext = Vec::with_capacity(json.len() + 64);
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(&json));
        let mut writer = tokio::io::BufWriter::new(&mut ciphertext);
        crypto_stream::encrypt_stream(reader, &mut writer, key).await?;
        json.zeroize();
        Ok(ciphertext)
    }

    pub async fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Self> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(ciphertext));
        let mut writer = tokio::io::BufWriter::new(&mut plaintext);
        crypto_stream::decrypt_stream(reader, &mut writer, key).await?;
        drop(writer);
        let result = Self::from_json(&plaintext);
        plaintext.zeroize();
        result
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
    pub fn create_drive(&mut self, name: &str) -> Result<&mut Drive> {
        if self.drives.contains_key(name) {
            anyhow::bail!("drive '{name}' already exists");
        }
        let now = Utc::now().timestamp();
        self.drives.insert(name.to_string(), Drive {
            created_at: now,
            files: Vec::new(),
        });
        self.updated_at = now;
        Ok(self.drives.get_mut(name).unwrap())
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
        if drive.files.iter().any(|f| f.name == name) {
            anyhow::bail!("file '{name}' already exists in drive '{drive_name}'");
        }
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

    /// Count how many file entries across all drives reference a given hash.
    pub fn hash_refcount(&self, hash: &str) -> usize {
        self.drives
            .values()
            .flat_map(|d| &d.files)
            .filter(|f| f.hash == hash)
            .count()
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

#[cfg(test)]
mod manifest_tests {
    use super::*;

    #[test]
    fn test_manifest_crud_and_duplicates() {
        let mut m = Manifest::new();
        m.create_drive("docs").unwrap();

        m.add_file("docs", "resume.pdf", "blake3:hash1", 1024, "nodeaddr1").unwrap();

        // Duplicate file name should fail
        assert!(m.add_file("docs", "resume.pdf", "blake3:hash2", 2048, "nodeaddr1").is_err());

        // Duplicate drive name should fail
        assert!(m.create_drive("docs").is_err());

        // Verify hash refcount (hash1 is referenced once)
        assert_eq!(m.hash_refcount("blake3:hash1"), 1);

        // Add same hash to another drive
        m.create_drive("backup").unwrap();
        m.add_file("backup", "resume_backup.pdf", "blake3:hash1", 1024, "nodeaddr2").unwrap();
        assert_eq!(m.hash_refcount("blake3:hash1"), 2);

        // Remove from one drive, refcount should drop
        m.remove_file("docs", "resume.pdf").unwrap();
        assert_eq!(m.hash_refcount("blake3:hash1"), 1);
    }

    #[tokio::test]
    async fn test_manifest_encryption_wrong_key_fails() {
        let m = Manifest::new();
        let key1 = [0xAB; 32];
        let key2 = [0xCD; 32];

        let ct = m.encrypt(&key1).await.unwrap();

        // Decrypting with the wrong key should fail
        let result = Manifest::decrypt(&ct, &key2).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_schema_validation() {
        let bad_json = r#"{"version": 99, "schema": "wrong-schema", "created_at": 0, "updated_at": 0}"#;
        let result = Manifest::from_json(bad_json.as_bytes());
        assert!(result.is_err(), "wrong schema should fail validation");
        assert!(result.unwrap_err().to_string().contains("unknown manifest schema"),
            "error should mention unknown schema");
    }
}
