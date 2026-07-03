use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::io::Read;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use anyhow::{Context, Result};
use fs2::FileExt;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::blob_store::{BlobStore, ProgressTx};
use crate::derive::DerivedKeys;
use crate::manifest::{Drive, FileEntry, Manifest, Shard, ShardManifestRef};
use crate::pointer::ManifestPointer;

#[cfg(unix)]
pub type IpcStream = tokio::net::UnixStream;
#[cfg(unix)]
pub type IpcListener = tokio::net::UnixListener;

#[cfg(windows)]
pub type IpcStream = tokio::net::TcpStream;
#[cfg(windows)]
pub type IpcListener = tokio::net::TcpListener;

pub fn ipc_endpoint() -> PathBuf {
    let base = zerodrive_dir();
    #[cfg(unix)]
    { base.join("daemon.sock") }
    #[cfg(windows)]
    { base.join("daemon.port") }
}

fn zerodrive_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("zerodrive")
}

async fn bind_ipc_listener() -> Result<(IpcListener, String)> {
    #[cfg(unix)]
    {
        let path = ipc_endpoint();
        let _ = tokio::fs::remove_file(&path).await;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let listener = IpcListener::bind(&path).context("binding IPC socket")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .context("setting socket permissions")?;
        Ok((listener, path.to_string_lossy().to_string()))
    }
    #[cfg(windows)]
    {
        let listener = IpcListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let path = ipc_endpoint();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, port.to_string()).await?;
        Ok((listener, format!("127.0.0.1:{port}")))
    }
}

async fn connect_ipc() -> Result<IpcStream> {
    let endpoint = ipc_endpoint();
    let stream = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            #[cfg(unix)]
            {
                match IpcStream::connect(&endpoint).await {
                    Ok(s) => return Ok(s),
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            #[cfg(windows)]
            {
                let port_str = match tokio::fs::read_to_string(&endpoint).await {
                    Ok(p) => p,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let port: u16 = match port_str.trim().parse() {
                    Ok(p) => p,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                match IpcStream::connect(("127.0.0.1", port)).await {
                    Ok(s) => return Ok(s),
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out connecting to daemon"))?
    .map_err(|e: std::io::Error| anyhow::anyhow!("connecting to daemon: {e}"))?;
    Ok(stream)
}

pub fn sanitize_filename(name: &str) -> String {
    let name = name.rsplit('/').next().unwrap_or(name)
        .rsplit('\\').next().unwrap_or(name)
        .trim_start_matches('.');
    let fallback = || format!("file_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    if name.is_empty() || name == "." || name == ".." {
        return fallback();
    }
    let name: String = name.chars().filter(|&c| c != '\0').collect();
    if name.is_empty() || name == "." || name == ".." {
        return fallback();
    }
    if cfg!(windows) {
        let stem = name.split('.').next().unwrap_or(&name).to_lowercase();
        match stem.as_str() {
            "con" | "prn" | "aux" | "nul"
            | "com1" | "com2" | "com3" | "com4" | "com5" | "com6" | "com7" | "com8" | "com9"
            | "lpt1" | "lpt2" | "lpt3" | "lpt4" | "lpt5" | "lpt6" | "lpt7" | "lpt8" | "lpt9" => {
                return format!("_{name}");
            }
            _ => {}
        }
    }
    name.to_string()
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_filename;

    #[test]
    fn test_path_traversal_prevention() {
        assert_eq!(sanitize_filename("../../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("..\\..\\windows\\system32"), "system32");
        assert_eq!(sanitize_filename("valid_name.txt"), "valid_name.txt");
    }

    #[test]
    fn test_dot_files() {
        assert_eq!(sanitize_filename(".hidden_file"), "hidden_file");
        assert!(sanitize_filename("..").starts_with("file_"));
        assert!(sanitize_filename(".").starts_with("file_"));
    }

    #[test]
    fn test_empty_and_nul_bytes() {
        assert!(sanitize_filename("").starts_with("file_"));
        assert!(sanitize_filename("\0\0\0").starts_with("file_"));
        assert_eq!(sanitize_filename("hello\0world"), "helloworld");
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_reserved_names() {
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("PRN.txt"), "_PRN.txt");
        assert_eq!(sanitize_filename("aux"), "_aux");
    }
}

pub struct DaemonState {
    pub keys: DerivedKeys,
    pub pointer: Option<ManifestPointer>,
    pub manifests: BTreeMap<String, Manifest>,
    pub relays: Vec<String>,
    pub shutdown: CancellationToken,
    pub last_sync: Instant,
    pub pending_changes: bool,
}

impl DaemonState {
    /// Reconnect the Nostr pointer (creates a fresh client connection).
    async fn reconnect_pointer(&mut self) {
        info!("Reconnecting Nostr pointer...");
        let relays: Vec<String> = self.relays.iter().map(|r| {
            if r.starts_with("wss://") || r.starts_with("ws://") || r.starts_with("wss:/") {
                r.clone()
            } else {
                // Web UI config includes the "wss:" prefix already
                format!("wss://{r}")
            }
        }).collect();
        let new_ptr = crate::pointer::ManifestPointer::new(
            &self.keys.nostr_secret_key,
            &relays,
        ).await.ok();
        if new_ptr.is_some() {
            self.pointer = new_ptr;
            info!("Nostr pointer reconnected.");
        } else {
            warn!("Failed to reconnect Nostr pointer.");
        }
    }

    /// Publish a specific manifest by d-tag, with retry and pointer reconnection.
    pub async fn publish_manifest(&mut self, d_tag: &str) -> Result<String> {
        let mk = self.keys.manifest_key;
        let mut m = match self.manifests.get(d_tag).cloned() {
            Some(m) => m,
            None => return Ok("offline".into()),
        };
        let mut last_err = Ok("offline".into());
        for attempt in 0..2 {
            let ptr = match self.pointer.clone() {
                Some(p) => p,
                None => { self.reconnect_pointer().await; continue; }
            };
            match ptr.publish_and_update_with_tag(&mut m, &mk, d_tag).await {
                Ok(id) => { last_err = Ok(id); break; }
                Err(e) => {
                    warn!("publish_manifest attempt {}/2 failed: {e}", attempt + 1);
                    last_err = Err(e);
                    self.reconnect_pointer().await;
                }
            }
        }
        if last_err.is_ok() {
            self.manifests.insert(d_tag.to_string(), m);
        }
        if last_err.is_ok() {
            self.pending_changes = false;
            self.last_sync = Instant::now();
        }
        last_err
    }

    /// Find which manifest contains a drive.
    pub fn find_manifest_for_drive(&self, drive_name: &str) -> Option<String> {
        for (d_tag, manifest) in &self.manifests {
            if manifest.drives.contains_key(drive_name) {
                return Some(d_tag.clone());
            }
        }
        None
    }

    /// Get a drive from whichever manifest contains it.
    pub fn get_drive(&self, name: &str) -> Result<&Drive> {
        for manifest in self.manifests.values() {
            if let Ok(drive) = manifest.get_drive(name) {
                return Ok(drive);
            }
        }
        anyhow::bail!("drive '{}' not found", name)
    }

    /// Merge all drives from all manifests (for listing).
    pub fn list_all_drives(&self) -> Vec<&str> {
        let mut drives: Vec<&str> = self.manifests.values()
            .flat_map(|m| m.drives.keys().map(|s| s.as_str()))
            .collect();
        drives.sort();
        drives.dedup();
        drives
    }

    /// List files in a drive across all manifests (aggregated).
    pub fn list_files_in_drive(&self, drive_name: &str) -> Result<Vec<FileEntry>> {
        let mut all_files: Vec<FileEntry> = Vec::new();
        let mut found = false;
        for manifest in self.manifests.values() {
            if manifest.drives.contains_key(drive_name) {
                found = true;
                if let Ok(files) = manifest.list_files(drive_name) {
                    all_files.extend(files.iter().cloned());
                }
            }
        }
        if !found {
            anyhow::bail!("drive '{}' not found", drive_name);
        }
        all_files.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all_files)
    }

    /// Create a drive in whichever manifest has room, or create a new manifest.
    pub async fn create_drive_in_manifest(&mut self, name: &str) -> Result<()> {
        // Try existing manifests first
        for manifest in self.manifests.values_mut() {
            if !manifest.drives.contains_key(name) {
                if let Ok(json) = serde_json::to_vec(manifest) {
                    if json.len() < 32 * 1024 {
                        manifest.create_drive(name)?;
                        return Ok(());
                    }
                }
            }
        }
        // All manifests full or contain this drive — create a new one
        let new_tag = crate::pointer::next_manifest_tag(&self.manifests);
        let mut new_manifest = Manifest::new();
        new_manifest.create_drive(name)?;
        self.manifests.insert(new_tag, new_manifest);
        Ok(())
    }
}

pub async fn run_daemon(
    keys: DerivedKeys,
    relays: Vec<String>,
) -> Result<()> {
    let pointer = ManifestPointer::new(&keys.nostr_secret_key, &relays).await
        .map_err(|e| { warn!("Nostr init failed (will retry): {e}"); e })
        .ok();

    let manifests = if let Some(ref p) = pointer {
        let mut result: Option<BTreeMap<String, Manifest>> = None;
        for attempt in 0..5 {
            match p.resolve_all(&keys.manifest_key).await {
                Ok(m) if m.len() > 1 || m.contains_key(crate::pointer::D_TAG_PREFIX) => {
                    result = Some(m); break;
                }
                Ok(m) => { result = Some(m); break; }
                Err(e) => {
                    warn!("Manifest resolve attempt {}/5 failed: {e}", attempt + 1);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
        result.unwrap_or_default()
    } else {
        BTreeMap::new()
    };

    let shutdown = CancellationToken::new();
    let state = Arc::new(Mutex::new(DaemonState {
        keys,
        pointer,
        manifests,
        relays,
        shutdown: shutdown.clone(),
        last_sync: Instant::now(),
        pending_changes: false,
    }));

    // Periodic background sync every 30 seconds so new manifests are auto-discovered
    {
        let bg_state = state.clone();
        let bg_shutdown = shutdown.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        sync_manifest_no_lock(&bg_state).await;
                    }
                    _ = bg_shutdown.cancelled() => break,
                }
            }
        });
    }

    let (listener, endpoint_str) = bind_ipc_listener().await?;
    info!("Daemon listening on {endpoint_str}");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("Daemon shutting down gracefully");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_ipc(stream, state).await {
                                error!("IPC handler: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("IPC accept: {e}");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }
    }

    info!("Daemon exited");
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct IpcCommand {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct IpcResponse {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<serde_json::Value>,
}

pub async fn execute_command(
    state: &Arc<Mutex<DaemonState>>,
    method: &str,
    params: serde_json::Value,
) -> IpcResponse {
    let cmd = IpcCommand {
        id: 0,
        method: method.to_string(),
        params,
    };
    let (tx, _rx) = mpsc::unbounded_channel();
    process_command(cmd, state, tx).await
}

async fn handle_ipc(
    stream: IpcStream,
    state: Arc<Mutex<DaemonState>>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, writer) = stream.into_split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let mut reader = BufReader::new(reader);
    const MAX_LINE: usize = 64 * 1024;
    let mut line = String::new();

    loop {
        line.clear();
        use tokio::io::AsyncReadExt;
        let mut limited = (&mut reader).take(MAX_LINE as u64 + 1);
        let n = limited.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        if line.len() > MAX_LINE || !line.ends_with('\n') {
            let resp = IpcResponse {
                id: 0,
                result: None,
                error: Some("line too long".into()), progress: None,
            };
            let mut json = serde_json::to_vec(&resp)?;
            json.push(b'\n');
            let mut w = writer.lock().await;
            let _ = w.write_all(&json).await;
            break;
        }

        let cmd: IpcCommand = match serde_json::from_str(&line) {
            Ok(c) => c,
            Err(e) => {
                let resp = IpcResponse {
                    id: 0,
                    result: None,
                    error: Some(format!("parse error: {e}")), progress: None,
                };
                let mut json = serde_json::to_vec(&resp)?;
                json.push(b'\n');
                let mut w = writer.lock().await;
                w.write_all(&json).await?;
                w.flush().await?;
                continue;
            }
        };

        let (progress_tx, progress_rx) = mpsc::unbounded_channel();

        let progress_writer = writer.clone();
        let progress_handle = tokio::spawn(async move {
            let mut rx = progress_rx;
            while let Some((current, total)) = rx.recv().await {
                let msg = serde_json::json!({"id": 0, "progress": {"current": current, "total": total}});
                if let Ok(json) = serde_json::to_vec(&msg) {
                    let mut bytes = json;
                    bytes.push(b'\n');
                    let mut w = progress_writer.lock().await;
                    let _ = w.write_all(&bytes).await;
                    let _ = w.flush().await;
                }
            }
        });

        let response = process_command(cmd, &state, progress_tx).await;

        let _ = progress_handle.await;

        let mut json = serde_json::to_vec(&response)?;
        json.push(b'\n');
        let mut w = writer.lock().await;
        w.write_all(&json).await?;
        w.flush().await?;
    }
    Ok(())
}

async fn process_command(
    cmd: IpcCommand,
    state: &Arc<Mutex<DaemonState>>,
    progress_tx: ProgressTx,
) -> IpcResponse {
    let id = cmd.id;

    let method = cmd.method.as_str();
    match method {
        "status" => {
            let s = state.lock().await;
            IpcResponse {
                id,
                result: Some(serde_json::json!({
                    "relays": s.relays.len(),
                })),
                error: None,
                progress: None,
            }
        }

        "stop" => {
            let s = state.lock().await;
            s.shutdown.cancel();
            IpcResponse {
                id,
                result: Some(serde_json::json!("stopping")),
                error: None,
                progress: None,
            }
        }

        "create_drive" => {
            let name = cmd.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let mut s = state.lock().await;
            if let Err(e) = s.create_drive_in_manifest(name).await {
                return IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None };
            }
            s.pending_changes = true;
            let d_tag = s.find_manifest_for_drive(name)
                .unwrap_or_else(|| crate::pointer::D_TAG_PREFIX.to_string());
            match s.publish_manifest(&d_tag).await {
                Ok(_) => IpcResponse { id, result: Some(serde_json::json!({ "ok": true })), error: None, progress: None },
                Err(e) => {
                    if let Some(m) = s.manifests.get_mut(&d_tag) {
                        m.drives.remove(name);
                    }
                    s.pending_changes = false;
                    IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None }
                }
            }
        }

        "upload" => {
            let drive = cmd.params.get("drive").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let path = cmd.params.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fname = cmd.params.get("as").and_then(|v| v.as_str()).unwrap_or(&path).to_string();
            let fname = sanitize_filename(&fname);

            let local_path = PathBuf::from(&path);
            if !local_path.exists() {
                return IpcResponse { id, result: None, error: Some("file not found".into()), progress: None };
            }
            {
                let s = state.lock().await;
                if s.get_drive(&drive).is_err() {
                    return IpcResponse { id, result: None, error: Some(format!("drive '{drive}' not found")), progress: None };
                }
            }

            let file_key = {
                let s = state.lock().await;
                s.keys.file_key
            };
            match BlobStore::upload(&local_path, &file_key, Some(progress_tx.clone())).await {
                Ok((shards, size)) => {
                    let mut s = state.lock().await;
                    let d_tag = match s.find_manifest_for_drive(&drive) {
                        Some(t) => t,
                        None => return IpcResponse { id, result: None, error: Some(format!("drive '{drive}' not found")), progress: None },
                    };

                    // Offload shard list to an external encrypted blob if serialized size exceeds ~20KB
                    let shard_manifest_ref = if serde_json::to_string(&shards)
                        .map(|j| j.len() > 4_000)
                        .unwrap_or(false)
                    {
                        let blob_data = match serde_json::to_vec(&shards) {
                            Ok(d) => d,
                            Err(e) => return IpcResponse { id, result: None, error: Some(format!("serializing shard manifest: {e}")), progress: None },
                        };
                        match BlobStore::upload_encrypted_blob(&blob_data, &file_key, &format!("{fname}.shards")).await {
                            Ok((url, priv_key)) => Some(ShardManifestRef { url, priv_key }),
                            Err(e) => return IpcResponse { id, result: None, error: Some(format!("uploading shard manifest: {e}")), progress: None },
                        }
                    } else {
                        None
                    };

                    let use_shards = if shard_manifest_ref.is_some() {
                        Vec::new()
                    } else {
                        shards.clone()
                    };

                    // Take manifest out of the map to avoid borrow issues across await points
                    let mut manifest = match s.manifests.remove(&d_tag) {
                        Some(m) => m,
                        None => return IpcResponse { id, result: None, error: Some("internal: manifest not found".into()), progress: None },
                    };
                    if let Err(e) = manifest.add_file_with_manifest(&drive, &fname, size, use_shards, shard_manifest_ref) {
                        s.manifests.insert(d_tag.clone(), manifest);
                        return IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None };
                    }
                    s.pending_changes = true;
                    s.manifests.insert(d_tag.clone(), manifest);

                    // Try to publish; if manifest too large, split drive to a new manifest
                    let result = match s.publish_manifest(&d_tag).await {
                        Ok(_) => IpcResponse {
                            id,
                            result: Some(serde_json::json!({ "size": size })),
                            error: None,
                            progress: None,
                        },
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("too large") {
                                // Split files between old and new manifests
                                const SPLIT_KEEP: usize = 140;
                                let mut manifest = match s.manifests.remove(&d_tag) {
                                    Some(m) => m,
                                    None => return IpcResponse { id, result: None, error: Some("internal: manifest not found on split".into()), progress: None },
                                };
                                let mut drive_entry = match manifest.drives.remove(&drive) {
                                    Some(d) => d,
                                    None => { s.manifests.insert(d_tag.clone(), manifest); return IpcResponse { id, result: None, error: Some("internal: drive not found on split".into()), progress: None }; }
                                };
                                // Keep first SPLIT_KEEP files in old manifest, overflow goes to new manifest
                                let overflow = if drive_entry.files.len() > SPLIT_KEEP {
                                    drive_entry.files.split_off(SPLIT_KEEP)
                                } else {
                                    drive_entry.files.split_off(drive_entry.files.len().saturating_sub(1))
                                };
                                let drive_created = drive_entry.created_at;
                                manifest.drives.insert(drive.clone(), drive_entry);
                                s.manifests.insert(d_tag.clone(), manifest);
                                let new_tag = crate::pointer::next_manifest_tag(&s.manifests);
                                let mut new_manifest = Manifest::new();
                                let new_drive = crate::manifest::Drive { created_at: drive_created, files: overflow };
                                new_manifest.drives.insert(drive.clone(), new_drive);
                                s.manifests.insert(new_tag.clone(), new_manifest);
                                // Publish old manifest first, then new one
                                match s.publish_manifest(&d_tag).await {
                                    Ok(_) => match s.publish_manifest(&new_tag).await {
                                        Ok(_) => IpcResponse {
                                            id,
                                            result: Some(serde_json::json!({ "size": size })),
                                            error: None,
                                            progress: None,
                                        },
                                        Err(e2) => {
                                            let overflow_files = s.manifests.remove(&new_tag)
                                                .and_then(|mut m| m.drives.remove(&drive))
                                                .map(|d| d.files)
                                                .unwrap_or_default();
                                            if let Some(old_m) = s.manifests.get_mut(&d_tag) {
                                                if let Some(old_drive) = old_m.drives.get_mut(&drive) {
                                                    old_drive.files.extend(overflow_files);
                                                }
                                            }
                                            s.pending_changes = false;
                                            IpcResponse { id, result: None, error: Some(format!("{e2}")), progress: None }
                                        }
                                    },
                                    Err(e) => {
                                        let overflow_files = s.manifests.remove(&new_tag)
                                            .and_then(|mut m| m.drives.remove(&drive))
                                            .map(|d| d.files)
                                            .unwrap_or_default();
                                        if let Some(old_m) = s.manifests.get_mut(&d_tag) {
                                            if let Some(old_drive) = old_m.drives.get_mut(&drive) {
                                                old_drive.files.extend(overflow_files);
                                            }
                                        }
                                        s.pending_changes = false;
                                        IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None }
                                    }
                                }
                            } else {
                                match s.manifests.get_mut(&d_tag) {
                                    Some(manifest) => { let _ = manifest.remove_file(&drive, &fname); }
                                    None => {}
                                }
                                s.pending_changes = false;
                                IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None }
                            }
                        }
                    };
                    result
                }
                Err(e) => IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None },
            }
        }

        "download" => {
            let drive = cmd.params.get("drive").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fname = cmd.params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let out = cmd.params.get("out").and_then(|v| v.as_str()).map(|s| PathBuf::from(s.to_string()));
            let out_path = out.unwrap_or_else(|| PathBuf::from(sanitize_filename(&fname)));

            sync_manifest_no_lock(state).await;
            let entry;
            {
                let s = state.lock().await;
                let drive_obj = match s.get_drive(&drive) {
                    Ok(d) => d,
                    Err(e) => return IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None },
                };
                entry = match drive_obj.files.iter().find(|f| f.name == fname) {
                    Some(f) => f.clone(),
                    None => return IpcResponse {
                        id, result: None,
                        error: Some(format!("file '{fname}' not found in drive '{drive}'")),
                        progress: None,
                    },
                };
            }

            let file_key = state.lock().await.keys.file_key;
            let shards = if let Some(sm) = &entry.shard_manifest {
                let blob = BlobStore::download_encrypted_blob(&sm.url, &sm.priv_key, &file_key).await;
                match blob {
                    Ok(data) => match serde_json::from_slice::<Vec<Shard>>(&data) {
                        Ok(s) => s,
                        Err(e) => return IpcResponse {
                            id, result: None,
                            error: Some(format!("parsing shard manifest: {e}")),
                            progress: None,
                        },
                    },
                    Err(e) => return IpcResponse {
                        id, result: None,
                        error: Some(format!("failed to download shard manifest: {e}")),
                        progress: None,
                    },
                }
            } else {
                entry.shards.clone()
            };
            match BlobStore::download(&shards, &out_path, &file_key, entry.size, Some(progress_tx.clone())).await {
                Ok(size) => IpcResponse {
                    id,
                    result: Some(serde_json::json!({ "path": out_path.to_string_lossy(), "size": size })),
                    error: None,
                    progress: None,
                },
                Err(e) => {
                    let _ = tokio::fs::remove_file(&out_path).await;
                    IpcResponse { id, result: None, error: Some(format!("{e:#}")), progress: None }
                }
            }
        }

        "list" => {
            let drive_name = cmd.params.get("drive").and_then(|v| v.as_str());
            sync_manifest_no_lock(state).await;
            let s = state.lock().await;
            match drive_name {
                Some("") | None => {
                    let drives = s.list_all_drives();
                    let drive_details: Vec<serde_json::Value> = drives.iter().map(|name| {
                        let file_count = s.list_files_in_drive(name).map(|f| f.len()).unwrap_or(0);
                        json!({ "name": name, "file_count": file_count })
                    }).collect();
                    IpcResponse { id, result: Some(serde_json::json!({ "drives": drives, "drive_details": drive_details })), error: None, progress: None }
                }
                Some(name) => match s.list_files_in_drive(name) {
                    Ok(files) => IpcResponse {
                        id,
                        result: Some(serde_json::json!({ "drive": name, "files": files })),
                        error: None,
                        progress: None,
                    },
                    Err(e) => IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None },
                },
            }
        }

        "delete" => {
            let drive = cmd.params.get("drive").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fname = cmd.params.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let mut s = state.lock().await;

            let d_tag = match s.find_manifest_for_drive(&drive) {
                Some(t) => t,
                None => return IpcResponse { id, result: None, error: Some(format!("drive '{drive}' not found")), progress: None },
            };

            let backup_entry: Option<FileEntry> = if let Some(ref name) = fname {
                s.get_drive(&drive).ok()
                    .and_then(|d| d.files.iter().find(|f| f.name == *name))
                    .cloned()
            } else {
                None
            };
            let backup_drive: Option<Drive> = if fname.is_none() {
                s.manifests.get(&d_tag)
                    .and_then(|m| m.drives.get(&drive).cloned())
            } else {
                None
            };

            let manifest = s.manifests.get_mut(&d_tag).unwrap();
            if let Some(ref name) = fname {
                if manifest.get_drive(&drive).ok()
                    .and_then(|d| d.files.iter().find(|f| f.name == *name))
                    .is_none()
                {
                    return IpcResponse { id, result: None, error: Some(format!("file '{name}' not found in drive '{drive}'")), progress: None };
                }
                if let Err(e) = manifest.remove_file(&drive, name) {
                    return IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None };
                }
                s.pending_changes = true;
            } else {
                manifest.drives.remove(&drive);
                s.pending_changes = true;
            }

            match s.publish_manifest(&d_tag).await {
                Ok(_) => {
                    IpcResponse { id, result: Some(serde_json::json!({ "ok": true })), error: None, progress: None }
                }
                Err(e) => {
                    if let Some(entry) = backup_entry {
                        let _ = s.manifests.get_mut(&d_tag)
                            .unwrap()
                            .add_file_with_manifest(&drive, &entry.name, entry.size, entry.shards, entry.shard_manifest);
                    } else if let Some(orig_drive) = backup_drive {
                        s.manifests.get_mut(&d_tag).unwrap().drives.insert(drive.clone(), orig_drive);
                    }
                    s.pending_changes = true;
                    IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None }
                }
            }
        }

        _ => IpcResponse {
            id,
            result: None,
            error: Some(format!("unknown method: {method}")),
            progress: None,
        },
    }
}

pub async fn sync_manifest_no_lock(state: &Arc<Mutex<DaemonState>>) {
    let pointer_data = {
        let mut s = state.lock().await;
        let is_empty = s.manifests.values().all(|m| m.drives.is_empty());
        // Allow sync if empty, or if >10s passed
        if !is_empty && s.last_sync.elapsed() < Duration::from_secs(10) { None }
        else if s.pending_changes { None }
        else {
            let mk = s.keys.manifest_key;
            match s.pointer.clone() {
                Some(p) => {
                    s.last_sync = Instant::now();
                    Some((p, mk))
                }
                None => None,
            }
        }
    };
    if let Some((pointer, mk)) = pointer_data {
        let manifests = tokio::time::timeout(Duration::from_secs(10), pointer.resolve_all(&mk)).await;
        if let Ok(Ok(remote_manifests)) = manifests {
            let mut s = state.lock().await;
            if !s.pending_changes {
                // Merge remote into local: only update if remote is newer
                for (d_tag, remote_m) in remote_manifests {
                    match s.manifests.entry(d_tag) {
                        std::collections::btree_map::Entry::Occupied(mut entry) => {
                            if remote_m.updated_at > entry.get().updated_at {
                                entry.insert(remote_m);
                            }
                        }
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(remote_m);
                        }
                    }
                }
            }
        }
    }
}

fn daemon_lock_path() -> PathBuf {
    zerodrive_dir().join("daemon.lock")
}

pub struct DaemonLock {
    file: Option<std::fs::File>,
    path: PathBuf,
    remove_on_drop: bool,
}

impl DaemonLock {
    pub fn acquire() -> Result<Self> {
        let path = daemon_lock_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .context("creating daemon lock file")?;
        file.try_lock_exclusive()
            .with_context(|| {
                format!("another daemon is running (lock: {})", path.display())
            })?;
        Ok(Self { file: Some(file), path, remove_on_drop: false })
    }

    pub fn adopt(path: PathBuf) -> Self {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .ok();
        if let Some(ref f) = file {
            let _ = f.lock_exclusive();
        }
        Self { file, path, remove_on_drop: true }
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        let _ = self.file.take();
        if self.remove_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub fn spawn_daemon(keys: DerivedKeys, relays: Vec<String>) -> Result<()> {
    let lock = DaemonLock::acquire()?;
    let lock_path = lock.path.clone();
    let args = DaemonArgs {
        nostr_secret_key: keys.nostr_secret_key,
        manifest_key: keys.manifest_key,
        file_key: keys.file_key,
        lock_path: lock_path.to_string_lossy().to_string(),
        relays,
    };

    let mut keys_json = serde_json::to_vec(&args)?;
    let exe = std::env::current_exe()?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.args(["__daemon_internal__"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().context("spawning daemon")?;

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        if let Err(e) = stdin.write_all(&keys_json) {
            let _ = child.kill();
            anyhow::bail!("failed to write keys to daemon stdin: {e}");
        }
        if let Err(e) = stdin.flush() {
            let _ = child.kill();
            anyhow::bail!("failed to flush keys to daemon stdin: {e}");
        }
    }

    keys_json.zeroize();
    drop(lock);
    info!("Daemon spawned (PID: {})", child.id());
    Ok(())
}

pub fn read_daemon_args_from_stdin() -> Result<DaemonArgs> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).context("reading daemon args from stdin")?;
    let args: DaemonArgs = serde_json::from_str(&input)?;
    let mut bytes = input.into_bytes();
    bytes.zeroize();
    Ok(args)
}

pub async fn is_daemon_running() -> bool {
    tokio::time::timeout(Duration::from_millis(500), connect_ipc())
        .await
        .ok()
        .and_then(Result::ok)
        .is_some()
}

pub async fn send_command(
    method: &str,
    params: serde_json::Value,
    progress_bar: Option<indicatif::ProgressBar>,
) -> Result<IpcResponse> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let stream = connect_ipc().await?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let cmd = IpcCommand {
        id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        method: method.to_string(),
        params,
    };

    let mut json = serde_json::to_vec(&cmd)?;
    json.push(b'\n');
    writer.write_all(&json).await?;
    writer.flush().await?;

    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        let resp: IpcResponse = serde_json::from_str(&line)?;
        if let Some(ref p) = resp.progress {
            if let (Some(current), Some(total)) = (
                p.get("current").and_then(|v| v.as_u64()),
                p.get("total").and_then(|v| v.as_u64()),
            ) {
                if let Some(ref pb) = progress_bar {
                    pb.set_length(total);
                    pb.set_position(current);
                }
            }
            continue;
        }
        if let Some(ref pb) = progress_bar {
            pb.finish_and_clear();
        }
        return Ok(resp);
    }
}

#[derive(serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DaemonArgs {
    pub nostr_secret_key: [u8; 32],
    pub manifest_key: [u8; 32],
    pub file_key: [u8; 32],
    pub lock_path: String,
    pub relays: Vec<String>,
}
