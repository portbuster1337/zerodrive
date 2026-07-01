use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::io::Read;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use anyhow::{Context, Result};
use fs2::FileExt;
use serde_json::json;
use iroh::node::Node;
use iroh_blobs::store::mem::Store as MemStore;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::blob_store::{BlobStore, ProgressTx};
use crate::derive::DerivedKeys;
use crate::manifest::{Drive, FileEntry, Manifest};
use crate::pointer::ManifestPointer;

/// Cross-platform IPC: Unix sockets on Unix, TCP loopback on Windows.
#[cfg(unix)]
pub type IpcStream = tokio::net::UnixStream;
#[cfg(unix)]
pub type IpcListener = tokio::net::UnixListener;

#[cfg(windows)]
pub type IpcStream = tokio::net::TcpStream;
#[cfg(windows)]
pub type IpcListener = tokio::net::TcpListener;

/// Resolve the IPC endpoint (socket path on Unix, port file on Windows).
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

/// Bind the IPC listener.
async fn bind_ipc_listener() -> Result<(IpcListener, String)> {
    #[cfg(unix)]
    {
        let path = ipc_endpoint();
        let _ = tokio::fs::remove_file(&path).await;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let listener = IpcListener::bind(&path).context("binding IPC socket")?;
        // Restrict socket to owner-only access
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

/// Connect to the IPC listener (with retry).
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

/// Sanitize a filename to prevent path traversal.
pub fn sanitize_filename(name: &str) -> String {
    // Strip path components
    let name = name.rsplit('/').next().unwrap_or(name)
        .rsplit('\\').next().unwrap_or(name)
        .trim_start_matches('.');
    // Reject empty, dot, dotdot after trimming
    let fallback = || format!("file_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    if name.is_empty() || name == "." || name == ".." {
        return fallback();
    }
    // Strip NUL bytes
    let name: String = name.chars().filter(|&c| c != '\0').collect();
    if name.is_empty() || name == "." || name == ".." {
        return fallback();
    }
    // Windows reserved device names (case-insensitive)
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

/// State held by the running daemon process.
pub struct DaemonState {
    pub keys: DerivedKeys,
    pub node: Node<MemStore>,
    pub pointer: Option<ManifestPointer>,
    pub manifest: Manifest,
    pub relays: Vec<String>,
    pub node_addr_str: String,
    pub shutdown: CancellationToken,
    last_sync: Instant,
    /// True if there are local manifest changes not yet published to Nostr.
    pending_changes: bool,
}

impl DaemonState {
    pub fn node_id(&self) -> String {
        self.node.node_id().to_string()
    }

    /// Publish manifest and return event ID (avoids borrow conflicts).
    pub async fn publish_manifest(&mut self) -> Result<String> {
        let mk = self.keys.manifest_key;
        let result = if let Some(ref pointer) = self.pointer {
            pointer
                .publish_and_update(&mut self.manifest, &mk)
                .await
        } else {
            Ok("offline".into())
        };
        if result.is_ok() {
            self.pending_changes = false;
        }
        result
    }

}

/// Main daemon entry point.
pub async fn run_daemon(
    keys: DerivedKeys,
    relays: Vec<String>,
) -> Result<()> {
    // Create ephemeral iroh node (no disk writes)
    let iroh_secret = iroh::base::key::SecretKey::from_bytes(&keys.iroh_secret_key_bytes);
    let node = Node::memory()
        .secret_key(iroh_secret)
        .spawn()
        .await?;

    let node_id = node.node_id().to_string();
    let node_addr = node.client().net().node_addr().await?;
    let node_addr_str = serde_json::to_string(&node_addr)?;
    info!("Daemon NodeID: {node_id}");

    // Connect Nostr, resolve or create manifest
    let pointer = ManifestPointer::new(&keys.nostr_secret_key, &relays).await
        .map_err(|e| { warn!("Nostr init failed (will retry): {e}"); e })
        .ok();
    let mut manifest = if let Some(ref p) = pointer {
        // Retry resolve a few times in case relays are slow or not yet connected
        let mut result = None;
        for attempt in 0..5 {
            match p.resolve(&keys.manifest_key).await {
                Ok(Some(m)) => { result = Some(m); break; }
                Ok(None) => {
                    warn!("Manifest resolve attempt {}/5: no manifest returned (relays may not be ready yet)", attempt + 1);
                    if attempt < 4 {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
                Err(e) => {
                    warn!("Manifest resolve attempt {}/5 failed: {e}", attempt + 1);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
        result.unwrap_or_else(Manifest::new)
    } else {
        Manifest::new()
    };

    // Register as provider for any blobs we hold
    for drive in manifest.drives.values_mut() {
        for file in drive.files.iter_mut() {
            if BlobStore::has_blob(&node, &file.hash).await.unwrap_or(false)
                && !file.providers.iter().any(|p| p == &node_addr_str)
            {
                file.providers.push(node_addr_str.clone());
            }
        }
    }
    if let Some(ref p) = pointer {
        if let Err(e) = p.publish_and_update(&mut manifest, &keys.manifest_key).await {
            warn!("Initial manifest publish failed: {e}");
        }
    }

    let shutdown = CancellationToken::new();
    let state = Arc::new(Mutex::new(DaemonState {
        keys,
        node,
        pointer,
        manifest,
        relays,
        node_addr_str,
        shutdown: shutdown.clone(),
        last_sync: Instant::now(),
        pending_changes: false,
    }));

    // Listen on IPC socket / TCP port
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

    // Cleanup: shutdown the iroh node
    let node = state.lock().await.node.clone();
    node.shutdown().await.ok();
    info!("Daemon exited");
    Ok(())
}

// ── IPC Protocol ──────────────────────────────────────────────────────

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
        // Bound the read to prevent OOM on malicious input
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

        // Spawn a task to forward progress messages to the client concurrently
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

        // Wait for the progress task to finish draining (channel closes when all senders drop)
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
                    "node_id": s.node_id(),
                    "num_relays": s.relays.len(),
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
            if let Err(e) = s.manifest.create_drive(name) {
                return IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None };
            }
            s.pending_changes = true;
            match s.publish_manifest().await {
                Ok(_) => IpcResponse { id, result: Some(serde_json::json!({ "ok": true })), error: None, progress: None },
                Err(e) => {
                    s.manifest.drives.remove(name);
                    s.pending_changes = false;
                    IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None }
                }
            }
        }

        "upload" => {
            let drive = cmd.params.get("drive").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let path = cmd.params.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fname = cmd.params.get("as").and_then(|v| v.as_str()).unwrap_or(&path).to_string();
            // Sanitize the filename stored in the manifest
            let fname = sanitize_filename(&fname);

            // Validate inputs before doing work
            let local_path = PathBuf::from(&path);
            if !local_path.exists() {
                return IpcResponse { id, result: None, error: Some("file not found".into()), progress: None };
            }
            {
                let s = state.lock().await;
                if s.manifest.get_drive(&drive).is_err() {
                    return IpcResponse { id, result: None, error: Some(format!("drive '{drive}' not found")), progress: None };
                }
            }

            // Clone what we need and release the lock before the long-running upload
            let (node, file_key, node_addr_str) = {
                let s = state.lock().await;
                (s.node.clone(), s.keys.file_key, s.node_addr_str.clone())
            };
            match BlobStore::upload(&node, &local_path, &file_key, Some(progress_tx.clone())).await {
                Ok((hash, size)) => {
            let mut s = state.lock().await;

                    if let Err(e) = s.manifest.add_file(&drive, &fname, &hash, size, &node_addr_str) {
                        return IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None };
                    }
                    s.pending_changes = true;
                    match s.publish_manifest().await {
                        Ok(_) => IpcResponse {
                            id,
                            result: Some(serde_json::json!({ "hash": hash, "size": size })),
                            error: None,
                            progress: None,
                        },
                        Err(e) => {
                            let _ = s.manifest.remove_file(&drive, &fname);
                            s.pending_changes = false;
                            IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None }
                        }
                    }
                }
                Err(e) => IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None },
            }
        }

        "download" => {
            let drive = cmd.params.get("drive").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fname = cmd.params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let out = cmd.params.get("out").and_then(|v| v.as_str()).map(|s| PathBuf::from(s.to_string()));
            let out_path = out.unwrap_or_else(|| PathBuf::from(sanitize_filename(&fname)));

            // Sync manifest without holding the lock (network I/O)
            sync_manifest_no_lock(state).await;
            let entry;
            let has_local;
            let hash_str;
            let file_size;
            let providers;
            {
                let s = state.lock().await;
                let drive_obj = match s.manifest.get_drive(&drive) {
                    Ok(d) => d,
                    Err(e) => return IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None },
                };
                let found = match drive_obj.files.iter().find(|f| f.name == fname) {
                    Some(f) => f.clone(),
                    None => return IpcResponse {
                        id, result: None,
                        error: Some(format!("file '{fname}' not found in drive '{drive}'")),
                        progress: None,
                    },
                };
                entry = found;
                has_local = BlobStore::has_blob(&s.node, &entry.hash).await.unwrap_or(false);
                hash_str = entry.hash.clone();
                file_size = entry.size;
                providers = entry.providers.clone();
            }

            if !has_local {
                if let Err(e) = fetch_from_providers(state, &hash_str, &providers).await {
                    return IpcResponse { id, result: None, error: Some(format!("fetch failed: {e}")), progress: None };
                }
            }

            let (node, file_key) = {
                let s = state.lock().await;
                (s.node.clone(), s.keys.file_key)
            }; // lock dropped before download
            match BlobStore::download(&node, &hash_str, &out_path, &file_key, file_size, Some(progress_tx.clone())).await {
                Ok(size) => IpcResponse {
                    id,
                    result: Some(serde_json::json!({ "path": out_path.to_string_lossy(), "size": size })),
                    error: None,
                    progress: None,
                },
                Err(e) => {
                    let _ = tokio::fs::remove_file(&out_path).await;
                    IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None }
                }
            }
        }

        "list" => {
            let drive_name = cmd.params.get("drive").and_then(|v| v.as_str());
            // Sync manifest without holding the state lock (network I/O)
            sync_manifest_no_lock(state).await;
            let s = state.lock().await;
            match drive_name {
                Some("") | None => {
                    let drives = s.manifest.list_drives();
                    let drive_details: Vec<serde_json::Value> = drives.iter().map(|name| {
                        let file_count = s.manifest.list_files(name).map(|f| f.len()).unwrap_or(0);
                        json!({ "name": name, "file_count": file_count })
                    }).collect();
                    IpcResponse { id, result: Some(serde_json::json!({ "drives": drives, "drive_details": drive_details })), error: None, progress: None }
                }
                Some(name) => match s.manifest.list_files(name) {
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
            let purge = cmd.params.get("purge").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut s = state.lock().await;

            // Collect hashes to purge (defer actual deletion until after successful publish)
            let hashes_to_purge: Vec<String> = if let Some(ref name) = fname {
                if purge {
                    s.manifest.get_drive(&drive).ok()
                        .and_then(|d| d.files.iter().find(|f| f.name == *name))
                        .map(|f| f.hash.clone())
                        .into_iter().collect()
                } else {
                    Vec::new()
                }
            } else {
                if purge {
                    s.manifest.drives.get(&drive)
                        .map(|d| d.files.iter().map(|f| f.hash.clone()).collect())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            };

            // Save backup for potential revert
            let backup_entry: Option<FileEntry> = if let Some(ref name) = fname {
                s.manifest.get_drive(&drive).ok()
                    .and_then(|d| d.files.iter().find(|f| f.name == *name))
                    .cloned()
            } else {
                None
            };
            let backup_drive: Option<Drive> = if fname.is_none() {
                s.manifest.drives.get(&drive).cloned()
            } else {
                None
            };

            if let Some(ref name) = fname {
                if s.manifest.get_drive(&drive).ok()
                    .and_then(|d| d.files.iter().find(|f| f.name == *name))
                    .is_none()
                {
                    return IpcResponse { id, result: None, error: Some(format!("file '{name}' not found in drive '{drive}'")), progress: None };
                }
                if let Err(e) = s.manifest.remove_file(&drive, name) {
                    return IpcResponse { id, result: None, error: Some(format!("{e}")), progress: None };
                }
                s.pending_changes = true;
            } else {
                if s.manifest.drives.get(&drive).is_none() {
                    return IpcResponse { id, result: None, error: Some(format!("drive '{drive}' not found")), progress: None };
                }
                s.manifest.drives.remove(&drive);
                s.pending_changes = true;
            }

            match s.publish_manifest().await {
                Ok(_) => {
                    // Purge blobs AFTER successful publish
                    if purge {
                        for hash in &hashes_to_purge {
                            let refcount = s.manifest.hash_refcount(hash);
                            if refcount == 0 {
                                let hash_str = hash.strip_prefix("blake3:").unwrap_or(hash);
                                if let Ok(h) = hash_str.parse::<iroh_blobs::Hash>() {
                                    let _ = s.node.client().blobs().delete_blob(h).await;
                                }
                            }
                        }
                    }
                    IpcResponse { id, result: Some(serde_json::json!({ "ok": true })), error: None, progress: None }
                }
                Err(e) => {
                    // Revert deletion using current daemon address as provider
                    if let Some(entry) = backup_entry {
                        let node_addr = s.node_addr_str.clone();
                        let _ = s.manifest.add_file(&drive, &entry.name, &entry.hash, entry.size, &node_addr);
                    } else if let Some(orig_drive) = backup_drive {
                        s.manifest.drives.insert(drive.clone(), orig_drive);
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

/// Sync the manifest from Nostr without holding the state lock during network I/O.
/// Clones pointer and key, drops the lock, does resolve, re-acquires to update.
async fn sync_manifest_no_lock(state: &Arc<Mutex<DaemonState>>) {
    let pointer_data = {
        let mut s = state.lock().await;
        if s.last_sync.elapsed() < Duration::from_secs(10) { None }
        else if s.pending_changes { None }
        else {
            // Update last_sync before network to prevent concurrent syncs
            s.last_sync = Instant::now();
            let mk = s.keys.manifest_key;
            s.pointer.clone().map(|p| (p, mk))
        }
    };
    if let Some((pointer, mk)) = pointer_data {
        // Network call without the lock
        let manifest = tokio::time::timeout(Duration::from_secs(3), pointer.resolve(&mk)).await;
        if let Ok(Ok(Some(m))) = manifest {
            let mut s = state.lock().await;
            // Only update if no local changes happened while we were fetching
            if !s.pending_changes {
                s.manifest = m;
            }
        }
    }
}

/// Try fetching a blob from known providers (providers contains serialized NodeAddr strings).
async fn fetch_from_providers(
    state: &Arc<Mutex<DaemonState>>,
    hash_str: &str,
    providers: &[String],
) -> Result<()> {
    let hash_str = hash_str.strip_prefix("blake3:").unwrap_or(hash_str);
    let hash: iroh_blobs::Hash = hash_str.parse()?;

    let node = {
        let s = state.lock().await;
        s.node.clone()
    }; // lock dropped

    for node_addr_str in providers {
        match BlobStore::fetch_from_peer(&node, &hash, node_addr_str).await {
            Ok(_) => {
                info!("Fetched blob from {node_addr_str}");
                return Ok(());
            }
            Err(e) => {
                warn!("Failed to fetch from {node_addr_str}: {e}");
                continue;
            }
        }
    }

    anyhow::bail!("could not fetch blob from any provider")
}

// ── Daemon Lifecycle ──────────────────────────────────────────────────

fn daemon_lock_path() -> PathBuf {
    zerodrive_dir().join("daemon.lock")
}

/// A file lock that prevents concurrent daemon spawns AND signals that
/// the daemon is running. The daemon itself holds this lock for its lifetime.
/// On drop (daemon exit), the lock file is removed.
pub struct DaemonLock {
    file: Option<std::fs::File>,
    path: PathBuf,
    remove_on_drop: bool,
}

impl DaemonLock {
    /// Acquire the lock exclusively using OS-level advisory locking.
    /// Lock is automatically released if the process dies (no stale lock files).
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
        // Advisory lock — automatically released by OS on process death
        file.try_lock_exclusive()
            .with_context(|| {
                format!("another daemon is running (lock: {})", path.display())
            })?;
        Ok(Self { file: Some(file), path, remove_on_drop: false })
    }

    /// Take ownership of the lock (used by daemon after receiving args).
    /// The daemon holds the file open; on drop the lock file is removed.
    pub fn adopt(path: PathBuf) -> Self {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .ok();
        // Re-acquire the advisory lock (parent released it)
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

/// Spawn a detached daemon process, passing keys via piped stdin.
pub fn spawn_daemon(keys: DerivedKeys, relays: Vec<String>) -> Result<()> {
    let lock = DaemonLock::acquire()?;
    let lock_path = lock.path.clone();
    let args = DaemonArgs {
        nostr_secret_key: keys.nostr_secret_key,
        iroh_secret_key_bytes: keys.iroh_secret_key_bytes,
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
        // Put daemon in its own process group so SIGINT (Ctrl+C) doesn't kill it
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
    // Drop the lock — the file persists (Drop doesn't remove it).
    // The daemon will open and hold it for its lifetime.
    drop(lock);
    info!("Daemon spawned (PID: {})", child.id());
    Ok(())
}

/// Parse daemon args from stdin.
pub fn read_daemon_args_from_stdin() -> Result<DaemonArgs> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).context("reading daemon args from stdin")?;
    let args: DaemonArgs = serde_json::from_str(&input)?;
    let mut bytes = input.into_bytes();
    bytes.zeroize();
    Ok(args)
}

/// Check if the daemon is running.
pub async fn is_daemon_running() -> bool {
    tokio::time::timeout(Duration::from_millis(500), connect_ipc())
        .await
        .ok()
        .and_then(Result::ok)
        .is_some()
}

/// Send a JSON command to the daemon, return the response.
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

    // Read response lines, updating progress bar or skipping progress messages
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
    pub iroh_secret_key_bytes: [u8; 32],
    pub manifest_key: [u8; 32],
    pub file_key: [u8; 32],
    pub lock_path: String,
    pub relays: Vec<String>,
}
