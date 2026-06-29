use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use std::io::Read;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use anyhow::{Context, Result};
use iroh::node::FsNode;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::blob_store::BlobStore;
use crate::derive::DerivedKeys;
use crate::manifest::Manifest;
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
fn sanitize_filename(name: &str) -> String {
    name.rsplit('/')
        .next()
        .unwrap_or(name)
        .rsplit('\\')
        .next()
        .unwrap_or(name)
        .trim_start_matches('.')
        .to_string()
}

/// State held by the running daemon process.
pub struct DaemonState {
    pub keys: DerivedKeys,
    pub node: FsNode,
    pub pointer: ManifestPointer,
    pub manifest: Manifest,
    pub blob_dir: PathBuf,
    pub relays: Vec<String>,
    pub node_addr_str: String,
    pub shutdown: CancellationToken,
}

impl DaemonState {
    pub fn node_id(&self) -> String {
        self.node.node_id().to_string()
    }

    /// Publish manifest and return event ID (avoids borrow conflicts).
    pub async fn publish_manifest(&mut self) -> Result<String> {
        let mk = self.keys.manifest_key;
        self.pointer
            .publish_and_update(&mut self.manifest, &mk)
            .await
    }
}

/// Main daemon entry point.
pub async fn run_daemon(
    keys: DerivedKeys,
    blob_dir: PathBuf,
    relays: Vec<String>,
) -> Result<()> {
    tokio::fs::create_dir_all(&blob_dir).await?;

    // Create iroh node
    let iroh_secret = iroh::base::key::SecretKey::from_bytes(&keys.iroh_secret_key_bytes);
    let node = FsNode::persistent(&blob_dir)
        .await?
        .secret_key(iroh_secret)
        .spawn()
        .await?;

    let node_id = node.node_id().to_string();
    let node_addr = node.client().net().node_addr().await?;
    let node_addr_str = serde_json::to_string(&node_addr)?;
    info!("Daemon NodeID: {node_id}");

    // Connect Nostr, resolve or create manifest
    let pointer = ManifestPointer::new(&keys.nostr_secret_key, &relays).await?;
    let mut manifest = pointer
        .resolve(&keys.manifest_key)
        .await?
        .unwrap_or_else(Manifest::new);

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
    pointer
        .publish_and_update(&mut manifest, &keys.manifest_key)
        .await?;

    let shutdown = CancellationToken::new();
    let state = Arc::new(Mutex::new(DaemonState {
        keys,
        node,
        pointer,
        manifest,
        blob_dir,
        relays,
        node_addr_str,
        shutdown: shutdown.clone(),
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
}

async fn handle_ipc(
    stream: IpcStream,
    state: Arc<Mutex<DaemonState>>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    const MAX_LINE: usize = 64 * 1024;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        if line.len() > MAX_LINE {
            let resp = IpcResponse {
                id: 0,
                result: None,
                error: Some("line too long".into()),
            };
            let mut json = serde_json::to_vec(&resp)?;
            json.push(b'\n');
            let _ = writer.write_all(&json).await;
            break;
        }

        let cmd: IpcCommand = match serde_json::from_str(&line) {
            Ok(c) => c,
            Err(e) => {
                let resp = IpcResponse {
                    id: 0,
                    result: None,
                    error: Some(format!("parse error: {e}")),
                };
                let mut json = serde_json::to_vec(&resp)?;
                json.push(b'\n');
                writer.write_all(&json).await?;
                writer.flush().await?;
                continue;
            }
        };

        let response = process_command(cmd, &state).await;
        let mut json = serde_json::to_vec(&response)?;
        json.push(b'\n');
        writer.write_all(&json).await?;
        writer.flush().await?;
    }
    Ok(())
}

async fn process_command(
    cmd: IpcCommand,
    state: &Arc<Mutex<DaemonState>>,
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
                    "blob_dir": s.blob_dir.to_string_lossy(),
                    "num_relays": s.relays.len(),
                })),
                error: None,
            }
        }

        "stop" => {
            let s = state.lock().await;
            s.shutdown.cancel();
            IpcResponse {
                id,
                result: Some(serde_json::json!("stopping")),
                error: None,
            }
        }

        "create_drive" => {
            let name = cmd.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let mut s = state.lock().await;
            s.manifest.create_drive(name);
            match s.publish_manifest().await {
                Ok(_) => IpcResponse { id, result: Some(serde_json::json!({ "ok": true })), error: None },
                Err(e) => IpcResponse { id, result: None, error: Some(format!("{e}")) },
            }
        }

        "upload" => {
            let drive = cmd.params.get("drive").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let path = cmd.params.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fname = cmd.params.get("as").and_then(|v| v.as_str()).unwrap_or(&path).to_string();

            let local_path = PathBuf::from(&path);
            if !local_path.exists() {
                return IpcResponse { id, result: None, error: Some("file not found".into()) };
            }

            // Clone what we need and release the lock before the long-running upload
            let (node, file_key, node_addr_str) = {
                let s = state.lock().await;
                (s.node.clone(), s.keys.file_key, s.node_addr_str.clone())
            };
            match BlobStore::upload(&node, &local_path, &file_key, false).await {
                Ok((hash, size)) => {
                    let mut s = state.lock().await;

                    if let Err(e) = s.manifest.add_file(&drive, &fname, &hash, size, &node_addr_str) {
                        return IpcResponse { id, result: None, error: Some(format!("{e}")) };
                    }
                    match s.publish_manifest().await {
                        Ok(_) => IpcResponse {
                            id,
                            result: Some(serde_json::json!({ "hash": hash, "size": size })),
                            error: None,
                        },
                        Err(e) => IpcResponse { id, result: None, error: Some(format!("{e}")) },
                    }
                }
                Err(e) => IpcResponse { id, result: None, error: Some(format!("{e}")) },
            }
        }

        "download" => {
            let drive = cmd.params.get("drive").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fname = cmd.params.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let out = cmd.params.get("out").and_then(|v| v.as_str()).map(|s| PathBuf::from(s.to_string()));
            let out_path = out.unwrap_or_else(|| PathBuf::from(sanitize_filename(&fname)));

            let s = state.lock().await;
            let drive_obj = match s.manifest.get_drive(&drive) {
                Ok(d) => d,
                Err(e) => return IpcResponse { id, result: None, error: Some(format!("{e}")) },
            };
            let entry = match drive_obj.files.iter().find(|f| f.name == fname) {
                Some(f) => f.clone(),
                None => return IpcResponse {
                    id, result: None,
                    error: Some(format!("file '{fname}' not found in drive '{drive}'")),
                },
            };
            drop(s);

            // Check if we need to fetch from peers
            let s = state.lock().await;
            let has_local = BlobStore::has_blob(&s.node, &entry.hash).await.unwrap_or(false);
            let hash_str = entry.hash.clone();
            let file_size = entry.size;
            let providers = entry.providers.clone();
            drop(s);

            if !has_local {
                if let Err(e) = fetch_from_providers(state, &hash_str, &providers).await {
                    return IpcResponse { id, result: None, error: Some(format!("fetch failed: {e}")) };
                }
            }

            let s = state.lock().await;
            match BlobStore::download(&s.node, &hash_str, &out_path, &s.keys.file_key, file_size, false).await {
                Ok(size) => IpcResponse {
                    id,
                    result: Some(serde_json::json!({ "path": out_path.to_string_lossy(), "size": size })),
                    error: None,
                },
                Err(e) => {
                    let _ = tokio::fs::remove_file(&out_path).await;
                    IpcResponse { id, result: None, error: Some(format!("{e}")) }
                }
            }
        }

        "list" => {
            let drive_name = cmd.params.get("drive").and_then(|v| v.as_str());
            let s = state.lock().await;
            match drive_name {
                Some("") | None => {
                    let drives = s.manifest.list_drives();
                    IpcResponse { id, result: Some(serde_json::json!({ "drives": drives })), error: None }
                }
                Some(name) => match s.manifest.list_files(name) {
                    Ok(files) => IpcResponse {
                        id,
                        result: Some(serde_json::json!({ "drive": name, "files": files })),
                        error: None,
                    },
                    Err(e) => IpcResponse { id, result: None, error: Some(format!("{e}")) },
                },
            }
        }

        "delete" => {
            let drive = cmd.params.get("drive").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let fname = cmd.params.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let purge = cmd.params.get("purge").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut s = state.lock().await;

            if let Some(ref name) = fname {
                // If purge, get the hash before removing from manifest
                let hash_to_delete = if purge {
                    s.manifest.get_drive(&drive).ok()
                        .and_then(|d| d.files.iter().find(|f| f.name == *name))
                        .map(|f| f.hash.clone())
                } else {
                    None
                };
                if let Err(e) = s.manifest.remove_file(&drive, name) {
                    return IpcResponse { id, result: None, error: Some(format!("{e}")) };
                }
                if let Some(hash) = hash_to_delete {
                    // Delete from local blob store (best-effort)
                    let hash_str = hash.strip_prefix("blake3:").unwrap_or(&hash);
                    if let Ok(h) = hash_str.parse::<iroh_blobs::Hash>() {
                        let _ = s.node.client().blobs().delete_blob(h).await;
                    }
                }
            } else {
                let removed_drive = s.manifest.drives.remove(&drive);
                if removed_drive.is_none() {
                    return IpcResponse { id, result: None, error: Some(format!("drive '{drive}' not found")) };
                }
                if purge {
                    for file in removed_drive.unwrap().files {
                        let hash_str = file.hash.strip_prefix("blake3:").unwrap_or(&file.hash).to_string();
                        if let Ok(h) = hash_str.parse::<iroh_blobs::Hash>() {
                            let _ = s.node.client().blobs().delete_blob(h).await;
                        }
                    }
                }
                s.manifest.updated_at = chrono::Utc::now().timestamp();
            }
            match s.publish_manifest().await {
                Ok(_) => IpcResponse { id, result: Some(serde_json::json!({ "ok": true })), error: None },
                Err(e) => IpcResponse { id, result: None, error: Some(format!("{e}")) },
            }
        }

        _ => IpcResponse {
            id,
            result: None,
            error: Some(format!("unknown method: {method}")),
        },
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

    for node_addr_str in providers {
        let s = state.lock().await;
        match BlobStore::fetch_from_peer(&s.node, &hash, node_addr_str).await {
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

/// A file lock that prevents concurrent daemon spawns.
/// The lock file is removed on drop.
struct DaemonLock {
    path: PathBuf,
}

impl DaemonLock {
    fn acquire() -> Result<Self> {
        let path = daemon_lock_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("another daemon is starting (lock: {})", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Spawn a detached daemon process, passing keys via piped stdin.
pub fn spawn_daemon(keys: DerivedKeys, blob_dir: PathBuf, relays: Vec<String>) -> Result<()> {
    let _lock = DaemonLock::acquire()?;
    let args = DaemonArgs {
        nostr_secret_key: keys.nostr_secret_key,
        iroh_secret_key_bytes: keys.iroh_secret_key_bytes,
        manifest_key: keys.manifest_key,
        file_key: keys.file_key,
        blob_dir: blob_dir.to_string_lossy().to_string(),
        relays,
    };

    let mut keys_json = serde_json::to_vec(&args)?;
    let exe = std::env::current_exe()?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.args(["__daemon_internal__"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().context("spawning daemon")?;

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        stdin.write_all(&keys_json)?;
        stdin.flush()?;
    }

    keys_json.zeroize();
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
pub async fn send_command(method: &str, params: serde_json::Value) -> Result<IpcResponse> {
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
    reader.read_line(&mut line).await?;
    let resp: IpcResponse = serde_json::from_str(&line)?;
    Ok(resp)
}

#[derive(serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DaemonArgs {
    pub nostr_secret_key: [u8; 32],
    pub iroh_secret_key_bytes: [u8; 32],
    pub manifest_key: [u8; 32],
    pub file_key: [u8; 32],
    pub blob_dir: String,
    pub relays: Vec<String>,
}
