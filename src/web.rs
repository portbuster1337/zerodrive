use std::net::SocketAddr;
use std::sync::Arc;

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::{
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use bytes::Bytes;
use futures_core::Stream;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use serde_json::json;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use crate::daemon::{self, sanitize_filename};
use crate::manifest::FileEntry;

struct WebState {
    relays: Vec<String>,
    session_token: Option<String>,
    shutdown_token: CancellationToken,
}

type SharedState = Arc<Mutex<WebState>>;

/// Generate a random 64-char hex session token.
fn generate_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("rng");
    hex::encode(buf)
}

/// Start the web server on localhost with a random port.
/// Blocks until the server shuts down.
pub async fn run_web(relays: Vec<String>) -> Result<u16, anyhow::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let state = Arc::new(Mutex::new(WebState {
        relays,
        session_token: None,
        shutdown_token: CancellationToken::new(),
    }));

    let protected = Router::new()
        .route("/api/status", get(status_handler))
        .route("/api/drives", get(list_drives_handler).post(create_drive_handler))
        .route("/api/drives/:name", delete(delete_drive_handler))
        .route("/api/drives/:name/files", get(list_files_handler))
        .route("/api/drives/:name/upload", post(upload_handler))
        .route("/api/drives/:name/download/:file", get(download_handler))
        .route("/api/drives/:name/files/:file", delete(delete_file_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/api/setup", post(setup_handler))
        .merge(protected)
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024 * 1024))
        .with_state(state);

    let _addr = SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("  Web UI: http://localhost:{}", port);

    axum::serve(listener, app).await?;

    Ok(port)
}

// ── Auth Middleware ──

async fn auth_middleware(
    State(state): State<SharedState>,
    headers: HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let authorized = {
        let s = state.lock().await;
        s.session_token.as_ref().map_or(false, |token| {
            let provided = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let expected = format!("Bearer {token}");
            let mut hasher = Sha256::new();
            hasher.update(expected.as_bytes());
            let expected_hash = hasher.finalize_reset();
            hasher.update(provided.as_bytes());
            let provided_hash = hasher.finalize();
            bool::from(expected_hash.ct_eq(&provided_hash))
        })
    };

    if authorized {
        next.run(request).await
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
    }
}

// ── Frontend ──

async fn root_handler() -> Html<&'static str> {
    Html(FRONTEND_HTML)
}

// ── Helpers ──

fn api_error(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg.into() })))
}

fn server_error(msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": msg.into() })))
}

fn daemon_unavailable() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "daemon not initialized", "need_setup": true })),
    )
}

/// Proxy an IPC command to the daemon.
/// Returns `daemon_unavailable()` if the daemon is not reachable.
async fn ipc(method: &str, params: serde_json::Value) -> Result<serde_json::Value, Response> {
    if !daemon::is_daemon_running().await {
        return Err(daemon_unavailable().into_response());
    }
    match daemon::send_command(method, params, None).await {
        Ok(resp) => {
            if let Some(err) = resp.error {
                Err(api_error(err).into_response())
            } else {
                Ok(resp.result.unwrap_or(json!({})))
            }
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("Connection refused")
                || msg.contains("connect")
                || msg.contains("No such file")
            {
                Err(daemon_unavailable().into_response())
            } else {
                Err(server_error(msg).into_response())
            }
        }
    }
}

// ── API: Setup ──

#[derive(Deserialize)]
struct SetupBody {
    mnemonic: String,
}

async fn setup_handler(
    State(state): State<SharedState>,
    Json(body): Json<SetupBody>,
) -> impl IntoResponse {
    let relays;
    // Generate token regardless
    let token = generate_token();

    // If daemon is already running, just return a new token
    if daemon::is_daemon_running().await {
        state.lock().await.session_token = Some(token.clone());
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "already_running": true, "token": token })),
        );
    }

    {
        let s = state.lock().await;
        relays = s.relays.clone();
    }

    let mnemonic = match bip39::Mnemonic::parse(&body.mnemonic) {
        Ok(m) => m,
        Err(e) => return api_error(format!("invalid mnemonic: {e}")),
    };

    let keys = match crate::derive::derive(&mnemonic) {
        Ok(k) => k,
        Err(e) => return api_error(format!("key derivation failed: {e}")),
    };
    drop(mnemonic);

    if let Err(e) = daemon::spawn_daemon(keys, relays) {
        return server_error(format!("failed to start daemon: {e}"));
    }

    // Store token immediately; daemon may take time to connect to Nostr relays
    state.lock().await.session_token = Some(token.clone());

    // Spawn background task to wait for daemon readiness, tied to shutdown token
    let cancel = {
        let s = state.lock().await;
        s.shutdown_token.clone()
    };
    tokio::spawn(async move {
        for _ in 0..120 {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
            if daemon::is_daemon_running().await { return; }
        }
    });

    (StatusCode::OK, Json(json!({ "ok": true, "token": token })))
}

// ── API: Status ──

async fn status_handler() -> impl IntoResponse {
    match ipc("status", json!({})).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(resp) => resp,
    }
}

// ── API: Drives ──

async fn list_drives_handler() -> impl IntoResponse {
    let resp = match ipc("list", json!({})).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let result: Vec<serde_json::Value> = resp
        .get("drive_details")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| {
            resp.get("drives")
                .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
                .unwrap_or_default()
                .into_iter()
                .map(|name| json!({ "name": name, "file_count": 0 }))
                .collect()
        });

    (StatusCode::OK, Json(json!(result))).into_response()
}

async fn create_drive_handler(Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return api_error("missing 'name' field").into_response(),
    };
    match ipc("create_drive", json!({ "name": name })).await {
        Ok(_) => (StatusCode::CREATED, Json(json!({ "ok": true }))).into_response(),
        Err(resp) => resp,
    }
}

async fn delete_drive_handler(Path(name): Path<String>) -> impl IntoResponse {
    match ipc("delete", json!({ "drive": name, "name": null, "purge": false })).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(resp) => resp,
    }
}

// ── API: Files ──

async fn list_files_handler(Path(name): Path<String>) -> impl IntoResponse {
    match ipc("list", json!({ "drive": name })).await {
        Ok(result) => {
            let files: Vec<FileEntry> = result
                .get("files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            (StatusCode::OK, Json(json!(files))).into_response()
        }
        Err(resp) => resp,
    }
}

async fn delete_file_handler(Path((drive, file)): Path<(String, String)>) -> impl IntoResponse {
    match ipc("delete", json!({ "drive": drive, "name": file, "purge": false })).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(resp) => resp,
    }
}

// ── API: Upload ──

async fn upload_handler(
    Path(drive): Path<String>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    use tokio::io::AsyncWriteExt;

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let file_name = field
            .file_name()
            .map(|s| sanitize_filename(s))
            .unwrap_or_else(|| {
                format!(
                    "upload_{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                )
            });

        // Use a UUID subdirectory to avoid temp file collisions
        let upload_id = uuid::Uuid::new_v4();
        let mut temp_dir = std::env::temp_dir();
        temp_dir.push("zerodrive-web-uploads");
        temp_dir.push(upload_id.to_string());
        let _ = tokio::fs::create_dir_all(&temp_dir).await;
        let temp_path = temp_dir.join(&file_name);

        // Stream multipart body directly to temp file (no full buffering)
        let mut file = match tokio::fs::File::create(&temp_path).await {
            Ok(f) => f,
            Err(_) => return server_error("failed to create temp file for upload").into_response(),
        };
        loop {
            match field.chunk().await {
                Ok(Some(bytes)) => {
                    if let Err(e) = file.write_all(&bytes).await {
                        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                        return server_error(format!("write error: {e}")).into_response();
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = tokio::fs::remove_dir_all(&temp_dir).await;
                    return server_error(format!("upload read error: {e}")).into_response();
                }
            }
        }
        if let Err(e) = file.flush().await {
            let _ = tokio::fs::remove_dir_all(&temp_dir).await;
            return server_error(format!("flush error: {e}")).into_response();
        }
        drop(file);

        let result = ipc(
            "upload",
            json!({
                "drive": drive,
                "path": temp_path.to_string_lossy(),
                "as": file_name,
            }),
        )
        .await;
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;

        match result {
            Ok(r) => {
                let hash = r.get("hash").and_then(|v| v.as_str()).unwrap_or("?");
                let size = r.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                return (
                    StatusCode::CREATED,
                    Json(json!({ "ok": true, "hash": hash, "size": size, "name": file_name })),
                )
                    .into_response();
            }
            Err(resp) => return resp,
        }
    }

    api_error("no file field in upload").into_response()
}

// ── API: Download ──

/// A stream wrapper that removes the temp directory when the stream is dropped
/// (after all bytes have been sent to the HTTP client).
struct CleanupStream {
    inner: tokio_util::io::ReaderStream<tokio::fs::File>,
    dir: std::path::PathBuf,
}

impl Stream for CleanupStream {
    type Item = Result<Bytes, std::io::Error>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl Drop for CleanupStream {
    fn drop(&mut self) {
        let dir = self.dir.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::remove_dir_all(&dir).await;
        });
    }
}

async fn download_handler(
    Path((drive, fname)): Path<(String, String)>,
) -> impl IntoResponse {
    let dl_id = uuid::Uuid::new_v4();
    let out_dir = std::env::temp_dir().join("zerodrive-web-dl").join(dl_id.to_string());
    let _ = tokio::fs::create_dir_all(&out_dir).await;
    let safe_name = sanitize_filename(&fname);
    let out_path = out_dir.join(&safe_name);

    match ipc(
        "download",
        json!({
            "drive": drive,
            "name": fname,
            "out": out_path.to_string_lossy(),
        }),
    )
    .await
    {
        Ok(_) => match tokio::fs::File::open(&out_path).await {
            Ok(file) => {
                let content_length = file.metadata().await.map(|m| m.len()).ok();
                let stream = CleanupStream { inner: tokio_util::io::ReaderStream::new(file), dir: out_dir };
                let mut builder = Response::builder()
                    .header("Content-Type", "application/octet-stream")
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", safe_name),
                    );
                if let Some(len) = content_length {
                    builder = builder.header("Content-Length", len.to_string());
                }
                builder.body(axum::body::Body::from_stream(stream)).unwrap()
            }
            Err(e) => {
                let _ = tokio::fs::remove_dir_all(&out_dir).await;
                server_error(format!("failed to read downloaded file: {e}")).into_response()
            },
        },
        Err(resp) => {
            let _ = tokio::fs::remove_dir_all(&out_dir).await;
            resp
        },
    }
}

// ── Embedded Frontend ──

const FRONTEND_HTML: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'">
<title>ZeroDrive</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --bg: #0d1117; --surface: #161b22; --surface-2: #21262d;
    --border: #30363d; --text: #e6edf3; --text-secondary: #8b949e;
    --accent: #58a6ff; --accent-hover: #79b8ff; --danger: #f85149;
    --success: #3fb950; --warning: #d29922; --radius: 8px;
  }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  .header { border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; background: var(--surface); }
  .header h1 { font-size: 20px; font-weight: 600; }
  .header h1 span { color: var(--accent); }
  .header .badge { font-size: 11px; color: var(--text-secondary); background: var(--surface-2); padding: 4px 10px; border-radius: 12px; }
  .container { max-width: 960px; margin: 0 auto; padding: 24px; }
  .section-title { font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); margin-bottom: 12px; }
  .empty { text-align: center; padding: 48px 24px; color: var(--text-secondary); }
  .empty p { margin-top: 8px; font-size: 14px; }
  .empty .icon { font-size: 48px; margin-bottom: 16px; opacity: 0.4; }

  /* Setup */
  #setupScreen { display: none; align-items: center; justify-content: center; min-height: 80vh; padding: 24px; }
  #setupScreen .card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 32px; max-width: 480px; width: 100%; }
  #setupScreen .card h2 { margin-bottom: 8px; }
  #setupScreen .card p { color: var(--text-secondary); font-size: 14px; margin-bottom: 20px; }
  #setupScreen textarea { width: 100%; padding: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 14px; outline: none; resize: vertical; font-family: monospace; min-height: 80px; margin-bottom: 16px; }
  #setupScreen textarea:focus { border-color: var(--accent); }
  #setupScreen .btn-row { display: flex; gap: 8px; }
  #setupScreen .btn-row button { flex: 1; padding: 10px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 14px; font-weight: 500; }
  #setupScreen .btn-row .primary { background: var(--accent); color: #fff; }
  #setupScreen .btn-row .primary:hover { background: var(--accent-hover); }
  #setupScreen .btn-row .primary:disabled { opacity: 0.5; cursor: not-allowed; }
  #setupScreen .error { color: var(--danger); font-size: 13px; margin-top: 8px; }
  #setupScreen .hint { color: var(--text-secondary); font-size: 12px; margin-top: 12px; }
  #setupScreen .token { color: var(--accent); font-size: 11px; margin-top: 12px; word-break: break-all; }

  /* Drives */
  .drives-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; margin-bottom: 32px; }
  .drive-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; cursor: pointer; transition: border-color 0.15s, background 0.15s; position: relative; }
  .drive-card:hover { border-color: var(--accent); background: var(--surface-2); }
  .drive-card .name { font-size: 15px; font-weight: 500; }
  .drive-card .meta { font-size: 12px; color: var(--text-secondary); margin-top: 4px; }
  .drive-card .actions { position: absolute; top: 12px; right: 12px; display: none; gap: 4px; }
  .drive-card:hover .actions { display: flex; }
  .drive-card .actions button { background: none; border: none; color: var(--text-secondary); cursor: pointer; padding: 4px; font-size: 14px; border-radius: 4px; }
  .drive-card .actions button:hover { color: var(--danger); background: rgba(248,81,73,0.1); }

  /* Files */
  .file-list { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  .file-header, .file-row { display: grid; grid-template-columns: 1fr 100px 120px; padding: 10px 16px; align-items: center; gap: 8px; }
  .file-header { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); border-bottom: 1px solid var(--border); }
  .file-row { font-size: 14px; border-bottom: 1px solid var(--border); transition: background 0.1s; }
  .file-row:last-child { border-bottom: none; }
  .file-row:hover { background: var(--surface-2); }
  .file-row .name { color: var(--accent); }
  .file-row .size { color: var(--text-secondary); }
  .file-row .actions { display: flex; gap: 8px; justify-content: flex-end; }
  .file-row .actions a, .file-row .actions button { background: none; border: none; color: var(--text-secondary); cursor: pointer; font-size: 13px; padding: 4px 8px; border-radius: 4px; text-decoration: none; transition: background 0.1s; }
  .file-row .actions a:hover, .file-row .actions button:hover { background: var(--surface-2); }
  .file-row .actions .dl-link { color: var(--accent); }
  .file-row .actions .dl-link:hover { background: rgba(88,166,255,0.1); }
  .file-row .actions .del-btn:hover { color: var(--danger); background: rgba(248,81,73,0.1); }

  /* Upload */
  .upload-area { border: 2px dashed var(--border); border-radius: var(--radius); padding: 32px; text-align: center; cursor: pointer; transition: border-color 0.2s, background 0.2s; margin-bottom: 24px; }
  .upload-area:hover, .upload-area.dragover { border-color: var(--accent); background: rgba(88,166,255,0.05); }
  .upload-area .icon { font-size: 32px; margin-bottom: 8px; opacity: 0.5; }
  .upload-area p { font-size: 14px; color: var(--text-secondary); }
  .upload-area .sub { font-size: 12px; color: var(--text-secondary); margin-top: 4px; opacity: 0.7; }
    .upload-area input[type="file"] { display: none; }
  .upload-mode-toggle { display: flex; gap: 4px; justify-content: center; margin: 8px 0; }
  .upload-mode-toggle button { padding: 4px 14px; border-radius: 12px; border: 1px solid var(--border); background: var(--surface); color: var(--text-secondary); cursor: pointer; font-size: 12px; transition: all 0.15s; }
  .upload-mode-toggle button.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .upload-progress { margin-top: 12px; height: 4px; background: var(--border); border-radius: 2px; overflow: hidden; display: none; }
  .upload-progress .bar { height: 100%; background: var(--accent); width: 0%; transition: width 0.3s; }

  /* Misc */
  .back-btn { background: none; border: none; color: var(--accent); cursor: pointer; font-size: 14px; padding: 8px 0; margin-bottom: 16px; display: inline-flex; align-items: center; gap: 4px; }
  .back-btn:hover { color: var(--accent-hover); }
  .modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); z-index: 100; align-items: center; justify-content: center; }
  .modal-overlay.active { display: flex; }
  .modal { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; width: 360px; max-width: 90vw; }
  .modal h3 { margin-bottom: 16px; font-size: 16px; }
  .modal input { width: 100%; padding: 10px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 14px; outline: none; margin-bottom: 16px; }
  .modal input:focus { border-color: var(--accent); }
  .modal .btn-row { display: flex; gap: 8px; justify-content: flex-end; }
  .modal .btn-row button { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 14px; }
  .modal .btn-row .cancel { background: var(--surface-2); color: var(--text); }
  .modal .btn-row .cancel:hover { background: var(--border); }
  .modal .btn-row .confirm { background: var(--accent); color: #fff; }
  .modal .btn-row .confirm:hover { background: var(--accent-hover); }
  .toast { position: fixed; bottom: 24px; right: 24px; padding: 12px 20px; border-radius: var(--radius); color: #fff; font-size: 14px; z-index: 200; transform: translateY(100px); opacity: 0; transition: transform 0.3s, opacity 0.3s; }
  .toast.show { transform: translateY(0); opacity: 1; }
  .toast.success { background: var(--success); }
  .toast.error { background: var(--danger); }
  .toast.info { background: var(--accent); }
  @media (max-width:600px) { .drives-grid { grid-template-columns: 1fr; } .file-header, .file-row { grid-template-columns: 1fr 80px 90px; } .container { padding: 12px; } }
</style>
</head>
<body>
<div class="header">
  <h1><span>Zero</span>Drive</h1>
  <span class="badge" id="statusBadge">starting...</span>
</div>

<div id="setupScreen">
  <div class="card">
    <h2>Welcome to ZeroDrive</h2>
    <p>Enter your 24-word BIP-39 mnemonic to unlock your drives. This is your identity — it never leaves this machine.</p>
    <textarea id="mnemonicInput" placeholder="Paste your 24-word mnemonic here..."></textarea>
    <div class="btn-row">
      <button class="primary" id="setupBtn" onclick="doSetup()">Unlock</button>
    </div>
    <div class="error" id="setupError"></div>
    <div class="hint">The daemon will start in the background. You only need to do this once per session.</div>
  </div>
</div>

<div class="container" id="app" style="display:none;">
  <div id="drivesView">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <div class="section-title">Drives</div>
      <button onclick="showCreateDrive()" style="background:var(--accent);color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500;">+ New Drive</button>
    </div>
    <div class="drives-grid" id="drivesGrid"></div>
  </div>
  <div id="filesView" style="display:none;">
    <button class="back-btn" onclick="showDrives()">&larr; Back to Drives</button>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <div class="section-title" id="filesTitle">Files</div>
    </div>
    <div class="upload-area" id="uploadArea">
      <div class="icon">&#x1F4C1;</div>
      <p>Drop files here or click to upload</p>
      <div class="upload-mode-toggle">
        <button id="modeFiles" class="active" onclick="setUploadMode('files')">Files</button>
        <button id="modeFolder" onclick="setUploadMode('folder')">Folder</button>
      </div>
      <div class="upload-progress" id="uploadProgress"><div class="bar" id="uploadBar"></div></div>
      <input type="file" id="fileInput" multiple onchange="inputUpload(event)" />
    </div>
    <div class="file-list" id="filesList"></div>
  </div>
</div>

<div class="modal-overlay" id="createDriveModal">
  <div class="modal">
    <h3>Create Drive</h3>
    <input type="text" id="newDriveName" placeholder="Drive name" onkeydown="if(event.key==='Enter') confirmCreateDrive()" />
    <div class="btn-row">
      <button class="cancel" onclick="closeCreateDrive()">Cancel</button>
      <button class="confirm" onclick="confirmCreateDrive()">Create</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let currentDrive = null;
let isSetup = false;

function getToken() { return localStorage.getItem('zd_session_token'); }

function authHeaders(headers = {}) {
  const token = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return headers;
}

async function api(path, opts = {}) {
  const headers = authHeaders(opts.headers || {});
  if (!headers['Content-Type'] && opts.body && !(opts.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401) {
    localStorage.removeItem('zd_session_token');
    if (!isSetup) { showSetup(); }
    const data = await res.json().catch(() => ({}));
    data._unauthorized = true;
    return data;
  }
  const data = await res.json();
  if (!res.ok) {
    if (data.need_setup && !isSetup && !getToken()) { showSetup(); return null; }
    throw new Error(data.error || res.statusText);
  }
  return data;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024; const sizes = ['B','KiB','MiB','GiB','TiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg; el.className = 'toast ' + type + ' show';
  setTimeout(() => el.classList.remove('show'), 3000);
}

function escHtml(s) {
  const d = document.createElement('div'); d.textContent = s;
  return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Setup ──

function showSetup() {
  isSetup = true;
  if (getToken()) toast('Session expired — please unlock again', 'info');
  document.getElementById('setupScreen').style.display = 'flex';
  document.getElementById('app').style.display = 'none';
  document.getElementById('statusBadge').textContent = 'locked';
  document.getElementById('statusBadge').style.color = 'var(--warning)';
}

async function doSetup() {
  const input = document.getElementById('mnemonicInput');
  const btn = document.getElementById('setupBtn');
  const error = document.getElementById('setupError');
  const mnemonic = input.value.trim();
  if (!mnemonic) { error.textContent = 'Please enter your mnemonic.'; return; }
  error.textContent = ''; btn.disabled = true; btn.textContent = 'Starting...';
  try {
    const data = await fetch('/api/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mnemonic }),
    }).then(r => r.json());
    if (data.ok && data.token) {
      localStorage.setItem('zd_session_token', data.token);
      input.value = '';  // clear mnemonic from DOM
      isSetup = false;
      document.getElementById('setupScreen').style.display = 'none';
      document.getElementById('app').style.display = 'block';
      document.getElementById('statusBadge').textContent = 'connecting...';
      document.getElementById('statusBadge').style.color = 'var(--warning)';
      toast('Daemon starting...', 'info');
      const token = data.token;
      let ready = false;
      for (let i = 0; i < 120; i++) {
        try {
          if ((await fetch('/api/status', { headers: { 'Authorization': 'Bearer ' + token } })).ok) {
            ready = true; break;
          }
        } catch {}
        await new Promise(r => setTimeout(r, 1000));
      }
      if (!ready) { toast('Daemon failed to start within 120s', 'error'); return; }
      document.getElementById('statusBadge').textContent = 'online';
      document.getElementById('statusBadge').style.color = 'var(--success)';
      toast('Daemon ready', 'success');
      await loadDrives();
    } else {
      error.textContent = data.error || 'Setup failed';
    }
  } catch (e) { error.textContent = e.message; }
  btn.disabled = false; btn.textContent = 'Unlock';
}

// ── Drives ──

async function loadDrives() {
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const data = await api('/api/drives');
      if (!data || data._unauthorized) return;
      const grid = document.getElementById('drivesGrid');
      if (!data.length) {
        grid.innerHTML = '<div class="empty"><div class="icon">&#x1F4C2;</div><p>No drives yet. Create one to get started.</p></div>';
        return;
      }
      grid.innerHTML = data.map(d => '<div class="drive-card" data-name="' + escHtml(d.name) + '"><div class="name">' + escHtml(d.name) + '</div><div class="meta">' + d.file_count + ' file' + (d.file_count !== 1 ? 's' : '') + '</div><div class="actions"><button class="del-drive-btn" data-name="' + escHtml(d.name) + '" title="Delete drive">&times;</button></div></div>').join('');
      // Delegate event listeners
      document.getElementById('drivesGrid').onclick = function(e) {
        const card = e.target.closest('.drive-card');
        if (card && !e.target.closest('.del-drive-btn')) {
          openDrive(card.dataset.name);
        }
        const delBtn = e.target.closest('.del-drive-btn');
        if (delBtn) {
          e.stopPropagation();
          deleteDrive(delBtn.dataset.name);
        }
      };
      return;
    } catch (e) { lastErr = e; await new Promise(r => setTimeout(r, 1000)); }
  }
  toast('Failed to load drives: ' + lastErr.message, 'error');
}

function showCreateDrive() {
  document.getElementById('newDriveName').value = '';
  document.getElementById('createDriveModal').classList.add('active');
  document.getElementById('newDriveName').focus();
}
function closeCreateDrive() { document.getElementById('createDriveModal').classList.remove('active'); }
async function confirmCreateDrive() {
  const name = document.getElementById('newDriveName').value.trim();
  if (!name) return; closeCreateDrive();
  try {
    await api('/api/drives', { method: 'POST', body: JSON.stringify({ name }) });
    toast('Drive created', 'success');
    await loadDrives();
  } catch (e) { toast('Failed: ' + e.message, 'error'); }
}
async function deleteDrive(name) {
  if (!confirm('Delete drive "' + name + '" and all its files?')) return;
  try {
    await api('/api/drives/' + encodeURIComponent(name), { method: 'DELETE' });
    toast('Drive deleted', 'success');
    await loadDrives();
  } catch (e) { toast('Failed: ' + e.message, 'error'); }
}

// ── Files ──

async function openDrive(name) {
  currentDrive = name;
  document.getElementById('drivesView').style.display = 'none';
  document.getElementById('filesView').style.display = 'block';
  document.getElementById('filesTitle').textContent = name + ' / files';
  document.getElementById('filesList').innerHTML = '<div class="file-header"><span>Name</span><span>Size</span><span style="text-align:right;">Actions</span></div>';
  setupUploadArea(); await loadFiles();
}
function showDrives() {
  currentDrive = null;
  document.getElementById('drivesView').style.display = 'block';
  document.getElementById('filesView').style.display = 'none';
  loadDrives();
}
function setupUploadArea() {
  const area = document.getElementById('uploadArea');
  const input = document.getElementById('fileInput');
  setUploadMode(uploadMode);
  area.onclick = () => input.click();
  area.ondragover = e => { e.preventDefault(); area.classList.add('dragover'); };
  area.ondragleave = () => { area.classList.remove('dragover'); };
  area.ondrop = e => {
    e.preventDefault(); area.classList.remove('dragover');
    if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; doUpload(e.dataTransfer.files); }
  };
}
async function doUpload(files) {
  if (!currentDrive) return;
  const prog = document.getElementById('uploadProgress');
  const bar = document.getElementById('uploadBar'); prog.style.display = 'block';
  const filesArr = Array.from(files);
  const total = filesArr.length;
  const totalBytes = filesArr.reduce((s, f) => s + f.size, 0);
  let sentBytes = 0;
  for (const file of filesArr) {
    const displayName = file.webkitRelativePath || file.name;
    try {
      const data = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        const token = getToken();
        xhr.open('POST', '/api/drives/' + encodeURIComponent(currentDrive) + '/upload');
        if (token) xhr.setRequestHeader('Authorization', 'Bearer ' + token);
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) {
            const pct = ((sentBytes + e.loaded) / totalBytes * 100);
            bar.style.width = Math.min(pct, 100) + '%';
          }
        };
        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            try { resolve(JSON.parse(xhr.responseText)); } catch { resolve({}); }
          } else {
            try { const d = JSON.parse(xhr.responseText); reject(new Error(d.error || xhr.statusText)); }
            catch { reject(new Error(xhr.statusText)); }
          }
        };
        xhr.onerror = () => reject(new Error('Network error'));
        const fd = new FormData();
        fd.append('file', file, displayName);
        xhr.send(fd);
      });
      sentBytes += file.size;
      toast('Uploaded ' + displayName, 'success');
    } catch (e) {
      sentBytes += file.size;
      toast('Failed ' + displayName + ': ' + e.message, 'error');
    }
  }
  bar.style.width = '100%';
  setTimeout(() => { prog.style.display = 'none'; bar.style.width = '0%'; }, 1000);
  await loadFiles();
}
async function loadFiles() {
  if (!currentDrive) return;
  const list = document.getElementById('filesList');
  list.innerHTML = '<div class="file-header"><span>Name</span><span>Size</span><span style="text-align:right;">Actions</span></div>';
  try {
    const data = await api('/api/drives/' + encodeURIComponent(currentDrive) + '/files');
    if (!data || data._unauthorized) return;
    let html = '<div class="file-header"><span>Name</span><span>Size</span><span style="text-align:right;">Actions</span></div>';
    if (!data.length) {
      html += '<div class="empty" style="padding:32px;"><p>No files in this drive.</p></div>';
    } else {
      html += data.map(f => '<div class="file-row"><span class="name">' + escHtml(f.name) + '</span><span class="size">' + formatBytes(f.size) + '</span><span class="actions"><button class="dl-link" data-file="' + escHtml(f.name) + '">Download</button><button class="del-btn" data-file="' + escHtml(f.name) + '">Delete</button></span></div>').join('');
    }
    list.innerHTML = html;
    // Delegate event listeners for files
    list.onclick = function(e) {
      const dlBtn = e.target.closest('.dl-link');
      if (dlBtn) { downloadFile(currentDrive, dlBtn.dataset.file); }
      const delBtn = e.target.closest('.del-btn');
      if (delBtn) { deleteFile(delBtn.dataset.file); }
    };
  } catch (e) { toast('Failed to load files: ' + e.message, 'error'); }
}
async function downloadFile(drive, name) {
  try {
    const token = getToken();
    const res = await fetch('/api/drives/' + encodeURIComponent(drive) + '/download/' + encodeURIComponent(name), {
      headers: token ? { 'Authorization': 'Bearer ' + token } : {},
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || 'Download failed');
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) { toast('Download failed: ' + e.message, 'error'); }
}

let uploadMode = 'files';
function setUploadMode(mode) {
  uploadMode = mode;
  document.getElementById('modeFiles').className = mode === 'files' ? 'active' : '';
  document.getElementById('modeFolder').className = mode === 'folder' ? 'active' : '';
  const input = document.getElementById('fileInput');
  input.value = '';
  if (mode === 'folder') { input.setAttribute('webkitdirectory', ''); }
  else { input.removeAttribute('webkitdirectory'); }
}
function inputUpload(e) {
  if (e.target.files.length) doUpload(e.target.files);
}

async function deleteFile(name) {
  if (!currentDrive) return;
  if (!confirm('Delete "' + name + '"?')) return;
  try {
    await api('/api/drives/' + encodeURIComponent(currentDrive) + '/files/' + encodeURIComponent(name), { method: 'DELETE' });
    toast('File deleted', 'success'); await loadFiles();
  } catch (e) { toast('Failed: ' + e.message, 'error'); }
}

// ── Init ──

async function init() {
  const badge = document.getElementById('statusBadge');
  const token = getToken();
  if (token) {
    try {
      const status = await api('/api/status');
      if (status && status._unauthorized) { showSetup(); return; }
      badge.textContent = 'online'; badge.style.color = 'var(--success)';
      document.getElementById('setupScreen').style.display = 'none';
      document.getElementById('app').style.display = 'block';
      await loadDrives(); return;
    } catch {}
  }
  showSetup();
}

init();
</script>
</body>
</html>"###;