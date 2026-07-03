use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use crate::daemon::{self, DaemonState};
use crate::derive::DerivedKeys;
use crate::manifest::Manifest;

type DaemonArc = Arc<Mutex<DaemonState>>;

#[allow(dead_code)]
struct AndroidState {
    relays: Vec<String>,
    daemon: Option<DaemonArc>,
}

type SharedState = Arc<Mutex<AndroidState>>;

static GLOBAL_STATE: OnceLock<SharedState> = OnceLock::new();
static GLOBAL_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn rt() -> &'static tokio::runtime::Runtime {
    GLOBAL_RT.get_or_init(|| tokio::runtime::Runtime::new().expect("Failed to create tokio runtime"))
}

fn global_state() -> &'static SharedState {
    GLOBAL_STATE.get().expect("Backend not initialized")
}

async fn get_daemon() -> Result<DaemonArc, String> {
    let s = match tokio::time::timeout(Duration::from_secs(5), global_state().lock()).await {
        Ok(guard) => guard,
        Err(_) => return Err("lock timeout getting daemon".into()),
    };
    s.daemon.clone().ok_or_else(|| "daemon not initialized".into())
}

fn err_json(msg: &str) -> String {
    serde_json::json!({"error": msg}).to_string()
}

async fn start_in_process_daemon(keys: DerivedKeys) -> Result<(), anyhow::Error> {
    log::info!("Android daemon: connecting to Nostr...");
    let relays = crate::pointer::DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    let pointer = crate::pointer::ManifestPointer::new(&keys.nostr_secret_key, &relays).await
        .map_err(|e| { log::warn!("Nostr init failed: {e}"); e })
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
                    log::warn!("Manifest resolve attempt {}/5 failed: {e}", attempt + 1);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
        result.unwrap_or_default()
    } else {
        BTreeMap::new()
    };

    global_state().lock().await.daemon = Some(Arc::new(Mutex::new(DaemonState {
        keys: keys.clone(),
        pointer,
        manifests,
        relays,
        shutdown: CancellationToken::new(),
        last_sync: Instant::now(),
        pending_changes: false,
    })));

    // Periodic background sync every 30 seconds
    let bg_state = global_state();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let daemon_opt = bg_state.lock().await.daemon.clone();
            if let Some(daemon) = daemon_opt {
                daemon::sync_manifest_no_lock(&daemon).await;
            }
        }
    });

    log::info!("Android daemon state initialized and synced!");

    Ok(())
}

pub fn init() {
    GLOBAL_STATE.get_or_init(|| Arc::new(Mutex::new(AndroidState {
        relays: crate::pointer::DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
        daemon: None,
    })));
}

fn spawn_async_timeout<F, T>(f: F, timeout: Duration) -> Result<T, String>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel::<T>();
    rt().spawn(async move {
        let result = f.await;
        let _ = tx.send(result);
    });
    rx.recv_timeout(timeout)
        .map_err(|e| match e {
            std::sync::mpsc::RecvTimeoutError::Timeout =>
                format!("operation timed out after {}s", timeout.as_secs()),
            std::sync::mpsc::RecvTimeoutError::Disconnected =>
                "runtime channel disconnected".into(),
        })
}

pub fn start_daemon(mnemonic_str: &str) -> String {
    let s = mnemonic_str.to_string();
    match spawn_async_timeout(async move {
        let mnemonic = match bip39::Mnemonic::parse(&s) {
            Ok(m) => m,
            Err(e) => { log::error!("Invalid mnemonic: {e}"); return format!("{{\"error\":\"invalid seed phrase: {e}\"}}"); }
        };
        let keys = match crate::derive::derive(&mnemonic) {
            Ok(k) => k,
            Err(e) => { log::error!("Key derivation failed: {e}"); return format!("{{\"error\":\"key derivation failed: {e}\"}}"); }
        };
        drop(mnemonic);
        match start_in_process_daemon(keys).await {
            Ok(_) => "{\"ok\":true}".to_string(),
            Err(e) => { log::error!("Daemon start failed: {e}"); format!("{{\"error\":\"failed to start daemon: {e}\"}}") }
        }
    }, Duration::from_secs(60)) {
        Ok(v) => v,
        Err(e) => { log::error!("{e}"); format!("{{\"error\":\"{e}\"}}") }
    }
}

pub fn list_drives() -> String {
    spawn_async_timeout(async {
        let daemon = match get_daemon().await { Ok(d) => d, Err(e) => return err_json(&e) };
        daemon::sync_manifest_no_lock(&daemon).await;
        let resp = daemon::execute_command(&daemon, "list", serde_json::json!({})).await;
        if let Some(err) = resp.error { return err_json(&err); }
        if let Some(res) = resp.result {
            if let Some(details) = res.get("drive_details") {
                return details.to_string();
            }
        }
        "[]".to_string()
    }, Duration::from_secs(15)).unwrap_or_else(|e| err_json(&e))
}

pub fn list_files(drive: &str) -> String {
    let d = drive.to_string();
    spawn_async_timeout(async move {
        let daemon = match get_daemon().await { Ok(d) => d, Err(e) => return err_json(&e) };
        daemon::sync_manifest_no_lock(&daemon).await;
        let resp = daemon::execute_command(&daemon, "list", serde_json::json!({"drive": d})).await;
        if let Some(err) = resp.error { return err_json(&err); }
        if let Some(res) = resp.result {
            if let Some(files) = res.get("files") {
                return files.to_string();
            }
        }
        "[]".to_string()
    }, Duration::from_secs(15)).unwrap_or_else(|e| err_json(&e))
}

pub fn create_drive(drive: &str) -> bool {
    let d = drive.to_string();
    rt().block_on(async {
        let daemon = match get_daemon().await { Ok(d) => d, Err(_) => return false };
        let resp = daemon::execute_command(&daemon, "create_drive", serde_json::json!({"name": d})).await;
        resp.error.is_none()
    })
}

pub fn delete_drive(drive: &str) -> bool {
    let d = drive.to_string();
    rt().block_on(async {
        let daemon = match get_daemon().await { Ok(d) => d, Err(_) => return false };
        let resp = daemon::execute_command(&daemon, "delete", serde_json::json!({"drive": d, "name": null})).await;
        resp.error.is_none()
    })
}

pub fn delete_file(drive: &str, file: &str) -> bool {
    let d = drive.to_string();
    let f = file.to_string();
    rt().block_on(async {
        let daemon = match get_daemon().await { Ok(d) => d, Err(_) => return false };
        let resp = daemon::execute_command(&daemon, "delete", serde_json::json!({"drive": d, "name": f})).await;
        resp.error.is_none()
    })
}

pub fn upload_file(drive: &str, file_path: &str) -> String {
    let d = drive.to_string();
    let p = file_path.to_string();
    let fname = std::path::Path::new(&p).file_name()
        .and_then(|s| s.to_str()).map(|s| s.to_string()).unwrap_or_default();

    rt().block_on(async {
        let daemon = match get_daemon().await { Ok(d) => d, Err(e) => return err_json(&e) };
        let resp = daemon::execute_command(&daemon, "upload", serde_json::json!({"drive": d, "path": p, "as": fname})).await;
        if let Some(err) = resp.error { return err_json(&err); }
        if let Some(mut res) = resp.result {
            if let Some(obj) = res.as_object_mut() {
                obj.insert("ok".into(), true.into());
                obj.insert("name".into(), fname.into());
            }
            return res.to_string();
        }
        err_json("unknown error")
    })
}

pub fn download_file(drive: &str, file_name: &str, dest_path: &str) -> String {
    let d = drive.to_string();
    let f = file_name.to_string();
    let dp = dest_path.to_string();

    rt().block_on(async {
        let daemon = match get_daemon().await { Ok(d) => d, Err(e) => return err_json(&e) };
        let resp = daemon::execute_command(&daemon, "download", serde_json::json!({"drive": d, "name": f, "out": dp})).await;
        if let Some(err) = resp.error { return err_json(&err); }
        if let Some(mut res) = resp.result {
            if let Some(obj) = res.as_object_mut() {
                obj.insert("ok".into(), true.into());
            }
            return res.to_string();
        }
        err_json("unknown error")
    })
}
