mod blob_store;
mod crypto_stream;
mod daemon;
mod derive;
mod manifest;
mod output;
mod pointer;
mod prompt;

use anyhow::{Context, Result};
use clap::Parser;
use nostr_sdk::prelude::*;
use tracing_subscriber::EnvFilter;

use crate::derive::DerivedKeys;

#[derive(Parser)]
#[command(name = "zerodrive", about = "Decentralized, secure file drive over Nostr + Iroh")]
struct Cli {
    /// Enable verbose debug output
    #[arg(global = true, long)]
    verbose: bool,

    /// Nostr relay URLs (comma-separated)
    #[arg(global = true, long, value_delimiter = ',')]
    relays: Vec<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    /// Create a new drive
    #[command(name = "create-drive")]
    CreateDrive {
        name: String,
    },
    /// Upload a file to a drive
    Upload {
        drive: String,
        path: String,
        #[arg(long)]
        as_name: Option<String>,
    },
    /// Download a file from a drive
    Download {
        drive: String,
        name: String,
        #[arg(short = 'o')]
        out: Option<String>,
    },
    /// List drives or files
    List {
        drive: Option<String>,
    },
    /// Delete a drive or file
    Delete {
        drive: String,
        name: Option<String>,
        /// Also remove the blob from the local store
        #[arg(long)]
        purge: bool,
    },
    /// Check daemon status
    Status,
    /// Stop the background daemon
    Stop,
    /// Print the Nostr public key
    #[command(name = "dump-id")]
    DumpId,
    /// Internal daemon command
    #[command(hide = true)]
    #[command(name = "__daemon_internal__")]
    DaemonInternal,
}

fn default_relays() -> Vec<String> {
    vec![
        "wss://relay.damus.io".to_string(),
        "wss://nostr.wine".to_string(),
        "wss://relay.nostr.band".to_string(),
    ]
}

#[tokio::main]
async fn main() {
    prompt::forensic_harden();

    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive("zerodrive=debug".parse().unwrap()))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive("zerodrive=warn".parse().unwrap()))
            .init();
    }

    let result = match &cli.command {
        Command::DaemonInternal => run_daemon_internal(&cli).await,
        _ => run_cli(cli).await,
    };

    if let Err(e) = result {
        output::error(format!("{e:#}"));
        std::process::exit(1);
    }
}

async fn run_cli(cli: Cli) -> Result<()> {
    let relays = if cli.relays.is_empty() {
        default_relays()
    } else {
        cli.relays.clone()
    };

    // Commands that need the daemon running.
    let needs_daemon = matches!(
        &cli.command,
        Command::CreateDrive { .. }
            | Command::Upload { .. }
            | Command::Download { .. }
            | Command::List { .. }
            | Command::Delete { .. }
    );

    let _ensure = if needs_daemon && !daemon::is_daemon_running().await {
        let k = get_keys()?;
        ensure_daemon_running(&k, &relays).await?;
        Some(k)
    } else {
        None
    };

    match &cli.command {
        Command::CreateDrive { name } => {
            let resp = daemon::send_command("create_drive", serde_json::json!({ "name": name }), None).await?;
            if let Some(err) = resp.error { anyhow::bail!("{err}"); }
            output::success(format!("Drive '{name}' created (manifest updated on Nostr)"));
        }

        Command::Upload { drive, path, as_name } => {
            let file_name = as_name.clone().unwrap_or_else(|| {
                std::path::Path::new(path)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.clone())
            });

            let pb = indicatif::ProgressBar::new(0);
            pb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{msg} [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                    .unwrap()
                    .progress_chars("=> "),
            );
            pb.set_message(format!("Uploading {file_name}"));
            let resp = daemon::send_command("upload", serde_json::json!({
                "drive": drive, "path": path, "as": file_name,
            }), Some(pb)).await?;
            if let Some(err) = resp.error { anyhow::bail!("{err}"); }
            if let Some(ref result) = resp.result {
                let hash = result["hash"].as_str().unwrap_or("?");
                let size = result["size"].as_u64().unwrap_or(0);
                output::success(format!("Uploaded {drive}/{file_name} → {hash} ({})", output::format_bytes(size)));
            }
        }

        Command::Download { drive, name, out } => {
            let pb = indicatif::ProgressBar::new(0);
            pb.set_style(
                indicatif::ProgressStyle::default_bar()
                    .template("{msg} [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                    .unwrap()
                    .progress_chars("=> "),
            );
            pb.set_message(format!("Downloading {name}"));
            let resp = daemon::send_command("download", serde_json::json!({
                "drive": drive, "name": name, "out": out,
            }), Some(pb)).await?;
            if let Some(err) = resp.error { anyhow::bail!("{err}"); }
            if let Some(ref result) = resp.result {
                let path = result["path"].as_str().unwrap_or(name);
                let size = result["size"].as_u64().unwrap_or(0);
                output::success(format!("Downloaded {drive}/{name} → {path} ({})", output::format_bytes(size)));
            }
        }

        Command::List { drive } => {
            let resp = daemon::send_command("list", serde_json::json!({ "drive": drive }), None).await?;
            if let Some(err) = resp.error { anyhow::bail!("{err}"); }
            if let Some(ref result) = resp.result {
                if let Some(drives) = result.get("drives") {
                    let drives: Vec<String> = serde_json::from_value(drives.clone()).unwrap_or_default();
                    if drives.is_empty() {
                        output::info("No drives found. Create one with 'zerodrive create-drive <name>'");
                    } else {
                        println!("Drives:");
                        for d in &drives { println!("  {d}"); }
                    }
                }
                if let Some(files) = result.get("files") {
                    let files: Vec<manifest::FileEntry> = serde_json::from_value(files.clone()).unwrap_or_default();
                    if files.is_empty() {
                        output::info("No files in this drive.");
                    } else {
                        println!("Files in drive '{}':", drive.as_deref().unwrap_or("?"));
                        for f in &files {
                            println!("  {}  {}  {}", output::format_bytes(f.size), &f.hash[..16.min(f.hash.len())], f.name);
                        }
                    }
                }
            }
        }

        Command::Delete { drive, name, purge } => {
            let resp = daemon::send_command("delete", serde_json::json!({
                "drive": drive, "name": name, "purge": purge,
            }), None).await?;
            if let Some(err) = resp.error { anyhow::bail!("{err}"); }
            if name.is_some() {
                output::success(format!("Deleted {drive}/{}", name.as_deref().unwrap_or("?")));
            } else {
                output::success(format!("Deleted drive '{drive}'"));
            }
        }

        Command::Status => {
            let resp = daemon::send_command("status", serde_json::json!({}), None).await?;
            if let Some(err) = resp.error { anyhow::bail!("{err}"); }
            if let Some(ref result) = resp.result {
                let node_id = result["node_id"].as_str().unwrap_or("?");
                output::success(format!("Daemon running (NodeID: {node_id})"));
            }
        }

        Command::Stop => {
            match daemon::send_command("stop", serde_json::json!({}), None).await {
                Ok(_) => output::success("Daemon stopping"),
                Err(_) => output::info("Daemon does not appear to be running"),
            }
        }

        Command::DumpId => {
            let k = get_keys()?;
            let sk = SecretKey::from_slice(&k.nostr_secret_key)
                .context("invalid Nostr secret key")?;
            let nostr_keys = Keys::new(sk);
            let pubkey = nostr_keys.public_key().to_bech32()
                .unwrap_or_else(|_| nostr_keys.public_key().to_hex());
            println!("Nostr public key: {pubkey}");
            println!("Nostr public key (hex): {}", nostr_keys.public_key().to_hex());
        }

        Command::DaemonInternal => unreachable!(),
    }

    Ok(())
}

/// Run as the daemon (spawned via __daemon_internal__).
async fn run_daemon_internal(_cli: &Cli) -> Result<()> {
    let args = daemon::read_daemon_args_from_stdin()?;
    let relays = args.relays.clone();

    let keys = DerivedKeys {
        nostr_secret_key: args.nostr_secret_key,
        iroh_secret_key_bytes: args.iroh_secret_key_bytes,
        manifest_key: args.manifest_key,
        file_key: args.file_key,
    };

    // Keys have been moved out; zeroize the args
    drop(args);

    daemon::run_daemon(keys, relays).await
}

/// Prompt for mnemonic once and derive keys.
fn get_keys() -> Result<DerivedKeys> {
    let mnemonic = prompt::secure_mnemonic_prompt("Enter mnemonic (24 words): ")?;
    let keys = derive::derive(&mnemonic)?;
    let _ = mnemonic;
    Ok(keys)
}

/// Ensure the daemon is running; if not, spawn it.
async fn ensure_daemon_running(
    keys: &DerivedKeys,
    relays: &[String],
) -> Result<()> {
    if daemon::is_daemon_running().await {
        return Ok(());
    }

    output::info("Daemon not running, starting...");

    let daemon_keys = DerivedKeys {
        nostr_secret_key: keys.nostr_secret_key,
        iroh_secret_key_bytes: keys.iroh_secret_key_bytes,
        manifest_key: keys.manifest_key,
        file_key: keys.file_key,
    };

    let relays_vec = relays.to_vec();

    daemon::spawn_daemon(daemon_keys, relays_vec)?;

    // Wait for daemon to start
    for _ in 0..20 {
        if daemon::is_daemon_running().await { break; }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Ok(())
}
