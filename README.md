# zerodrive

A CLI tool + Android app for decentralized, encrypted file storage over Nostr. Your files are encrypted client-side and stored on Blossom CDN servers; metadata is published as encrypted Nostr kind-30078 events. Only your mnemonic phrase can unlock everything.

You can generate a seedphrase from https://iancoleman.io/bip39/

## What? Where? Who?

| What | Where | Who can read it? |
| :--- | :--- | :--- |
| **Your Mnemonic** | In your head (or password manager) | Only you. |
| **Encrypted File Shards** | Blossom CDN servers (NIP-96) | No one (without your File Key). |
| **Encrypted File Map** | Nostr Relays (Public bulletin boards) | No one (without your Manifest Key). |
| **Decrypted Files** | Your local disk (when you download) | Only you. |

## How it works

One mnemonic phrase derives everything: your Nostr identity (for the manifest pointer) and two AES-256-GCM keys (one for the manifest, one for the files). Nothing leaves your machine without being encrypted first.

When you upload a file, it gets split into 40 MiB shards, each encrypted with AES-256-GCM, and PUT to a Blossom CDN server with Nostr Kind-24242 auth. A manifest mapping filenames to shard hashes is encrypted and published as a Nostr kind-30078 event. When you download, the daemon resolves the manifest from Nostr, fetches the shards from Blossom, decrypts them chunk-by-chunk, and writes the result to disk.

If the encrypted manifest exceeds ~48 KB, it is automatically split across multiple kind-30078 events (each with a unique d-tag). The daemon aggregates all manifests on resolve.

The daemon auto-spawns whenever you run a command and lives in its own process group. It also performs a periodic background sync every 30 seconds to pick up manifests published by other devices.

### Size limits

The manifest (file/drive metadata) is published as Nostr kind-30078 events. Each event has a ~48 KB encrypted payload limit. When a manifest exceeds this limit, files are automatically split across multiple linked manifests (each published as a separate event with a unique d-tag). Individual files have no size limit — arbitrary large files are sharded into 40 MiB encrypted chunks for CDN upload.

### Container format

Files are stored in a custom encrypted frame format:

```
magic  "ZD3\n"          4 bytes
nonce_prefix            8 bytes
  chunk_size: u32 BE    max 1,048,576 + 16
  ciphertext + GCM tag  variable
  ...repeated...
  0x00000000            zero terminator (truncation detection)
```

Each chunk gets a unique nonce: `nonce_prefix || u32_be(chunk_index)`. The 4-byte counter gives ~4 billion chunks, so ~4 PiB per file.

## Commands

| Command | What it does |
|---|---|
| `create-drive <name>` | New empty drive |
| `upload <drive> <path...>` | Upload files; `*` uploads everything in CWD; `--as-name` to rename |
| `download <drive> <name>` | Download a file; `*` downloads all files; `-o` for output path |
| `list [drive]` | List drives or files in a drive |
| `delete <drive> [name]` | Delete a file or whole drive |
| `status` | Check if the daemon is alive |
| `stop` | Shut the daemon down |
| `dump-id` | Print your Nostr public key (bech32 + hex) |

### Global flags

| Flag | Effect |
|---|---|
| `--verbose` | Debug tracing |
| `--relays <URLS>` | Comma-separated Nostr relay URLs (defaults to `wss://relay.damus.io`, `wss://nos.lol`, `wss://relay.primal.net`) |
| `--web` | Start the local web UI (opens on `http://localhost:<random-port>`) |

All usage: `zerodrive <command> [flags]` or `zerodrive --web`.

## Web UI

`zerodrive --web` starts a local HTTP server on a random port (printed to stderr). The first thing you'll see is a setup screen asking for your mnemonic phrase. Once submitted, the daemon starts in the background and the UI unlocks.

The web UI gives you the same operations as the CLI: create drives, upload (files or folders), download, delete. The session is protected by a random token stored in `localStorage` and sent as a `Bearer` header.

The upload progress bar uses `XMLHttpRequest` with `upload.onprogress` so it updates smoothly as bytes are sent.

## Android App

ZeroDrive ships as a native Android app via JNI. The Rust code compiles to `libzerodrive.so` (arm64-v8a) and runs the daemon in-process (no separate daemon process). The app presents a Material Design UI with:

- Mnemonic entry screen
- Drive listing with pull-to-refresh
- File listing per drive
- Upload/download progress tracking

Building requires the Android SDK/NDK and JDK 21.

## Security

- Client-side encryption. The Nostr relays and Blossom CDN servers never see plaintext.
- Streaming AES-256-GCM in 1 MiB chunks, never loading the whole file into memory.
- Each chunk uses a unique nonce (random 8-byte prefix + 4-byte counter).
- Container format bound as AAD (`ZD3\n` magic) to prevent chunk substitution.
- `RLIMIT_CORE = 0` on Linux to prevent core dumps.
- All key material zeroed on drop via `zeroize`.
- Zero-length terminator detects truncated streams.
- Constant-time session token comparison (SHA-256 + subtle).
- OS-level advisory file locking (no stale lock files on crash).
- One mnemonic controls everything. Lose it, lose your data.

## Key derivation

```
BIP‑39 mnemonic (24 words)
  └─ BIP‑32 m/44'/1237'/0'/0/0  →  Nostr secp256k1 key
  └─ HKDF‑SHA256("zerodrive/manifest/v1") →  AES manifest encryption key
  └─ HKDF‑SHA256("zerodrive/files/v1")   →  AES file encryption key
```

The manifest and file keys use HKDF from the raw seed with domain-separated info strings.

## Pre-built binaries

Pre-compiled binaries for Linux (x86_64) and Windows (x86_64, MinGW) are available on the [releases page](https://github.com/portbuster1337/zerodrive/releases). Just download the appropriate archive for your platform and extract it.

## Build from source

### Linux

```sh
git clone https://github.com/portbuster1337/zerodrive && cd zerodrive
cargo build --release
./target/release/zerodrive --help
```

### Windows (cross-compile from Linux)

```sh
cargo build --release --target x86_64-pc-windows-gnu
# requires: mingw-w64 (apt install gcc-mingw-w64-x86-64)
```

### Android APK

```sh
# requires: Android SDK + NDK, JDK 21, cargo-apk2
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
export JAVA_HOME=/path/to/jdk-21
cargo apk2 build --release --lib
# APK at target/release/apk/zerodrive.apk
```

## Project structure

| File | Does |
|---|---|
| `main.rs` | CLI parser, dispatch, daemon lifecycle |
| `derive.rs` | BIP‑39 → key derivation (Nostr + 2 AES keys) |
| `crypto_stream.rs` | Streaming AES‑256‑GCM, channel-based AsyncRead wrappers |
| `blob_store.rs` | Blossom CDN (NIP-96) blob upload/download with progress |
| `manifest.rs` | Manifest schema, JSON (de)serialization, encrypt/decrypt, shard manifest ref |
| `pointer.rs` | Nostr kind‑30078 publish/resolve with manifest splitting support |
| `daemon.rs` | IPC server, command processing, daemon spawn/lifecycle, background sync |
| `prompt.rs` | Secure mnemonic prompt, RLIMIT_CORE |
| `output.rs` | Pretty‑print helpers with NO_COLOR support |
| `web.rs` | Axum HTTP server, session auth, embedded frontend (HTML/CSS/JS inline) |
| `android/` | JNI bridge + in-process daemon runtime for Android |
| `integration_test.sh` | End-to-end integration test suite |

## Dependencies

- `nostr-sdk` (Nostr relay communication)
- `aes-gcm` / `aead` (AES-256-GCM)
- `bip39` / `bip32` / `hkdf` / `secp256k1` (key derivation)
- `clap` (CLI parsing)
- `reqwest` (HTTP client for Blossom CDN)
- `axum` / `tower-http` (web server)
- `tokio` (async runtime)
- `jni` / `android_logger` (Android platform)
- `zeroize` (secure memory clearing)
