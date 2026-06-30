# zerodrive

A CLI tool for decentralized file storage. Your files are encrypted and stored over a P2P network using only a mnemonic phrase as your identity.

It works like a minimal cloud drive: create drives, upload files, download them from anywhere. The daemon manages the P2P connections and publishes metadata over Nostr so you can find your files from any machine.

There's also a `--web` flag that serves a local browser UI so you don't have to use the terminal if you'd rather click things.

## What? Where? Who?

| What | Where | Who can read it? |
| :--- | :--- | :--- |
| **Your Mnemonic** | In your head (or password manager) | Only you. |
| **Encrypted File Chunks** | P2P Network (Iroh nodes) | No one (without your File Key). |
| **Encrypted File Map** | Nostr Relays (Public bulletin boards) | No one (without your Manifest Key). |
| **Decrypted Files** | Your local disk (when you download) | Only you. |

## How it works

One mnemonic phrase derives everything: your Nostr identity (for the manifest pointer), your Iroh P2P key (for blob transfer), and two AES-256-GCM keys (one for the manifest, one for the files). Nothing leaves your machine without being encrypted first.

When you upload a file, it gets split into 1 MiB chunks, each encrypted with a unique nonce, and stored in an ephemeral in-memory blob store (nothing written to disk locally). A manifest mapping filenames to content hashes is encrypted and published as a Nostr kind-30078 event. When you download, the daemon resolves that manifest from Nostr, finds the blobs on the P2P network, decrypts them chunk-by-chunk, and writes the result to disk.

The daemon auto-spawns whenever you run a command and lives in its own process group (Ctrl+C won't kill it).

### Size limits per mnemonic

The manifest (file/drive metadata) is published as a Nostr kind-30078 event. Different relays have different message size limits:

| Default relay | Message limit | Max files |
|---|---|---|
| relay.damus.io | 64 KB (strfry default) | ~70 |
| nostr.wine | 512 KB | ~620 |
| relay.nostr.band | unknown | varies |

Each file entry in the manifest is ~460 bytes after encryption and base64 encoding. The manifest must fit within at least one relay's limit for publishing to work.

Individual file size is not limited by the manifest. Iroh handles arbitrary blob sizes (terabytes). Web UI single uploads are capped at 4 GiB by the server. The CLI has no upload size limit.

## Container format

Files are stored in a custom frame format:

```
magic  "ZD2\n"          4 bytes
nonce_prefix            8 bytes
  chunk_size: u32 BE    max 1,048,576 + 16
  ciphertext + GCM tag  variable
  ...repeated...
```

Each chunk gets a unique nonce: `nonce_prefix || u32_be(chunk_index)`. The 4-byte counter gives ~4 billion chunks, so ~4 PiB per file.

## Commands

| Command | What it does |
|---|---|
| `create-drive <name>` | New empty drive |
| `upload <drive> <path...>` | Upload files; `*` uploads everything in CWD; `--as-name` to rename |
| `download <drive> <name>` | Download a file; `*` downloads all files; `-o` for output path |
| `list [drive]` | List drives or files in a drive |
| `delete <drive> [name]` | Delete a file or whole drive; `--purge` removes blobs from local store |
| `status` | Check if the daemon is alive |
| `stop` | Shut the daemon down |
| `dump-id` | Print your Nostr public key (bech32 + hex) |

### Global flags

| Flag | Effect |
|---|---|
| `--verbose` | Debug tracing |
| `--relays <URLS>` | Comma-separated Nostr relay URLs (defaults to `wss://relay.damus.io`, `wss://nostr.wine`, `wss://relay.nostr.band`) |
| `--web` | Start the local web UI (opens on `http://localhost:<random-port>`) |

All usage: `zerodrive <command> [flags]` or `zerodrive --web`.

## Web UI

`zerodrive --web` starts a local HTTP server on a random port (printed to stderr). The first thing you'll see is a setup screen asking for your mnemonic phrase. Once submitted, the daemon starts in the background and the UI unlocks.

The web UI gives you the same operations as the CLI: create drives, upload (files or folders), download, delete. The session is protected by a random token stored in `localStorage` and sent as a `Bearer` header.

The upload progress bar uses `XMLHttpRequest` with `upload.onprogress` so it updates smoothly as bytes are sent.

## Security

- Client-side encryption. The Nostr relay and P2P peers never see plaintext.
- Streaming AES-256-GCM in 1 MiB chunks, never loading the whole file into memory.
- `RLIMIT_CORE = 0` on Linux to prevent core dumps.
- All key material zeroed on drop via `zeroize`.
- One mnemonic controls everything. Lose it, lose your data.

## Key derivation

```
BIP‑39 mnemonic (24 words)
  └─ BIP‑32 m/44'/1237'/0'/0/0  →  Nostr secp256k1 key
  └─ HKDF‑SHA256("zerodrive/iroh/v1")    →  Iroh Ed25519 key
  └─ HKDF‑SHA256("zerodrive/manifest/v1") →  AES manifest encryption key
  └─ HKDF‑SHA256("zerodrive/files/v1")   →  AES file encryption key
```

The Iroh, manifest, and file keys use HKDF from the raw seed with domain-separated info strings.

## Build

```sh
git clone <repo> && cd zerodrive
cargo build --release
./target/release/zerodrive --help
```

## Project structure

| File | Does |
|---|---|
| `main.rs` | CLI parser, dispatch, daemon lifecycle |
| `derive.rs` | BIP‑39 → key derivation |
| `crypto_stream.rs` | Streaming AES‑256‑GCM, channel-based AsyncRead wrappers |
| `blob_store.rs` | Iroh blob upload/download with progress |
| `manifest.rs` | Manifest schema, JSON (de)serialization, encrypt/decrypt |
| `pointer.rs` | Nostr kind‑30078 publish/resolve |
| `daemon.rs` | IPC server, command processing, daemon spawn/lifecycle |
| `prompt.rs` | Secure mnemonic prompt, RLIMIT_CORE |
| `output.rs` | Pretty‑print helpers with NO_COLOR support |
| `web.rs` | Axum HTTP server, session auth, embedded frontend |

## Dependencies

- `iroh` / `iroh-blobs` (P2P blob storage)
- `nostr-sdk` (Nostr relay communication)
- `aes-gcm` / `aead` (AES-256-GCM)
- `bip39` / `bip32` / `hkdf` / `secp256k1` (key derivation)
- `clap` (CLI parsing)
- `axum` / `tower-http` (web server)
- `tokio` (async runtime)
- `zeroize` (secure memory clearing)
