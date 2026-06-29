# zerodrive

**Decentralized, secure file storage** — upload and download files over a P2P network with no central servers, no cloud accounts, and no trust required. Your data is encrypted end-to-end before it ever leaves your machine.

## How it works

```
┌─────────────────────────────────────────────────────────┐
│                   zerodrive CLI                          │
│                                                         │
│  create-drive  upload  download  list  delete           │
│  status  stop  dump-id                                  │
└──────────┬──────────────────────────────────────┬────────┘
           │ IPC (Unix socket / TCP loopback)     │ auto-spawn
           v                                      v
┌──────────────────────┐   ┌───────────────────────────────┐
│   Background Daemon  │   │   Key Derivation              │
│                      │   │   BIP‑39 mnemonic →           │
│  ┌─────────────────┐ │   │   Nostr secp256k1 key        │
│  │ Nostr Publisher │ │   │   Iroh Ed25519 key            │
│  │ kind 30078      │ │   │   AES‑256‑GCM file key        │
│  └────────┬────────┘ │   │   AES‑256‑GCM manifest key    │
│           │           │   └───────────────────────────────┘
│  ┌────────v────────┐ │
│  │  Iroh P2P Node  │ │
│  │  (direct ) │
│  │  blob store     │ │
│  └─────────────────┘ │
└──────────────────────┘
```

1. **Key derivation** — A single BIP‑39 mnemonic phrase deterministically derives all keys: a Nostr secp256k1 key (for manifest pointers), an Iroh Ed25519 key (for P2P identity), and two AES‑256‑GCM keys (one for file content, one for the manifest JSON).

2. **Upload** — Each file is read in 1 MiB chunks, encrypted with AES‑256‑GCM in a streaming fashion (never buffering more than ~2 MB), and stored on Iroh's local blob store. A manifest JSON mapping filenames → content hashes + provider addresses is encrypted and published as a Nostr kind‑30078 replaceable event.

3. **Download** — The manifest is resolved from Nostr relays, decrypted, and each blob is fetched from the P2P network, decrypted chunk‑by‑chunk, and written directly to disk — all streaming, no temporary files.

4. **P2P transport** — Iroh handles peer discovery and blob transfer directly, without any relay servers or Kademlia DHT. Peers find each other through the `NodeAddr` (serialized as JSON) embedded in each manifest file entry.

5. **Daemon** — A lightweight background process manages the Nostr session and Iroh node. It auto‑spawns on first command and communicates with the CLI over IPC (Unix sockets on Linux, TCP loopback on Windows). Daemon logs are written to `~/.local/share/zerodrive/daemon.log` (Linux) or the equivalent data directory. Keys are passed to the daemon via piped stdin and zeroized on drop.

## Container format

Each encrypted file uses a custom frame format:
```
magic  "ZD2\n"           (4 bytes)
nonce_prefix             (8 bytes)
  chunk_size: u32 BE     (max 1,048,576 + 16)
  ciphertext + GCM tag   (variable)
  ...repeated for each chunk...
```

AES‑256‑GCM nonce per chunk = `nonce_prefix || u32_be(chunk_index)` (12 bytes total). The 4‑byte counter supports up to ~4 billion chunks (~4 PiB) without nonce reuse.

## Commands

| Command | Description |
|---|---|
| `create-drive <name>` | Create a named drive |
| `upload <drive> <path>` | Upload a file; use `--as-name` to set a different name in the manifest |
| `download <drive> <name>` | Download a file; use `-o` to set output path |
| `list [drive]` | List drives, or files in a drive |
| `delete <drive> [name]` | Delete a file or entire drive; use `--purge` to also remove the blob from local storage |
| `status` | Check if the daemon is running |
| `stop` | Stop the background daemon |
| `dump-id` | Print the Nostr public key (bech32 + hex) |

### Global flags

| Flag | Description |
|---|---|
| `--verbose` | Enable debug tracing output |
| `--relays <URLS>` | Nostr relay URLs (comma‑separated); defaults to `wss://relay.damus.io`, `wss://nostr.wine`, `wss://relay.nostr.band` |
| `--blob-dir <DIR>` | Directory for Iroh blob storage; defaults to `~/.local/share/zerodrive/blobs` |

All commands use `zerodrive <command> [flags]` syntax.

## Security

- **Zero-trust** — Encryption happens client‑side. The Nostr relay and Iroh peers never see plaintext.
- **Streaming AES‑256‑GCM** — Files are encrypted in 1 MiB chunks with a unique nonce per chunk, never fully loaded into RAM.
- **Forensic hardening** — On Linux, `RLIMIT_CORE` is set to 0 to prevent core dumps. All key material is zeroed on drop (`zeroize`).
- **Single mnemonic** — One BIP‑39 phrase controls everything. Lost phrase = lost data. No backdoors, no password reset.

## Build

```sh
git clone <repo> && cd zerodrive
cargo build --release
./target/release/zerodrive --help
```

Dependencies are fetched automatically by Cargo.

## Project structure

| File | Purpose |
|---|---|
| `main.rs` | CLI parser, command dispatch, daemon lifecycle |
| `derive.rs` | BIP‑39 → BIP‑32 (Nostr) + HKDF (Iroh, manifest, file) key derivation |
| `crypto_stream.rs` | Streaming AES‑256‑GCM encrypt/decrypt, channel‑based `AsyncRead` wrappers, `decrypt_slice_to_writer` for offset‑based Iroh readers |
| `blob_store.rs` | Iroh blob upload/download with progress bars, peer fetching |
| `manifest.rs` | Manifest schema, JSON serialization, encrypt/decrypt |
| `pointer.rs` | Nostr kind‑30078 publish/resolve |
| `daemon.rs` | IPC server, command processing, daemon spawn/lifecycle |
| `prompt.rs` | Secure mnemonic prompt, `RLIMIT_CORE` hardening |
| `output.rs` | Pretty‑print helpers (`✓`/`✗`/`•`) with `NO_COLOR` support |

## Dependencies

- `iroh` / `iroh-blobs` — P2P blob storage and transfer
- `nostr-sdk` — Nostr protocol for manifest pointer events
- `aes-gcm` / `aead` — AES‑256‑GCM streaming encryption
- `bip39` / `bip32` / `hkdf` / `secp256k1` — key derivation
- `clap` — CLI argument parsing
- `indicatif` — progress bars
- `tokio` — async runtime
- `zeroize` — secure memory clearing
