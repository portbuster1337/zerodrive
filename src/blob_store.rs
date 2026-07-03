use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use base64::Engine;
use bytes::Bytes;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use nostr_sdk::prelude::*;
use nostr_sdk::bitcoin::hashes::Hash as BitcoinHash;

use crate::manifest::Shard;

pub type ProgressTx = mpsc::UnboundedSender<(u64, u64)>;

const SHARD_SIZE: usize = 40 * 1024 * 1024;

const SERVERS: &[&str] = &[
    "https://cdn.hzrd149.com/upload",
    "https://blossom.primal.net/upload",
    "https://nostr.download/upload",
];

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{msg} [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("=> ")
}

pub struct BlobStore;

impl BlobStore {
    pub async fn upload(
        local_path: &Path,
        file_key: &[u8; 32],
        progress: Option<ProgressTx>,
    ) -> Result<(Vec<Shard>, u64)> {
        let file = tokio::fs::File::open(local_path).await.context("opening file")?;
        let metadata = file.metadata().await?;
        let file_size = metadata.len();

        let fname = local_path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let pb = if progress.is_some() {
            let pb = ProgressBar::new(file_size);
            pb.set_style(progress_style());
            pb.set_message(format!("Encrypting & Uploading {fname}"));
            pb
        } else { ProgressBar::hidden() };

        if let Some(tx) = &progress { let _ = tx.send((0, file_size)); }

        let progress_file = ProgressRead { inner: file, pb: pb.clone(), tx: progress.clone(), total: file_size, last_reported: 0 };
        let mut encrypting_reader = crate::crypto_stream::EncryptingReader::new(progress_file, file_key);

        let mut shards = Vec::new();
        let mut server_idx = 0;
        let mut total_uploaded = 0;

        // Shared reqwest::Client for connection reuse (HTTP/2 multiplexing)
        let http = reqwest::Client::builder()
            .http2_keep_alive_while_idle(true)
            .http2_keep_alive_interval(Some(std::time::Duration::from_secs(10)))
            .build()
            .context("building HTTP client")?;

        let mut buf = Vec::with_capacity(SHARD_SIZE);
        loop {
            buf.clear();
            let n = read_buf_exact(&mut encrypting_reader, &mut buf, SHARD_SIZE).await?;

            if n == 0 && buf.is_empty() {
                break;
            }

            let ephemeral_keys = Keys::generate();
            let priv_key_hex = ephemeral_keys.secret_key().to_secret_hex();

            // Try servers in round-robin order until one accepts the shard
            let url = {
                let mut last_err = String::new();
                let mut uploaded = false;
                let mut url = String::new();
                for attempt in 0..SERVERS.len() {
                    let idx = (server_idx + attempt) % SERVERS.len();
                    match upload_shard_to_server(&http, SERVERS[idx], &buf, &ephemeral_keys, &fname).await {
                        Ok(u) => { url = u; uploaded = true; break; }
                        Err(e) => last_err = e.to_string(),
                    }
                }
                server_idx += 1;
                if !uploaded {
                    anyhow::bail!("All Blossom servers rejected shard: {last_err}");
                }
                url
            };

            total_uploaded += n as u64;
            pb.inc(n as u64);
            if let Some(tx) = &progress { let _ = tx.send((total_uploaded, file_size)); }

            shards.push(Shard {
                url,
                size: n as u64,
                priv_key: priv_key_hex,
            });

            if n < SHARD_SIZE {
                break;
            }
        }

        pb.finish_and_clear();
        if let Some(tx) = &progress { let _ = tx.send((file_size, file_size)); }

        Ok((shards, file_size))
    }

    pub async fn download(
        shards: &[Shard],
        output_path: &Path,
        file_key: &[u8; 32],
        original_size: u64,
        progress: Option<ProgressTx>,
    ) -> Result<u64> {
        let fname = output_path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let pb = if progress.is_some() {
            let pb = ProgressBar::new(original_size);
            pb.set_style(progress_style());
            pb.set_message(format!("Downloading & Decrypting {fname}"));
            pb
        } else { ProgressBar::hidden() };

        if let Some(tx) = &progress { let _ = tx.send((0, original_size)); }

        let output_file = tokio::fs::File::create(output_path).await?;
        let mut writer = ProgressWrite {
            inner: tokio::io::BufWriter::new(output_file),
            pb: pb.clone(),
            tx: progress.clone(),
            total: original_size,
            last_reported: 0,
        };

        let mut chain = HttpShardChain::new(shards.to_vec());
        crate::crypto_stream::decrypt_stream(&mut chain, &mut writer, file_key).await.context("decrypting blob")?;

        writer.flush().await?;
        pb.finish_and_clear();
        if let Some(tx) = &progress { let _ = tx.send((original_size, original_size)); }

        let meta = tokio::fs::metadata(output_path).await?;
        let actual_size = meta.len();
        if original_size > 0 && actual_size != original_size {
            anyhow::bail!(
                "downloaded file size mismatch: expected {original_size}, got {actual_size} — the file may be truncated"
            );
        }
        Ok(actual_size)
    }

    /// Encrypt arbitrary data and upload to Blossom as a single blob.
    /// Returns (url, priv_key_hex).
    pub async fn upload_encrypted_blob(data: &[u8], file_key: &[u8; 32], fname: &str) -> Result<(String, String)> {
        let mut ciphertext = Vec::new();
        {
            let reader = tokio::io::BufReader::new(std::io::Cursor::new(data));
            let mut writer = tokio::io::BufWriter::new(&mut ciphertext);
            crate::crypto_stream::encrypt_stream(reader, &mut writer, file_key).await
                .context("encrypting blob")?;
            writer.flush().await?;
        }

        let http = reqwest::Client::builder()
            .http2_keep_alive_while_idle(true)
            .http2_keep_alive_interval(Some(std::time::Duration::from_secs(10)))
            .build()
            .context("building HTTP client")?;

        let ephemeral_keys = Keys::generate();
        let priv_key_hex = ephemeral_keys.secret_key().to_secret_hex();

        let mut last_err = String::new();
        for server_url in SERVERS {
            match upload_shard_to_server(&http, server_url, &ciphertext, &ephemeral_keys, fname).await {
                Ok(url) => return Ok((url, priv_key_hex)),
                Err(e) => last_err = e.to_string(),
            }
        }
        anyhow::bail!("All Blossom servers rejected encrypted blob: {last_err}")
    }

    /// Download an encrypted blob from a Blossom URL and decrypt it.
    pub async fn download_encrypted_blob(url: &str, priv_key: &str, file_key: &[u8; 32]) -> Result<Vec<u8>> {
        let client = reqwest::Client::builder()
            .http2_keep_alive_while_idle(true)
            .http2_keep_alive_interval(Some(std::time::Duration::from_secs(10)))
            .build()
            .context("building HTTP client")?;

        let auth_header = match Keys::parse(priv_key) {
            Ok(keys) => {
                let expiry = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + 3600;
                match EventBuilder::new(Kind::Custom(24242), "Get file")
                    .tag(Tag::parse(["t", "get"]).unwrap())
                    .tag(Tag::parse(["expiration", &expiry.to_string()]).unwrap())
                    .sign_with_keys(&keys)
                {
                    Ok(event) => format!(
                        "Nostr {}",
                        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&event).unwrap())
                    ),
                    Err(_) => String::new(),
                }
            }
            Err(_) => String::new(),
        };

        let mut req = client.get(url);
        if !auth_header.is_empty() {
            req = req.header("Authorization", &auth_header);
        }
        let mut res = req.send().await?;

        if res.status() == 401 || res.status() == 403 {
            res = client.get(url).send().await?;
        }

        if !res.status().is_success() {
            anyhow::bail!("failed to download encrypted blob: HTTP {}", res.status());
        }

        let mut ciphertext = Vec::new();
        loop {
            match res.chunk().await {
                Ok(Some(chunk)) => {
                    if !chunk.is_empty() {
                        ciphertext.extend_from_slice(&chunk);
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    anyhow::bail!("blob download error: {e} — url: {url}");
                }
            }
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(ciphertext));
        let mut writer = tokio::io::BufWriter::new(&mut plaintext);
        crate::crypto_stream::decrypt_stream(reader, &mut writer, file_key).await
            .context("decrypting blob")?;
        writer.flush().await?;

        Ok(plaintext)
    }
}

async fn read_buf_exact<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut Vec<u8>, limit: usize) -> std::io::Result<usize> {
    buf.resize(limit, 0);
    let mut total_read = 0;
    while total_read < limit {
        let n = match reader.read(&mut buf[total_read..]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        total_read += n;
    }
    buf.truncate(total_read);
    Ok(total_read)
}

/// Blossom-style upload: PUT raw body with Kind 24242 auth
async fn upload_shard_to_server(
    client: &reqwest::Client,
    server_url: &str,
    data: &[u8],
    keys: &Keys,
    _filename: &str
) -> Result<String> {

    // Compute SHA256 for x tag (required by some servers for auth validation)
    let data_hash = nostr_sdk::bitcoin::hashes::sha256::Hash::hash(data);
    let hash_hex = data_hash.to_string();

    // Blossom auth: Kind 24242 with t=upload, x=SHA256, expiration tags
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600;
    let auth_event: Event = EventBuilder::new(Kind::Custom(24242), "Upload file")
        .tag(Tag::parse(["t", "upload"])?)
        .tag(Tag::parse(["x", &hash_hex])?)
        .tag(Tag::parse(["expiration", &expiry.to_string()])?)
        .sign_with_keys(keys)?;

    let auth_header = format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&auth_event)?)
    );

    let res = client
        .put(server_url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/octet-stream")
        .header("X-SHA-256", &hash_hex)
        .body(data.to_vec())
        .send()
        .await?;

    let status = res.status();
    let body_text = res.text().await?;

    if !status.is_success() {
        anyhow::bail!("Server {} returned error: {} — body: {}", server_url, status, body_text);
    }

    let body: serde_json::Value = serde_json::from_str(&body_text)?;

    // Blossom response: {"url": "...", "sha256": "..."}
    if let Some(url) = body.get("url").and_then(|v| v.as_str()) {
        return Ok(url.to_string());
    }

    // NIP-96 fallback: nip94_event.tags[url]
    if body.get("status").and_then(|v| v.as_str()) == Some("success") {
        if let Some(tags) = body.get("nip94_event").and_then(|v| v.get("tags")).and_then(|v| v.as_array()) {
            for tag in tags {
                if let Some(arr) = tag.as_array() {
                    if arr.len() >= 2 && arr[0].as_str() == Some("url") {
                        if let Some(url) = arr[1].as_str() {
                            return Ok(url.to_string());
                        }
                    }
                }
            }
        }
    }

    // Fallback: data field (void.cat style)
    if let Some(url) = body.get("data").and_then(|v| v.as_str()) {
        return Ok(url.to_string());
    }

    anyhow::bail!("Could not parse URL from server response: {:?}", body)
}

struct HttpShardChain {
    rx: mpsc::Receiver<std::io::Result<Bytes>>,
    buffer: Bytes,
    pos: usize,
}

impl HttpShardChain {
    fn new(shards: Vec<Shard>) -> Self {
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(4);
        // Shared client for connection reuse across all shard downloads
        let client = reqwest::Client::builder()
            .http2_keep_alive_while_idle(true)
            .http2_keep_alive_interval(Some(std::time::Duration::from_secs(10)))
            .build()
            .unwrap();
        tokio::spawn(async move {
            for shard in shards {
                // Blossom GET download — auth is optional, use Kind 24242 if needed
                let auth_header = match Keys::parse(&shard.priv_key) {
                    Ok(keys) => {
                        let expiry = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() + 3600;
                        match EventBuilder::new(Kind::Custom(24242), "Get file")
                            .tag(Tag::parse(["t", "get"]).unwrap())
                            .tag(Tag::parse(["expiration", &expiry.to_string()]).unwrap())
                            .sign_with_keys(&keys)
                        {
                            Ok(event) => format!(
                                "Nostr {}",
                                base64::engine::general_purpose::STANDARD.encode(serde_json::to_string(&event).unwrap())
                            ),
                            Err(_) => String::new(),
                        }
                    }
                    Err(_) => String::new(),
                };

                let mut req = client.get(&shard.url);
                if !auth_header.is_empty() {
                    req = req.header("Authorization", &auth_header);
                }
                let mut res = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))).await;
                        return;
                    }
                };

                // Fallback to unauthenticated GET if server rejects auth
                if res.status() == 401 || res.status() == 403 {
                    res = match client.get(&shard.url).send().await {
                        Ok(r) => r,
                        Err(e) => {
                            let _ = tx.send(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))).await;
                            return;
                        }
                    };
                }

                if !res.status().is_success() {
                    let _ = tx.send(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("HTTP download failed: {}", res.status())
                    ))).await;
                    return;
                }

                let mut received_bytes = 0u64;
                loop {
                    match res.chunk().await {
                        Ok(Some(chunk)) => {
                            if !chunk.is_empty() {
                                received_bytes += chunk.len() as u64;
                                if tx.send(Ok(chunk)).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Ok(None) => {
                            if received_bytes < shard.size {
                                let _ = tx.send(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    format!("shard truncated: received {} of {} bytes — url: {}", received_bytes, shard.size, shard.url),
                                ))).await;
                            }
                            break;
                        }
                        Err(e) => {
                            let _ = tx.send(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("shard download error: {e} — url: {}", shard.url),
                            ))).await;
                            return;
                        }
                    }
                }
            }
        });
        Self { rx, buffer: Bytes::new(), pos: 0 }
    }
}

impl AsyncRead for HttpShardChain {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buffer.len() {
            let avail = (self.buffer.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.buffer[self.pos..self.pos + avail]);
            self.pos += avail;
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut self.rx).poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                self.buffer = data;
                self.pos = 0;
                let avail = self.buffer.len().min(buf.remaining());
                buf.put_slice(&self.buffer[..avail]);
                self.pos = avail;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct ProgressRead<R> {
    inner: R,
    pb: ProgressBar,
    tx: Option<ProgressTx>,
    total: u64,
    last_reported: u64,
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressRead<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                self.pb.inc(n as u64);
                let pos = self.pb.position();
                if pos - self.last_reported >= 65536 {
                    self.last_reported = pos;
                    if let Some(tx) = &self.tx { let _ = tx.send((pos, self.total)); }
                }
            }
        }
        result
    }
}

struct ProgressWrite<W> {
    inner: W,
    pb: ProgressBar,
    tx: Option<ProgressTx>,
    total: u64,
    last_reported: u64,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ProgressWrite<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.pb.inc(*n as u64);
            let pos = self.pb.position();
            if pos - self.last_reported >= 65536 {
                self.last_reported = pos;
                if let Some(tx) = &self.tx { let _ = tx.send((pos, self.total)); }
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
