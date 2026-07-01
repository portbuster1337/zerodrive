use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce, Payload},
    Aes256Gcm, Key,
};
use anyhow::{bail, Result};
use bytes::Bytes;
use futures_core::stream::Stream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::io::StreamReader;
use iroh_io::AsyncSliceReader;
use zeroize::Zeroize;

/// Encrypted container format:
///   magic "ZD3\n" (4 bytes)
///   nonce_prefix (8 bytes)
///   For each chunk:
///     chunk_size: u32 big-endian (ciphertext + tag, max CHUNK_SIZE + 16)
///     ciphertext + gcm_tag
///   final zero-length chunk terminator (u32 BE = 0) — enables truncation detection
///
/// AES-256-GCM nonce for chunk i: nonce_prefix || u32_be(i)
/// Supports up to ~4 billion chunks (~4 PiB) without nonce reuse.
const MAGIC: &[u8] = b"ZD3\n";
const CHUNK_SIZE: usize = 1_048_576; // 1 MiB
const NONCE_PREFIX_LEN: usize = 8;
const TAG_LEN: usize = 16;
const MAX_CHUNK_CIPHER: usize = CHUNK_SIZE + TAG_LEN;

/// Encrypt a reader chunk-by-chunk to a writer.
pub async fn encrypt_stream<R, W>(mut reader: R, writer: &mut W, key: &[u8; 32]) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom::getrandom(&mut nonce_prefix)?;

    writer.write_all(MAGIC).await?;
    writer.write_all(&nonce_prefix).await?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_nonce = [0u8; 12];
    let mut chunk_idx: u32 = 0;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        chunk_nonce[..NONCE_PREFIX_LEN].copy_from_slice(&nonce_prefix);
        chunk_nonce[NONCE_PREFIX_LEN..].copy_from_slice(&chunk_idx.to_be_bytes());
        let nonce = Nonce::<Aes256Gcm>::from_slice(&chunk_nonce);

        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: &buf[..n], aad: MAGIC })
            .map_err(|e| anyhow::anyhow!("encrypt error: {e}"))?;

        let chunk_len = ciphertext.len() as u32;
        writer.write_all(&chunk_len.to_be_bytes()).await?;
        writer.write_all(&ciphertext).await?;

        chunk_idx = chunk_idx.checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("chunk index overflow (>4 billion chunks)"))?;
    }
    // Write zero-length terminator for truncation detection
    writer.write_all(&0u32.to_be_bytes()).await?;
    writer.flush().await?;
    nonce_prefix.zeroize();
    buf.zeroize();
    Ok(())
}

/// Decrypt a reader chunk-by-chunk to a writer.
pub async fn decrypt_stream<R, W>(mut reader: R, writer: &mut W, key: &[u8; 32]) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut magic = [0u8; MAGIC.len()];
    reader.read_exact(&mut magic).await?;
    if magic != *MAGIC {
        bail!("invalid magic bytes");
    }
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    reader.read_exact(&mut nonce_prefix).await?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut len_buf = [0u8; 4];
    let mut chunk_nonce = [0u8; 12];
    let mut chunk_idx: u32 = 0;

    loop {
        reader.read_exact(&mut len_buf).await?;
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        if chunk_len == 0 {
            // Zero-length terminator confirms clean end of stream
            break;
        }
        if chunk_len > MAX_CHUNK_CIPHER {
            bail!("chunk too large: {chunk_len}");
        }

        let mut ciphertext = vec![0u8; chunk_len];
        reader.read_exact(&mut ciphertext).await?;

        chunk_nonce[..NONCE_PREFIX_LEN].copy_from_slice(&nonce_prefix);
        chunk_nonce[NONCE_PREFIX_LEN..].copy_from_slice(&chunk_idx.to_be_bytes());
        let nonce = Nonce::<Aes256Gcm>::from_slice(&chunk_nonce);

        let plaintext = cipher
            .decrypt(nonce, Payload { msg: &ciphertext, aad: MAGIC })
            .map_err(|e| anyhow::anyhow!("decrypt error at chunk {chunk_idx}: {e}"))?;

        writer.write_all(&plaintext).await?;
        chunk_idx += 1;
    }
    writer.flush().await?;
    Ok(())
}

/// Decrypt an AsyncSliceReader (offset-based) chunk-by-chunk to a writer.
#[allow(dead_code)]
pub async fn decrypt_slice_to_writer<R: AsyncSliceReader + Unpin>(
    reader: &mut R,
    writer: &mut (impl AsyncWrite + Unpin),
    key: &[u8; 32],
) -> Result<()> {
    let mut offset = 0u64;

    let magic = reader.read_exact_at(offset, MAGIC.len()).await?;
    offset += MAGIC.len() as u64;
    if &magic[..] != MAGIC {
        bail!("invalid magic bytes");
    }

    let nonce_prefix = reader.read_exact_at(offset, NONCE_PREFIX_LEN).await?;
    offset += NONCE_PREFIX_LEN as u64;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut chunk_nonce = [0u8; 12];
    let mut idx: u32 = 0;

    loop {
        let len_bytes = reader.read_exact_at(offset, 4).await?;
        offset += 4;
        let chunk_len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if chunk_len == 0 {
            // Zero-length terminator confirms clean end of stream
            break;
        }
        if chunk_len > MAX_CHUNK_CIPHER {
            bail!("chunk too large: {chunk_len}");
        }

        let ciphertext = reader.read_exact_at(offset, chunk_len).await?;
        offset += chunk_len as u64;

        chunk_nonce[..NONCE_PREFIX_LEN].copy_from_slice(&nonce_prefix);
        chunk_nonce[NONCE_PREFIX_LEN..].copy_from_slice(&idx.to_be_bytes());
        let nonce = Nonce::<Aes256Gcm>::from_slice(&chunk_nonce);

        let plaintext = cipher
            .decrypt(nonce, Payload { msg: &ciphertext, aad: MAGIC })
            .map_err(|e| anyhow::anyhow!("decrypt error at chunk {idx}: {e}"))?;

        writer.write_all(&plaintext).await?;
        idx += 1;
    }
    writer.flush().await?;
    Ok(())
}

// ── Channel-based AsyncRead wrapper for encryption ──

async fn encrypt_to_channel<R: AsyncRead + Unpin>(
    mut inner: R,
    tx: mpsc::Sender<std::io::Result<Bytes>>,
    key: &[u8; 32],
) {
    let send = |res: std::io::Result<Bytes>| async {
        if tx.send(res).await.is_err() {
            return false;
        }
        true
    };

    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    if getrandom::getrandom(&mut nonce_prefix).is_err() {
        let _ = send(Err(std::io::Error::other("rng failure"))).await;
        return;
    }

    let mut header = Vec::with_capacity(MAGIC.len() + NONCE_PREFIX_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&nonce_prefix);
    if !send(Ok(Bytes::from(header))).await {
        return;
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut chunk_nonce = [0u8; 12];
    let mut idx: u32 = 0;

    loop {
        let n = match inner.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                let _ = send(Err(e)).await;
                return;
            }
        };

        chunk_nonce[..NONCE_PREFIX_LEN].copy_from_slice(&nonce_prefix);
        chunk_nonce[NONCE_PREFIX_LEN..].copy_from_slice(&idx.to_be_bytes());
        let nonce = Nonce::<Aes256Gcm>::from_slice(&chunk_nonce);

        let ciphertext = match cipher.encrypt(nonce, Payload { msg: &buf[..n], aad: MAGIC }) {
            Ok(c) => c,
            Err(e) => {
                let _ = send(Err(std::io::Error::other(format!("encrypt: {e}")))).await;
                return;
            }
        };

        let mut chunk_out = Vec::with_capacity(4 + ciphertext.len());
        chunk_out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        chunk_out.extend_from_slice(&ciphertext);

        if !send(Ok(Bytes::from(chunk_out))).await {
            return;
        }
        idx = match idx.checked_add(1) {
            Some(v) => v,
            None => {
                let _ = send(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk index overflow (>4 billion chunks)",
                ))).await;
                return;
            }
        };
    }
    // Zero-length terminator
    let _ = send(Ok(Bytes::from(0u32.to_be_bytes().to_vec()))).await;
}

// ── Channel-based AsyncRead wrapper for encryption ──

struct ChanStream {
    rx: mpsc::Receiver<std::io::Result<Bytes>>,
}

impl Stream for ChanStream {
    type Item = std::io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.rx).poll_recv(cx)
    }
}

/// AsyncRead wrapper that encrypts data on-the-fly via a background task.
pub struct EncryptingReader {
    inner: StreamReader<ChanStream, Bytes>,
    handle: tokio::task::JoinHandle<()>,
}

impl EncryptingReader {
    pub fn new<R: AsyncRead + Unpin + Send + 'static>(inner: R, key: &[u8; 32]) -> Self {
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(16);
        let key_arr = *key;
        let handle = tokio::spawn(async move {
            encrypt_to_channel(inner, tx, &key_arr).await;
        });
        Self { inner: StreamReader::new(ChanStream { rx }), handle }
    }
}

impl Drop for EncryptingReader {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl AsyncRead for EncryptingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// ── Channel-based AsyncRead wrapper for decryption ──

#[allow(dead_code)]
async fn decrypt_to_channel<R: AsyncRead + Unpin>(
    mut inner: R,
    tx: mpsc::Sender<std::io::Result<Bytes>>,
    key: &[u8; 32],
) {
    let send = |res: std::io::Result<Bytes>| async {
        if tx.send(res).await.is_err() {
            return false;
        }
        true
    };

    let mut magic = [0u8; MAGIC.len()];
    if let Err(e) = inner.read_exact(&mut magic).await {
        let _ = send(Err(e)).await;
        return;
    }
    if magic != MAGIC {
        let _ = send(Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid magic",
        )))
        .await;
        return;
    }

    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    if let Err(e) = inner.read_exact(&mut nonce_prefix).await {
        let _ = send(Err(e)).await;
        return;
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut len_buf = [0u8; 4];
    let mut chunk_nonce = [0u8; 12];
    let mut idx: u32 = 0;

    loop {
        if let Err(e) = inner.read_exact(&mut len_buf).await {
            let _ = send(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("truncated stream (missing terminator): {e}"),
            )))
            .await;
            return;
        }
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        if chunk_len == 0 {
            break;
        }
        if chunk_len > MAX_CHUNK_CIPHER {
            let _ = send(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("chunk too large: {chunk_len}"),
            )))
            .await;
            return;
        }

        let mut ciphertext = vec![0u8; chunk_len];
        if let Err(e) = inner.read_exact(&mut ciphertext).await {
            let _ = send(Err(e)).await;
            return;
        }

        chunk_nonce[..NONCE_PREFIX_LEN].copy_from_slice(&nonce_prefix);
        chunk_nonce[NONCE_PREFIX_LEN..].copy_from_slice(&idx.to_be_bytes());
        let nonce = Nonce::<Aes256Gcm>::from_slice(&chunk_nonce);

        match cipher.decrypt(nonce, Payload { msg: &ciphertext, aad: MAGIC }) {
            Ok(plaintext) => {
                if !send(Ok(Bytes::from(plaintext))).await {
                    return;
                }
            }
            Err(e) => {
                let _ = send(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("decrypt error at chunk {idx}: {e}"),
                )))
                .await;
                return;
            }
        }
        idx += 1;
    }
}

/// AsyncRead wrapper that decrypts data on-the-fly via a background task.
#[allow(dead_code)]
pub struct DecryptingReader {
    inner: StreamReader<ChanStream, Bytes>,
    handle: tokio::task::JoinHandle<()>,
}

impl DecryptingReader {
    #[allow(dead_code)]
    pub fn new<R: AsyncRead + Unpin + Send + 'static>(inner: R, key: &[u8; 32]) -> Self {
        let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(16);
        let key_arr = *key;
        let handle = tokio::spawn(async move {
            decrypt_to_channel(inner, tx, &key_arr).await;
        });
        Self { inner: StreamReader::new(ChanStream { rx }), handle }
    }
}

impl Drop for DecryptingReader {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl AsyncRead for DecryptingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_decrypt_truncated_stream() {
        let key = [0xABu8; 32];
        let data = b"Streaming truncation test data";

        let mut ct = Vec::new();
        let r = std::io::Cursor::new(data.to_vec());
        let mut w = tokio::io::BufWriter::new(&mut ct);
        encrypt_stream(tokio::io::BufReader::new(r), &mut w, &key).await.unwrap();
        drop(w);

        // Remove the last 4 bytes (the zero-length terminator)
        ct.truncate(ct.len() - 4);

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        let result = decrypt_stream(r, &mut w, &key).await;

        assert!(result.is_err(), "Decryption of truncated stream should fail");
    }

    #[tokio::test]
    async fn test_decrypt_invalid_magic() {
        let key = [0xABu8; 32];
        let mut ct = b"WRONG_MAGIC".to_vec();
        ct.extend_from_slice(&[0u8; 20]);

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        let result = decrypt_stream(r, &mut w, &key).await;

        assert!(result.is_err(), "Decryption with invalid magic should fail");
        assert!(result.unwrap_err().to_string().contains("invalid magic bytes"));
    }

    #[tokio::test]
    async fn test_decrypt_wrong_key() {
        let key1 = [0xABu8; 32];
        let key2 = [0xCDu8; 32];
        let data = b"Secret data";

        let mut ct = Vec::new();
        let r = std::io::Cursor::new(data.to_vec());
        let mut w = tokio::io::BufWriter::new(&mut ct);
        encrypt_stream(tokio::io::BufReader::new(r), &mut w, &key1).await.unwrap();
        drop(w);

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        let result = decrypt_stream(r, &mut w, &key2).await;

        assert!(result.is_err(), "Decryption with wrong key should fail");
        assert!(result.unwrap_err().to_string().contains("decrypt error at chunk 0"));
    }

    #[tokio::test]
    async fn test_decrypt_corrupted_chunk() {
        let key = [0xABu8; 32];
        let data = b"Corruption test data";

        let mut ct = Vec::new();
        let r = std::io::Cursor::new(data.to_vec());
        let mut w = tokio::io::BufWriter::new(&mut ct);
        encrypt_stream(tokio::io::BufReader::new(r), &mut w, &key).await.unwrap();
        drop(w);

        // Corrupt a byte in the middle of the ciphertext (skip magic + nonce + length prefix)
        let corrupt_idx = 4 + 8 + 4 + 2;
        ct[corrupt_idx] ^= 0xFF;

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        let result = decrypt_stream(r, &mut w, &key).await;

        assert!(result.is_err(), "Decryption of corrupted chunk should fail");
    }

    #[tokio::test]
    async fn test_roundtrip() {
        let key = [0xABu8; 32];
        let data = b"Hello, zerodrive!";

        let mut ct = Vec::new();
        let r = std::io::Cursor::new(data.to_vec());
        let mut w = tokio::io::BufWriter::new(&mut ct);
        encrypt_stream(tokio::io::BufReader::new(r), &mut w, &key).await.unwrap();
        drop(w);

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        decrypt_stream(r, &mut w, &key).await.unwrap();
        drop(w);

        assert_eq!(&pt, data);
    }

    #[tokio::test]
    async fn test_large_data() {
        let key = [0x99u8; 32];
        let data = vec![0x42u8; 3_000_000];

        let mut ct = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(data.clone()));
        let mut w = tokio::io::BufWriter::new(&mut ct);
        encrypt_stream(r, &mut w, &key).await.unwrap();
        drop(w);

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        decrypt_stream(r, &mut w, &key).await.unwrap();
        drop(w);

        assert_eq!(pt.len(), data.len());
        assert_eq!(pt, data);
    }

    #[tokio::test]
    async fn test_encrypting_reader() {
        let key = [0x42u8; 32];
        let data = b"Test data for EncryptingReader";

        let inner = tokio::io::BufReader::new(std::io::Cursor::new(data.to_vec()));
        let mut reader = EncryptingReader::new(inner, &key);
        let mut ct = Vec::new();
        tokio::io::copy(&mut reader, &mut ct).await.unwrap();

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        decrypt_stream(r, &mut w, &key).await.unwrap();
        drop(w);
        assert_eq!(&pt, data);
    }

    #[tokio::test]
    async fn test_encrypting_reader_large() {
        let key = [0x42u8; 32];
        let data: Vec<u8> = (0..3_000_000).map(|i| (i % 251) as u8).collect();

        let inner = tokio::io::BufReader::new(std::io::Cursor::new(data.clone()));
        let mut reader = EncryptingReader::new(inner, &key);
        let mut ct = Vec::new();
        tokio::io::copy(&mut reader, &mut ct).await.unwrap();

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        decrypt_stream(r, &mut w, &key).await.unwrap();
        drop(w);
        assert_eq!(pt.len(), data.len());
        assert_eq!(pt, data);
    }

    #[tokio::test]
    async fn test_decrypting_reader_multi_chunk() {
        let key = [0xcd; 32];
        let data: Vec<u8> = (0..2_200_000).map(|i| (i % 251) as u8).collect();

        let mut encrypted = Vec::new();
        {
            let r = std::io::Cursor::new(data.clone());
            let reader = tokio::io::BufReader::new(r);
            let mut writer = tokio::io::BufWriter::new(&mut encrypted);
            encrypt_stream(reader, &mut writer, &key).await.unwrap();
            writer.flush().await.unwrap();
        }

        let mut decrypted = Vec::new();
        {
            let cursor = std::io::Cursor::new(encrypted);
            let mut decrypting = DecryptingReader::new(cursor, &key);
            tokio::io::copy(&mut decrypting, &mut decrypted).await.unwrap();
        }
        assert_eq!(decrypted.len(), data.len(), "size mismatch");
        assert_eq!(decrypted, data, "data mismatch");
    }

    #[tokio::test]
    async fn test_encrypting_reader_with_file() {
        let dir = std::env::temp_dir().join(format!("zd-crypto-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        let data: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let key = [0xab; 32];
        let file = tokio::fs::File::open(&src).await.unwrap();
        let mut reader = EncryptingReader::new(file, &key);
        let mut ct = Vec::new();
        tokio::io::copy(&mut reader, &mut ct).await.unwrap();

        let mut pt = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(ct));
        let mut w = tokio::io::BufWriter::new(&mut pt);
        decrypt_stream(r, &mut w, &key).await.unwrap();
        drop(w);
        assert_eq!(pt.len(), data.len());
        assert_eq!(pt, data);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_decrypting_reader_with_file() {
        let dir = std::env::temp_dir().join(format!("zd-crypto-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        let data: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let key = [0xbc; 32];

        // Encrypt with encrypt_stream to a file
        let encrypted_path = dir.join("encrypted.bin");
        {
            let f = tokio::fs::File::open(&src).await.unwrap();
            let reader = tokio::io::BufReader::new(f);
            let out = tokio::fs::File::create(&encrypted_path).await.unwrap();
            let mut writer = tokio::io::BufWriter::new(out);
            encrypt_stream(reader, &mut writer, &key).await.unwrap();
            writer.flush().await.unwrap();
        }

        // Decrypt via DecryptingReader from the file
        let ef = tokio::fs::File::open(&encrypted_path).await.unwrap();
        let mut decrypting = DecryptingReader::new(ef, &key);
        let mut pt = Vec::new();
        tokio::io::copy(&mut decrypting, &mut pt).await.unwrap();
        assert_eq!(pt.len(), data.len());
        assert_eq!(pt, data);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
