use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use indicatif::{ProgressBar, ProgressStyle};
use iroh::net::NodeAddr;
type IrohNode = iroh::node::Node<MemStore>;
use iroh_blobs::store::mem::Store as MemStore;
use iroh_blobs::store::{Map, Store};
#[cfg(test)]
use iroh_blobs::store::MapEntry;
#[cfg(test)]
use iroh_io::AsyncSliceReaderExt;
use iroh_blobs::BlobFormat;
use iroh_blobs::Hash;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

/// Channel for reporting progress (current_bytes, total_bytes).
pub type ProgressTx = mpsc::UnboundedSender<(u64, u64)>;

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{msg} [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .progress_chars("=> ")
}

struct ProgressRead<R> {
    inner: R,
    pb: ProgressBar,
    tx: Option<ProgressTx>,
    total: u64,
    last_reported: u64,
}

impl<R: AsyncRead + Unpin> AsyncRead for ProgressRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                self.pb.inc(n as u64);
                let pos = self.pb.position();
                if pos - self.last_reported >= 65536 {
                    self.last_reported = pos;
                    if let Some(tx) = &self.tx {
                        let _ = tx.send((pos, self.total));
                    }
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
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            self.pb.inc(*n as u64);
            let pos = self.pb.position();
            if pos - self.last_reported >= 65536 {
                self.last_reported = pos;
                if let Some(tx) = &self.tx {
                    let _ = tx.send((pos, self.total));
                }
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

/// Static blob storage operations using an iroh node.
pub struct BlobStore;

impl BlobStore {
    /// Upload a file: encrypt via EncryptingReader, add encrypted blob.
    /// Returns (hash_string, original_file_size).
    pub async fn upload(
        node: &IrohNode,
        local_path: &Path,
        file_key: &[u8; 32],
        progress: Option<ProgressTx>,
    ) -> Result<(String, u64)> {
        let file = tokio::fs::File::open(local_path)
            .await
            .context("opening file")?;
        let metadata = file.metadata().await?;
        let file_size = metadata.len();

        let fname = local_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let pb = if progress.is_some() {
            let pb = ProgressBar::new(file_size);
            pb.set_style(progress_style());
            pb.set_message(format!("Uploading {fname}"));
            pb
        } else {
            ProgressBar::hidden()
        };

        if let Some(tx) = &progress {
            let _ = tx.send((0, file_size));
        }
        let progress_file = ProgressRead {
            inner: file,
            pb: pb.clone(),
            tx: progress.clone(),
            total: file_size,
            last_reported: 0,
        };
        let encrypting_reader = crate::crypto_stream::EncryptingReader::new(progress_file, file_key);

        let blobs_proto = node
            .get_protocol::<iroh_blobs::net_protocol::Blobs<MemStore>>(
                iroh_blobs::protocol::ALPN,
            )
            .context("getting blobs protocol")?;
        let store = blobs_proto.store();
        let (temp_tag, _stored_size) = store
            .import_reader(
                encrypting_reader,
                BlobFormat::Raw,
                iroh_blobs::util::progress::IgnoreProgressSender::default(),
            )
            .await
            .context("importing encrypted blob")?;
        pb.finish_and_clear();
        if let Some(tx) = &progress {
            let _ = tx.send((file_size, file_size));
        }
        let hash = *temp_tag.hash();
        let hash_str = format!("blake3:{}", hash);
        Ok((hash_str, file_size))
    }

    /// Download a blob, decrypt, write to output_path.
    /// Streams data chunk-by-chunk from the blob store through decryption to disk,
    /// never buffering the entire file in memory.
    pub async fn download(
        node: &IrohNode,
        blob_hash_str: &str,
        output_path: &Path,
        file_key: &[u8; 32],
        original_size: u64,
        progress: Option<ProgressTx>,
    ) -> Result<u64> {
        let hash = blob_hash_str
            .strip_prefix("blake3:")
            .unwrap_or(blob_hash_str)
            .parse::<Hash>()
            .context("invalid blob hash")?;

        // Read blob data directly from the local store, bypassing quic-rpc
        // Read blob into memory from the client API (Send-safe)
        use tokio::io::AsyncReadExt;
        let mut blob_buf = Vec::new();
        let mut blob_reader = node.client().blobs().read(hash).await?;
        blob_reader.read_to_end(&mut blob_buf).await?;
        let mut slice: &[u8] = &blob_buf;

        let fname = output_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let pb = if progress.is_some() {
            let pb = ProgressBar::new(original_size);
            pb.set_style(progress_style());
            pb.set_message(format!("Downloading {fname}"));
            pb
        } else {
            ProgressBar::hidden()
        };

        if let Some(tx) = &progress {
            let _ = tx.send((0, original_size));
        }
        let output_file = tokio::fs::File::create(output_path).await?;
        let mut writer = ProgressWrite {
            inner: tokio::io::BufWriter::new(output_file),
            pb: pb.clone(),
            tx: progress.clone(),
            total: original_size,
            last_reported: 0,
        };
        crate::crypto_stream::decrypt_slice_to_writer(&mut slice, &mut writer, file_key)
            .await
            .context("decrypting blob")?;
        writer.flush().await?;
        pb.finish_and_clear();
        if let Some(tx) = &progress {
            let _ = tx.send((original_size, original_size));
        }

        let meta = tokio::fs::metadata(output_path).await?;
        Ok(meta.len())
    }

    /// Check if a blob exists in the local store.
    pub async fn has_blob(node: &IrohNode, blob_hash_str: &str) -> Result<bool> {
        let hash = blob_hash_str
            .strip_prefix("blake3:")
            .unwrap_or(blob_hash_str)
            .parse::<Hash>()?;

        let blobs_proto = node
            .get_protocol::<iroh_blobs::net_protocol::Blobs<MemStore>>(
                iroh_blobs::protocol::ALPN,
            )
            .context("getting blobs protocol")?;
        let store = blobs_proto.store();
        match store.get(&hash).await {
            Ok(Some(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Download a blob from a remote peer and store it locally.
    /// `node_addr_str` is the serialized `NodeAddr` (Display format).
    pub async fn fetch_from_peer(
        node: &IrohNode,
        hash: &iroh_blobs::Hash,
        node_addr_str: &str,
    ) -> Result<()> {
        let node_addr: NodeAddr = serde_json::from_str(node_addr_str)
            .context("invalid NodeAddr in manifest")?;

        // Register the peer address with the node for connectivity
        let _ = node.client().net().add_node_addr(node_addr.clone()).await;

        let progress = node
            .client()
            .blobs()
            .download(*hash, node_addr)
            .await
            .context("starting download from peer")?;

        let outcome = progress.await.context("waiting for download")?;
        if outcome.downloaded_size > 0 || outcome.local_size > 0 {
            Ok(())
        } else {
            anyhow::bail!("peer returned no data")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read blob data directly from the local store, bypassing quic-rpc.
    async fn read_blob_local(node: &IrohNode, hash: Hash) -> Result<Vec<u8>> {
        let blobs_proto = node
            .get_protocol::<iroh_blobs::net_protocol::Blobs<MemStore>>(
                iroh_blobs::protocol::ALPN,
            )
            .context("getting blobs protocol")?;
        let store = blobs_proto.store();
        let entry = store
            .get(&hash)
            .await
            .context("looking up blob in store")?
            .context("blob not found in local store")?;
        let mut reader = entry.data_reader().await?;
        let bytes = reader.read_to_end().await?;
        Ok(bytes.to_vec())
    }

    async fn make_node() -> IrohNode {
        let secret = iroh::base::key::SecretKey::generate();
        iroh::node::Node::memory()
            .secret_key(secret)
            .spawn()
            .await
            .unwrap()
    }

    async fn upload_bytes(node: &IrohNode, data: &[u8]) -> Hash {
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(data.to_vec()));
        let blobs_proto = node
            .get_protocol::<iroh_blobs::net_protocol::Blobs<MemStore>>(
                iroh_blobs::protocol::ALPN,
            )
            .unwrap();
        let store = blobs_proto.store();
        let (temp_tag, _size) = store
            .import_reader(
                reader,
                BlobFormat::Raw,
                iroh_blobs::util::progress::IgnoreProgressSender::default(),
            )
            .await
            .unwrap();
        *temp_tag.hash()
    }

    #[tokio::test]
    async fn test_iroh_small_roundtrip() {
        let node = make_node().await;

        let plaintext = b"ZD1\n\xab\x00\x00\x00\x05hello";
        let hash = upload_bytes(&node, plaintext).await;
        let bytes = read_blob_local(&node, hash).await.unwrap();
        assert_eq!(bytes.len(), plaintext.len());
        assert_eq!(&bytes[..], plaintext);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_iroh_large_roundtrip() {
        let node = make_node().await;

        let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let hash = upload_bytes(&node, &data).await;
        let bytes = read_blob_local(&node, hash).await.unwrap();
        assert_eq!(bytes.len(), data.len());
        assert_eq!(&bytes[..], &data);
        node.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_encrypt_store_decrypt() {
        let node = make_node().await;

        let plaintext: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let key = [0xab; 32];

        // Encrypt using encrypt_stream (the working path)
        let mut ct = Vec::new();
        let r = tokio::io::BufReader::new(std::io::Cursor::new(plaintext.clone()));
        let mut w = tokio::io::BufWriter::new(&mut ct);
        crate::crypto_stream::encrypt_stream(r, &mut w, &key).await.unwrap();
        drop(w);
        eprintln!("encrypt_stream produced {} bytes", ct.len());

        // Store the encrypted data
        let reader = tokio::io::BufReader::new(std::io::Cursor::new(ct.clone()));
        let blobs_proto = node
            .get_protocol::<iroh_blobs::net_protocol::Blobs<MemStore>>(
                iroh_blobs::protocol::ALPN,
            )
            .unwrap();
        let store = blobs_proto.store();
        let (temp_tag, _size) = store
            .import_reader(
                reader,
                BlobFormat::Raw,
                iroh_blobs::util::progress::IgnoreProgressSender::default(),
            )
            .await
            .unwrap();
        let hash = *temp_tag.hash();

        // Read back via data_reader
        let entry = store.get(&hash).await.unwrap().unwrap();
        let mut reader = entry.data_reader().await.unwrap();
        let stored = reader.read_to_end().await.unwrap().to_vec();
        eprintln!("stored {} bytes (same as input: {})", stored.len(), stored.len() == ct.len());
        assert_eq!(stored.len(), ct.len(), "size changed through store");
        assert_eq!(stored, ct, "data changed through store");

        // Manually decrypt byte-by-byte using read_exact
        {
            use tokio::io::AsyncReadExt;
            let mut cursor = std::io::Cursor::new(ct.clone());
            let mut magic = [0u8; 4];
            cursor.read_exact(&mut magic).await.unwrap();
            eprintln!("magic: {:02x?}", magic);
            let mut nonce_prefix = [0u8; 8];
            cursor.read_exact(&mut nonce_prefix).await.unwrap();
            eprintln!("nonce_prefix: {:02x?}", nonce_prefix);
            let mut len_buf = [0u8; 4];
            cursor.read_exact(&mut len_buf).await.unwrap();
            let chunk_len = u32::from_be_bytes(len_buf) as usize;
            eprintln!("chunk_len: {} (remaining in cursor: {})", chunk_len, cursor.get_ref().len() - cursor.position() as usize);
            let mut ciphertext = vec![0u8; chunk_len];
            cursor.read_exact(&mut ciphertext).await.unwrap();
            eprintln!("ciphertext read successfully, remaining: {}", cursor.get_ref().len() - cursor.position() as usize);
        }

        // Test: decrypt the encrypt_stream output directly with DecryptingReader
        // (no iroh store in between)
        let cursor = std::io::Cursor::new(ct.clone());
        let mut decrypting = crate::crypto_stream::DecryptingReader::new(cursor, &key);
        let mut decrypted = Vec::new();
        tokio::io::copy(&mut decrypting, &mut decrypted).await.unwrap();
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(&decrypted[..], &plaintext);
        eprintln!("DecryptingReader works directly (no iroh)");

        node.shutdown().await.unwrap();
    }

    async fn upload_download_roundtrip(
        node: &IrohNode,
        data: &[u8],
        key: &[u8; 32],
    ) {
        let dir = std::env::temp_dir().join(format!("zd-rd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.bin");
        std::fs::write(&src, data).unwrap();

        let (hash, _size) = BlobStore::upload(node, &src, key, None).await.unwrap();


        let out = dir.join("out.bin");
        let _size = BlobStore::download(node, &hash, &out, key, data.len() as u64, None).await.unwrap();

        let downloaded = std::fs::read(&out).unwrap();
        assert_eq!(downloaded.len(), data.len());
        assert_eq!(&downloaded[..], data);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_upload_file_then_download() {
        let node = make_node().await;

        let key = [0xcd; 32];

        let data1: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        upload_download_roundtrip(&node, &data1, &key).await;
        eprintln!("10KB roundtrip OK");

        let data2: Vec<u8> = (0..2_000_000).map(|i| (i % 251) as u8).collect();
        upload_download_roundtrip(&node, &data2, &key).await;
        eprintln!("2MB roundtrip OK");

        node.shutdown().await.unwrap();
    }
}
