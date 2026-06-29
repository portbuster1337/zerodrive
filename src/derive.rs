use anyhow::Result;
use bip32::XPrv;
use bip39::Mnemonic;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub nostr_secret_key: [u8; 32],
    pub iroh_secret_key_bytes: [u8; 32],
    pub manifest_key: [u8; 32],
    pub file_key: [u8; 32],
}

pub fn derive(mnemonic: &Mnemonic) -> Result<DerivedKeys> {
    let mut seed = mnemonic.to_seed("");
    let keys = derive_from_seed(&seed);

    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    seed.zeroize();

    Ok(keys)
}

fn derive_from_seed(seed: &[u8; 64]) -> DerivedKeys {
    // 1. Nostr key: BIP-32 m/44'/1237'/0'/0/0 (NIP-06)
    let path = "m/44'/1237'/0'/0/0".parse::<bip32::DerivationPath>()
        .expect("Hardcoded derivation path is valid");
    let xprv = XPrv::derive_from_path(seed, &path)
        .expect("BIP-32 derivation should never fail for valid path");
    let nostr_secret_key = xprv.private_key().to_bytes();

    // 2. Iroh key: HKDF-SHA256(seed, "zerodrive/iroh/v1")
    let iroh_secret_key_bytes = hkdf_extract(seed, b"zerodrive/iroh/v1");

    // 3. Manifest encryption key: HKDF-SHA256(seed, "zerodrive/manifest/v1")
    let manifest_key = hkdf_extract(seed, b"zerodrive/manifest/v1");

    // 4. File encryption key: HKDF-SHA256(seed, "zerodrive/files/v1")
    let file_key = hkdf_extract(seed, b"zerodrive/files/v1");

    DerivedKeys {
        nostr_secret_key: nostr_secret_key.into(),
        iroh_secret_key_bytes,
        manifest_key,
        file_key,
    }
}

fn hkdf_extract(seed: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand: 32 bytes is a valid output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_derivation() {
        let mnemonic = Mnemonic::parse_normalized(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();
        let a = derive(&mnemonic).unwrap();
        let b = derive(&mnemonic).unwrap();

        assert_eq!(a.nostr_secret_key, b.nostr_secret_key, "Nostr key must be deterministic");
        assert_eq!(a.iroh_secret_key_bytes, b.iroh_secret_key_bytes, "Iroh key must be deterministic");
        assert_eq!(a.manifest_key, b.manifest_key, "Manifest key must be deterministic");
        assert_eq!(a.file_key, b.file_key, "File key must be deterministic");
    }
}
