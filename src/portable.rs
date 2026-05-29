//! Portable vault bundles — the core of `svault export` / `svault import`.
//!
//! A bundle is a single JSON file holding hex-encoded copies of a vault's
//! files (`meta.yaml`, `vault.enc`, and `recovery.enc` if present) plus a
//! `sha256` over them for corruption detection. Every byte is already
//! encrypted or HMAC-signed, so the bundle is safe at rest. These functions
//! have no I/O side effects beyond the explicit reads/writes and never print
//! or exit, so both the CLI and the TUI can call them.

use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::path::Path;

pub const EXPORT_VERSION: u32 = 1;
/// Files copied into a bundle. `recovery.enc` is optional; the rest are required.
const EXPORT_FILES: &[&str] = &["meta.yaml", "vault.enc", "recovery.enc"];

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ExportBundle {
    pub svault_export: u32,
    pub name: String,
    pub storage: String,
    pub sha256: String,
    pub files: BTreeMap<String, String>,
}

/// Hash the files map deterministically (sorted keys) for corruption detection.
fn bundle_digest(files: &BTreeMap<String, String>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for (k, v) in files {
        h.update(k.as_bytes());
        h.update([0u8]);
        h.update(v.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

/// Build a bundle for the vault at `vault_dir`. `name`/`storage` come from the
/// (unverified) meta the caller already read. Returns pretty-printed JSON.
pub fn build_bundle(vault_dir: &Path, name: &str, storage: &str) -> Result<String> {
    let mut files = BTreeMap::new();
    for fname in EXPORT_FILES {
        let path = vault_dir.join(fname);
        if path.exists() {
            files.insert(fname.to_string(), hex::encode(std::fs::read(&path)?));
        } else if *fname != "recovery.enc" {
            return Err(anyhow!("vault is missing {fname} — cannot export"));
        }
    }

    let bundle = ExportBundle {
        svault_export: EXPORT_VERSION,
        name: name.to_string(),
        storage: storage.to_string(),
        sha256: bundle_digest(&files),
        files,
    };
    Ok(serde_json::to_string_pretty(&bundle)?)
}

/// Parse and validate a bundle from JSON: version + checksum.
pub fn parse_bundle(raw: &str) -> Result<ExportBundle> {
    let bundle: ExportBundle =
        serde_json::from_str(raw).map_err(|_| anyhow!("not a valid svault export"))?;
    if bundle.svault_export != EXPORT_VERSION {
        return Err(anyhow!(
            "unsupported export version {}",
            bundle.svault_export
        ));
    }
    if bundle_digest(&bundle.files) != bundle.sha256 {
        return Err(anyhow!("checksum mismatch — the bundle is corrupted"));
    }
    Ok(bundle)
}

/// Write a validated bundle into `svault_base/<name>/`. Refuses to overwrite an
/// existing vault. Returns the imported vault's name.
pub fn import_bundle(raw: &str, svault_base: &Path) -> Result<String> {
    let bundle = parse_bundle(raw)?;
    let target = svault_base.join(&bundle.name);
    if target.exists() {
        return Err(anyhow!(
            "a vault named '{}' already exists — names must be unique",
            bundle.name
        ));
    }

    std::fs::create_dir_all(&target)?;
    std::fs::write(target.join(".gitignore"), ".session\naudit.log\n")?;
    for (name, hex_content) in &bundle.files {
        let bytes = hex::decode(hex_content)
            .map_err(|_| anyhow!("bundle file '{name}' is not valid hex"))?;
        std::fs::write(target.join(name), bytes)?;
    }
    Ok(bundle.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_files() -> BTreeMap<String, String> {
        let mut f = BTreeMap::new();
        f.insert("meta.yaml".into(), hex::encode(b"name: v"));
        f.insert("vault.enc".into(), hex::encode([1u8, 2, 3, 4]));
        f
    }

    #[test]
    fn digest_is_deterministic() {
        let f = sample_files();
        assert_eq!(bundle_digest(&f), bundle_digest(&f.clone()));
    }

    #[test]
    fn digest_changes_when_a_file_changes() {
        let f = sample_files();
        let before = bundle_digest(&f);
        let mut tampered = f.clone();
        tampered.insert("vault.enc".into(), hex::encode([9u8, 9, 9, 9]));
        assert_ne!(before, bundle_digest(&tampered));
    }

    #[test]
    fn parse_rejects_a_tampered_bundle() {
        let files = sample_files();
        let mut bundle = ExportBundle {
            svault_export: EXPORT_VERSION,
            name: "v".into(),
            storage: "local".into(),
            sha256: bundle_digest(&files),
            files,
        };
        // Corrupt a file without updating the checksum.
        bundle
            .files
            .insert("vault.enc".into(), hex::encode([0u8; 4]));
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(parse_bundle(&json).is_err());
    }

    #[test]
    fn parse_accepts_a_clean_bundle() {
        let files = sample_files();
        let bundle = ExportBundle {
            svault_export: EXPORT_VERSION,
            name: "v".into(),
            storage: "local".into(),
            sha256: bundle_digest(&files),
            files,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        assert_eq!(parse_bundle(&json).unwrap().name, "v");
    }
}
