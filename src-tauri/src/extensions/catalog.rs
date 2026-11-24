//! Signed in-app extension catalog: fetch, Minisign verification, SQLite cache,
//! and staged download into `extensions_dir/.staging/` before install consent.

use super::manifest;
use super::registry::{self, ExtError, Inspection, Installed, BUILTIN_PREFIX, MAX_PACKAGE};
use crate::store::{now_ms, Store};
use minisign_verify::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

// PROVISIONAL: catalog endpoint and signing key until the catalog repository is published.
const DEFAULT_CATALOG_URL: &str = "https://extensions.linen.app/catalog/v1/catalog.json";
// PROVISIONAL: placeholder Minisign public key until the release signing key is provisioned.
const DEFAULT_CATALOG_PUBKEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

const SCHEMA_VERSION: u32 = 1;
const CACHE_TTL_MS: i64 = 24 * 60 * 60 * 1000;
const MAX_CATALOG_BYTES: u64 = 2 << 20;
const MAX_SIG_BYTES: u64 = 4 << 10;
const MAX_TEXT: usize = 200;
const MAX_REDIRECTS: usize = 3;
const CATALOG_TIMEOUT: Duration = Duration::from_secs(15);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);

const KEY_CACHE: &str = "extCatalogCache";
const KEY_ETAG: &str = "extCatalogEtag";
const KEY_FETCHED_AT: &str = "extCatalogFetchedAt";
const KEY_URL: &str = "extCatalogUrl";
const KEY_PUBKEY: &str = "extCatalogPubkey";
const STAGING_DIR: &str = ".staging";

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("catalog signature verification failed: {0}")]
    Verification(String),
    #[error("invalid catalog: {0}")]
    Invalid(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("package integrity check failed: {0}")]
    Integrity(String),
    #[error("extension not found in catalog: {0}")]
    NotFound(String),
    #[error("staged download not found or expired")]
    StagedNotFound,
    #[error(transparent)]
    Ext(#[from] ExtError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogCategory {
    Lookup,
    Theme,
    Export,
    Navigation,
    Utility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogDocument {
    pub schema_version: u32,
    pub generated_at: i64,
    pub entries: Vec<CatalogEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntry {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub publisher: String,
    pub homepage: String,
    pub category: CatalogCategory,
    pub version: String,
    pub engines_linen: String,
    pub download_url: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub optional_permissions: Vec<String>,
    #[serde(default)]
    pub contributes_summary: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum EntryInstallState {
    NotInstalled,
    InstalledCurrent,
    UpdateAvailable { installed_version: String },
    Incompatible { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEntryView {
    pub entry: CatalogEntry,
    pub state: EntryInstallState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogResponse {
    pub entries: Vec<CatalogEntryView>,
    pub fetched_at: i64,
    pub offline: bool,
    pub stale: bool,
}

#[derive(Debug, Clone)]
pub struct StagedDownload {
    pub id: String,
    pub version: String,
    pub path: PathBuf,
    pub inspection: Inspection,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedInspection {
    pub token: String,
    pub inspection: Inspection,
}

#[derive(Default)]
pub struct CatalogStaging(pub Mutex<HashMap<String, StagedDownload>>);

impl CatalogStaging {
    pub fn insert(&self, download: StagedDownload) -> StagedInspection {
        let token = uuid::Uuid::new_v4().to_string();
        let inspection = download.inspection.clone();
        self.0.lock().unwrap().insert(token.clone(), download);
        StagedInspection { token, inspection }
    }

    pub fn take(&self, token: &str) -> Option<StagedDownload> {
        self.0.lock().unwrap().remove(token)
    }

    pub fn discard(&self, token: &str) {
        if let Some(staged) = self.take(token) {
            let _ = std::fs::remove_file(&staged.path);
        }
    }
}

/// Remove any leftover staged downloads from a previous run.
pub fn cleanup_staging(extensions_dir: &Path) {
    let dir = extensions_dir.join(STAGING_DIR);
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(feature = "spikes")]
static SPIKE_OVERRIDE: std::sync::OnceLock<Mutex<Option<(String, String)>>> =
    std::sync::OnceLock::new();

#[cfg(feature = "spikes")]
pub fn set_spike_override(url: String, pubkey: String) {
    let lock = SPIKE_OVERRIDE.get_or_init(|| Mutex::new(None));
    *lock.lock().unwrap() = Some((url, pubkey));
}

pub fn catalog_url() -> String {
    #[cfg(feature = "spikes")]
    if let Some(lock) = SPIKE_OVERRIDE.get() {
        if let Some((url, _)) = lock.lock().unwrap().as_ref() {
            return url.clone();
        }
    }
    #[cfg(any(test, feature = "spikes"))]
    if let Ok(url) = std::env::var("LINEN_CATALOG_URL") {
        if !url.is_empty() {
            return url;
        }
    }
    DEFAULT_CATALOG_URL.to_string()
}

pub fn catalog_pubkey() -> String {
    #[cfg(feature = "spikes")]
    if let Some(lock) = SPIKE_OVERRIDE.get() {
        if let Some((_, key)) = lock.lock().unwrap().as_ref() {
            return key.clone();
        }
    }
    #[cfg(any(test, feature = "spikes"))]
    if let Ok(key) = std::env::var("LINEN_CATALOG_PUBKEY") {
        if !key.is_empty() {
            return key;
        }
    }
    DEFAULT_CATALOG_PUBKEY.to_string()
}

fn allowed_url(url: &str) -> bool {
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty() && !rest.starts_with('/');
    }
    #[cfg(any(test, feature = "spikes"))]
    if let Some(rest) = url.strip_prefix("http://127.0.0.1:") {
        return !rest.is_empty();
    }
    false
}

fn url_host(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(authority.to_ascii_lowercase())
}

fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_text(field: &str, value: &str) -> Result<(), CatalogError> {
    if value.trim().is_empty() {
        return Err(CatalogError::Invalid(format!("{field} is empty")));
    }
    if value.chars().count() > MAX_TEXT {
        return Err(CatalogError::Invalid(format!(
            "{field} exceeds {MAX_TEXT} characters"
        )));
    }
    Ok(())
}

/// Verify Minisign signature and validate the catalog document schema and every entry.
pub fn parse_and_verify(
    json_bytes: &[u8],
    sig_bytes: &[u8],
    pubkey: &str,
) -> Result<CatalogDocument, CatalogError> {
    let pk = PublicKey::from_base64(pubkey.trim())
        .map_err(|e| CatalogError::Verification(format!("invalid public key: {e}")))?;
    let sig_str = std::str::from_utf8(sig_bytes)
        .map_err(|_| CatalogError::Verification("signature is not UTF-8".into()))?;
    let sig = Signature::decode(sig_str)
        .map_err(|e| CatalogError::Verification(format!("malformed signature: {e}")))?;
    pk.verify(json_bytes, &sig, true)
        .map_err(|e| CatalogError::Verification(format!("signature mismatch: {e}")))?;

    let doc: CatalogDocument = serde_json::from_slice(json_bytes)
        .map_err(|e| CatalogError::Invalid(format!("malformed JSON: {e}")))?;
    if doc.schema_version != SCHEMA_VERSION {
        return Err(CatalogError::Invalid(format!(
            "unsupported schemaVersion {}",
            doc.schema_version
        )));
    }

    let mut seen_ids = HashSet::new();
    for entry in &doc.entries {
        if !super::valid_id(&entry.id) {
            return Err(CatalogError::Invalid(format!(
                "invalid extension id “{}”",
                entry.id
            )));
        }
        if entry.id.starts_with(BUILTIN_PREFIX) {
            return Err(CatalogError::Invalid(format!(
                "reserved built-in id “{}”",
                entry.id
            )));
        }
        if !seen_ids.insert(entry.id.as_str()) {
            return Err(CatalogError::Invalid(format!(
                "duplicate extension id “{}”",
                entry.id
            )));
        }
        validate_text("name", &entry.name)?;
        validate_text("summary", &entry.summary)?;
        semver::Version::parse(&entry.version).map_err(|_| {
            CatalogError::Invalid(format!(
                "entry “{}” has invalid version “{}”",
                entry.id, entry.version
            ))
        })?;
        semver::VersionReq::parse(&entry.engines_linen).map_err(|_| {
            CatalogError::Invalid(format!(
                "entry “{}” has invalid enginesLinen “{}”",
                entry.id, entry.engines_linen
            ))
        })?;
        if !allowed_url(&entry.homepage) || url_host(&entry.homepage).is_none() {
            return Err(CatalogError::Invalid(format!(
                "entry “{}” homepage must be a valid https:// URL",
                entry.id
            )));
        }
        if !allowed_url(&entry.download_url) || url_host(&entry.download_url).is_none() {
            return Err(CatalogError::Invalid(format!(
                "entry “{}” downloadUrl must be a valid https:// URL",
                entry.id
            )));
        }
        if !valid_sha256(&entry.sha256) {
            return Err(CatalogError::Invalid(format!(
                "entry “{}” sha256 must be 64 lowercase hex characters",
                entry.id
            )));
        }
        if entry.size_bytes == 0 || entry.size_bytes > MAX_PACKAGE {
            return Err(CatalogError::Invalid(format!(
                "entry “{}” sizeBytes ({}) out of range",
                entry.id, entry.size_bytes
            )));
        }
    }

    Ok(doc)
}

/// Resolve a catalog entry's install state against this build's API version and installed extensions.
pub fn resolve_entry_state(entry: &CatalogEntry, installed: &[Installed]) -> EntryInstallState {
    if let Some(reason) = manifest::incompatibility_for(&entry.engines_linen) {
        return EntryInstallState::Incompatible { reason };
    }
    let Some(existing) = installed.iter().find(|x| x.manifest.id == entry.id) else {
        return EntryInstallState::NotInstalled;
    };
    let catalog_ver = semver::Version::parse(&entry.version);
    let installed_ver = semver::Version::parse(&existing.manifest.version);
    match (catalog_ver, installed_ver) {
        (Ok(cat), Ok(inst)) if cat > inst => EntryInstallState::UpdateAvailable {
            installed_version: existing.manifest.version.clone(),
        },
        _ => EntryInstallState::InstalledCurrent,
    }
}

fn build_views(doc: CatalogDocument, installed: &[Installed]) -> Vec<CatalogEntryView> {
    doc.entries
        .into_iter()
        .map(|entry| {
            let state = resolve_entry_state(&entry, installed);
            CatalogEntryView { entry, state }
        })
        .collect()
}

/// Cached inputs needed before doing network I/O so we don't hold the store lock across HTTP calls.
pub struct CachedCatalog {
    pub doc: Option<CatalogDocument>,
    pub etag: Option<String>,
    pub fetched_at: Option<i64>,
}

pub fn read_cache(store: &Store, url: &str, pubkey: &str) -> Result<CachedCatalog, CatalogError> {
    let stored_url = store.setting(KEY_URL)?;
    let stored_pubkey = store.setting(KEY_PUBKEY)?;
    if stored_url.as_deref() != Some(url) || stored_pubkey.as_deref() != Some(pubkey) {
        return Ok(CachedCatalog {
            doc: None,
            etag: None,
            fetched_at: None,
        });
    }
    let json = store.setting(KEY_CACHE)?;
    let etag = store.setting(KEY_ETAG)?.filter(|s| !s.is_empty());
    let fetched_at = store
        .setting(KEY_FETCHED_AT)?
        .and_then(|s| s.parse::<i64>().ok());
    let doc = json.and_then(|raw| serde_json::from_str::<CatalogDocument>(&raw).ok());
    Ok(CachedCatalog {
        doc,
        etag,
        fetched_at,
    })
}

pub fn find_cached_entry(
    store: &Store,
    url: &str,
    pubkey: &str,
    id: &str,
) -> Result<CatalogEntry, CatalogError> {
    let cache = read_cache(store, url, pubkey)?;
    let doc = cache
        .doc
        .ok_or_else(|| CatalogError::NotFound(id.to_string()))?;
    doc.entries
        .into_iter()
        .find(|e| e.id == id)
        .ok_or_else(|| CatalogError::NotFound(id.to_string()))
}

fn make_agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(timeout))
        .user_agent("Linen")
        .http_status_as_error(false)
        .build()
        .into()
}

fn resolve_redirect(current: &str, origin_host: &str, loc: &str) -> Result<String, CatalogError> {
    let (scheme, _) = current
        .split_once("://")
        .ok_or_else(|| CatalogError::Network("invalid current URL".into()))?;
    let next_url = if loc.starts_with("//") {
        format!("{scheme}:{loc}")
    } else if loc.starts_with('/') {
        format!("{scheme}://{origin_host}{loc}")
    } else if loc.contains("://") {
        loc.to_string()
    } else {
        let base = current.split(['?', '#']).next().unwrap_or(current);
        let scheme_end = base.find("://").map(|i| i + 3).unwrap_or(0);
        match base[scheme_end..].rfind('/') {
            Some(rel_idx) => format!("{}{loc}", &base[..scheme_end + rel_idx + 1]),
            None => format!("{base}/{loc}"),
        }
    };
    if !allowed_url(&next_url) {
        return Err(CatalogError::Network(
            "redirected to a disallowed URL scheme".into(),
        ));
    }
    let next_host = url_host(&next_url)
        .ok_or_else(|| CatalogError::Network("redirect target has no host".into()))?;
    if next_host != origin_host {
        return Err(CatalogError::Network(format!(
            "refused cross-host redirect from {origin_host} to {next_host}"
        )));
    }
    Ok(next_url)
}

fn get_same_host(
    agent: &ureq::Agent,
    initial_url: &str,
    etag: Option<&str>,
) -> Result<(ureq::http::Response<ureq::Body>, String), CatalogError> {
    if !allowed_url(initial_url) {
        return Err(CatalogError::Invalid(format!(
            "disallowed URL: {initial_url}"
        )));
    }
    let origin_host =
        url_host(initial_url).ok_or_else(|| CatalogError::Invalid("URL has no host".into()))?;
    let mut current = initial_url.to_string();

    for hop in 0..=MAX_REDIRECTS {
        let mut req = agent.get(&current);
        if hop == 0 {
            if let Some(tag) = etag {
                req = req.header("If-None-Match", tag);
            }
        }
        let resp = req
            .call()
            .map_err(|e| CatalogError::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            if hop == MAX_REDIRECTS {
                return Err(CatalogError::Network("too many redirects".into()));
            }
            let loc = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| CatalogError::Network("redirect missing Location header".into()))?;
            current = resolve_redirect(&current, &origin_host, loc)?;
            continue;
        }
        return Ok((resp, current));
    }
    Err(CatalogError::Network("too many redirects".into()))
}

fn read_bounded(mut reader: impl Read, max_bytes: u64) -> Result<Vec<u8>, CatalogError> {
    let mut out = Vec::new();
    let mut limited = reader.by_ref().take(max_bytes + 1);
    limited.read_to_end(&mut out)?;
    if out.len() as u64 > max_bytes {
        return Err(CatalogError::Invalid(format!(
            "response exceeds {max_bytes} bytes"
        )));
    }
    Ok(out)
}

/// Outcome of a network fetch, ready to be persisted into SQLite.
pub enum FetchOutcome {
    FreshCache {
        doc: CatalogDocument,
        fetched_at: i64,
    },
    NotModified {
        doc: CatalogDocument,
        fetched_at: i64,
    },
    Updated {
        doc: CatalogDocument,
        raw_json: String,
        etag: Option<String>,
        fetched_at: i64,
        url: String,
        pubkey: String,
    },
    OfflineFallback {
        doc: CatalogDocument,
        fetched_at: i64,
    },
}

/// Fetch and verify the catalog without holding a `Store` lock.
pub fn fetch_catalog_network(
    cache: CachedCatalog,
    force: bool,
    url: &str,
    pubkey: &str,
) -> Result<FetchOutcome, CatalogError> {
    let now = now_ms();
    if !force {
        if let (Some(doc), Some(fetched_at)) = (&cache.doc, cache.fetched_at) {
            if now >= fetched_at && now - fetched_at < CACHE_TTL_MS {
                return Ok(FetchOutcome::FreshCache {
                    doc: doc.clone(),
                    fetched_at,
                });
            }
        }
    }

    let agent = make_agent(CATALOG_TIMEOUT);
    let etag_ref = cache.doc.as_ref().and(cache.etag.as_deref());
    let (resp, final_url) = match get_same_host(&agent, url, etag_ref) {
        Ok(r) => r,
        Err(e) => {
            if let (Some(doc), Some(fetched_at)) = (cache.doc, cache.fetched_at) {
                return Ok(FetchOutcome::OfflineFallback { doc, fetched_at });
            }
            return Err(e);
        }
    };

    let status = resp.status().as_u16();
    if status == 304 {
        if let Some(doc) = cache.doc {
            return Ok(FetchOutcome::NotModified {
                doc,
                fetched_at: now,
            });
        }
    }
    if status != 200 {
        if let (Some(doc), Some(fetched_at)) = (cache.doc, cache.fetched_at) {
            return Ok(FetchOutcome::OfflineFallback { doc, fetched_at });
        }
        return Err(CatalogError::Network(format!("HTTP {status}")));
    }

    let new_etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let json_bytes = read_bounded(resp.into_body().into_reader(), MAX_CATALOG_BYTES)?;

    let sig_url = format!("{final_url}.minisig");
    let (sig_resp, _) = match get_same_host(&agent, &sig_url, None) {
        Ok((r, u)) if r.status().as_u16() == 200 => (r, u),
        Ok((r, _)) => {
            return Err(CatalogError::Verification(format!(
                "signature fetch returned HTTP {}",
                r.status().as_u16()
            )));
        }
        Err(e) => {
            if let (Some(doc), Some(fetched_at)) = (cache.doc, cache.fetched_at) {
                return Ok(FetchOutcome::OfflineFallback { doc, fetched_at });
            }
            return Err(e);
        }
    };
    let sig_bytes = read_bounded(sig_resp.into_body().into_reader(), MAX_SIG_BYTES)?;

    let doc = parse_and_verify(&json_bytes, &sig_bytes, pubkey)?;
    let raw_json = String::from_utf8(json_bytes)
        .map_err(|_| CatalogError::Invalid("catalog JSON is not UTF-8".into()))?;
    Ok(FetchOutcome::Updated {
        doc,
        raw_json,
        etag: new_etag,
        fetched_at: now,
        url: url.to_string(),
        pubkey: pubkey.to_string(),
    })
}

pub fn apply_fetch_outcome(
    store: &mut Store,
    installed: &[Installed],
    outcome: FetchOutcome,
) -> Result<CatalogResponse, CatalogError> {
    match outcome {
        FetchOutcome::FreshCache { doc, fetched_at } => Ok(CatalogResponse {
            entries: build_views(doc, installed),
            fetched_at,
            offline: false,
            stale: false,
        }),
        FetchOutcome::NotModified { doc, fetched_at } => {
            store.set_setting(KEY_FETCHED_AT, &fetched_at.to_string())?;
            Ok(CatalogResponse {
                entries: build_views(doc, installed),
                fetched_at,
                offline: false,
                stale: false,
            })
        }
        FetchOutcome::Updated {
            doc,
            raw_json,
            etag,
            fetched_at,
            url,
            pubkey,
        } => {
            store.set_setting(KEY_CACHE, &raw_json)?;
            store.set_setting(KEY_URL, &url)?;
            store.set_setting(KEY_PUBKEY, &pubkey)?;
            store.set_setting(KEY_ETAG, etag.as_deref().unwrap_or(""))?;
            store.set_setting(KEY_FETCHED_AT, &fetched_at.to_string())?;
            Ok(CatalogResponse {
                entries: build_views(doc, installed),
                fetched_at,
                offline: false,
                stale: false,
            })
        }
        FetchOutcome::OfflineFallback { doc, fetched_at } => Ok(CatalogResponse {
            entries: build_views(doc, installed),
            fetched_at,
            offline: true,
            stale: true,
        }),
    }
}

/// Download the package to `extensions_dir/.staging/<uuid>.linenext` and verify its SHA-256.
/// Deletes the staged file on any error.
pub fn download_package(
    extensions_dir: &Path,
    entry: &CatalogEntry,
) -> Result<PathBuf, CatalogError> {
    if !allowed_url(&entry.download_url) || url_host(&entry.download_url).is_none() {
        return Err(CatalogError::Invalid(format!(
            "downloadUrl for “{}” must be a valid https:// URL",
            entry.id
        )));
    }
    let staging_dir = extensions_dir.join(STAGING_DIR);
    std::fs::create_dir_all(&staging_dir)?;
    let staged_path = staging_dir.join(format!("{}.linenext", uuid::Uuid::new_v4()));

    let res = (|| -> Result<(), CatalogError> {
        let agent = make_agent(DOWNLOAD_TIMEOUT);
        let (resp, _) = get_same_host(&agent, &entry.download_url, None)?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(CatalogError::Network(format!("HTTP {status}")));
        }
        let mut reader = resp.into_body().into_reader();
        let mut file = std::fs::File::create(&staged_path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        let mut total: u64 = 0;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_PACKAGE {
                return Err(CatalogError::Integrity(
                    "package exceeds the 20 MB limit".into(),
                ));
            }
            file.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
        }
        file.flush()?;

        let actual_hex: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if actual_hex != entry.sha256 {
            return Err(CatalogError::Integrity(format!(
                "SHA-256 mismatch for “{}”",
                entry.id
            )));
        }
        Ok(())
    })();

    if let Err(e) = res {
        let _ = std::fs::remove_file(&staged_path);
        return Err(e);
    }
    Ok(staged_path)
}

/// Inspect a downloaded package and verify its manifest ID and version match the catalog entry.
/// Deletes the staged file on any error.
pub fn inspect_staged(
    store: &Store,
    staged_path: PathBuf,
    entry: &CatalogEntry,
) -> Result<StagedDownload, CatalogError> {
    let inspection = match registry::inspect(store, &staged_path) {
        Ok(i) => i,
        Err(e) => {
            let _ = std::fs::remove_file(&staged_path);
            return Err(e.into());
        }
    };
    if inspection.manifest.id != entry.id || inspection.manifest.version != entry.version {
        let _ = std::fs::remove_file(&staged_path);
        return Err(CatalogError::Integrity(format!(
            "package manifest ({} {}) does not match catalog entry ({} {})",
            inspection.manifest.id, inspection.manifest.version, entry.id, entry.version
        )));
    }
    Ok(StagedDownload {
        id: entry.id.clone(),
        version: entry.version.clone(),
        path: staged_path,
        inspection,
    })
}

/// Convenience helper combining download and inspection (used in tests).
#[cfg(test)]
pub fn download_and_stage(
    store: &Store,
    extensions_dir: &Path,
    entry: &CatalogEntry,
) -> Result<StagedDownload, CatalogError> {
    let staged_path = download_package(extensions_dir, entry)?;
    inspect_staged(store, staged_path, entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::Arc;
    use zip::write::SimpleFileOptions;

    fn test_keypair() -> (SigningKey, [u8; 8], String) {
        let secret = [42u8; 32];
        let sk = SigningKey::from_bytes(&secret);
        let key_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut pk_bytes = Vec::with_capacity(42);
        pk_bytes.extend_from_slice(b"Ed");
        pk_bytes.extend_from_slice(&key_id);
        pk_bytes.extend_from_slice(sk.verifying_key().as_bytes());
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(pk_bytes);
        (sk, key_id, pubkey_b64)
    }

    fn sign_minisign(sk: &SigningKey, key_id: &[u8; 8], data: &[u8]) -> Vec<u8> {
        let sig = sk.sign(data);
        let mut sig_line = Vec::with_capacity(74);
        sig_line.extend_from_slice(b"Ed");
        sig_line.extend_from_slice(key_id);
        sig_line.extend_from_slice(&sig.to_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_line);

        let trusted = "timestamp:1700000000\tfile:catalog.json";
        let mut global_msg = Vec::with_capacity(64 + trusted.len());
        global_msg.extend_from_slice(&sig.to_bytes());
        global_msg.extend_from_slice(trusted.as_bytes());
        let global_sig = sk.sign(&global_msg);
        let global_b64 = base64::engine::general_purpose::STANDARD.encode(global_sig.to_bytes());

        format!(
            "untrusted comment: test catalog\n{sig_b64}\ntrusted comment: {trusted}\n{global_b64}\n"
        )
        .into_bytes()
    }

    fn sample_entry(download_url: &str, sha256: &str, size_bytes: u64) -> CatalogEntry {
        CatalogEntry {
            id: "org.example.dictionary".into(),
            name: "Dictionary".into(),
            summary: "Look up selected words.".into(),
            publisher: "Example Org".into(),
            homepage: "https://example.org/dictionary".into(),
            category: CatalogCategory::Lookup,
            version: "1.2.0".into(),
            engines_linen: "^1.0".into(),
            download_url: download_url.into(),
            sha256: sha256.into(),
            size_bytes,
            permissions: vec!["book.selection".into()],
            optional_permissions: vec![],
            contributes_summary: vec!["Lookup".into()],
        }
    }

    fn build_package_bytes(id: &str, version: &str) -> (Vec<u8>, String) {
        let manifest = format!(
            r#"{{
                "id": "{id}",
                "version": "{version}",
                "name": "Dictionary",
                "description": "Look up selected words.",
                "engines": {{ "linen": "^1.0" }},
                "main": "main.js",
                "activation": ["onCommand:define"],
                "contributes": {{ "commands": [{{ "id": "define", "title": "Define" }}] }},
                "permissions": ["book.selection"]
            }}"#
        );
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            w.start_file("manifest.json", SimpleFileOptions::default())
                .unwrap();
            w.write_all(manifest.as_bytes()).unwrap();
            w.start_file("main.js", SimpleFileOptions::default())
                .unwrap();
            w.write_all(b"export default {};").unwrap();
            w.finish().unwrap();
        }
        let bytes = cursor.into_inner();
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        (bytes, hash)
    }

    #[test]
    fn valid_signed_catalog_parses_and_verifies() {
        let (sk, key_id, pubkey) = test_keypair();
        let doc = CatalogDocument {
            schema_version: 1,
            generated_at: 1_700_000_000_000,
            entries: vec![sample_entry(
                "https://example.org/dict.linenext",
                &"a".repeat(64),
                1024,
            )],
        };
        let json = serde_json::to_vec(&doc).unwrap();
        let sig = sign_minisign(&sk, &key_id, &json);
        let parsed = parse_and_verify(&json, &sig, &pubkey).unwrap();
        assert_eq!(parsed, doc);
    }

    #[test]
    fn tampered_json_and_bad_signature_are_rejected() {
        let (sk, key_id, pubkey) = test_keypair();
        let doc = CatalogDocument {
            schema_version: 1,
            generated_at: 1_700_000_000_000,
            entries: vec![sample_entry(
                "https://example.org/dict.linenext",
                &"a".repeat(64),
                1024,
            )],
        };
        let json = serde_json::to_vec(&doc).unwrap();
        let sig = sign_minisign(&sk, &key_id, &json);

        let mut tampered = json.clone();
        tampered.push(b' ');
        assert!(matches!(
            parse_and_verify(&tampered, &sig, &pubkey),
            Err(CatalogError::Verification(_))
        ));
        assert!(matches!(
            parse_and_verify(&json, b"not a signature", &pubkey),
            Err(CatalogError::Verification(_))
        ));
    }

    #[test]
    fn invalid_entries_are_rejected() {
        let (sk, key_id, pubkey) = test_keypair();
        let check_invalid = |mut entry: CatalogEntry| {
            let doc = CatalogDocument {
                schema_version: 1,
                generated_at: 1_700_000_000_000,
                entries: vec![entry.clone()],
            };
            let json = serde_json::to_vec(&doc).unwrap();
            let sig = sign_minisign(&sk, &key_id, &json);
            assert!(
                matches!(
                    parse_and_verify(&json, &sig, &pubkey),
                    Err(CatalogError::Invalid(_))
                ),
                "expected invalid for {entry:?}"
            );
            // keep rustc happy about mut
            entry.id.clear();
        };

        let base = sample_entry("https://example.org/dict.linenext", &"a".repeat(64), 1024);

        let mut builtin = base.clone();
        builtin.id = "app.linen.fake".into();
        check_invalid(builtin);

        let mut http_url = base.clone();
        http_url.download_url = "http://example.org/dict.linenext".into();
        check_invalid(http_url);

        let mut bad_sha = base.clone();
        bad_sha.sha256 = "ABCDEF".into();
        check_invalid(bad_sha);

        let mut upper_sha = base.clone();
        upper_sha.sha256 = "A".repeat(64);
        check_invalid(upper_sha);

        let mut too_big = base.clone();
        too_big.size_bytes = MAX_PACKAGE + 1;
        check_invalid(too_big);

        let mut zero_size = base.clone();
        zero_size.size_bytes = 0;
        check_invalid(zero_size);

        let mut userinfo_homepage = base.clone();
        userinfo_homepage.homepage = "https://user:pass@evil.example/dict".into();
        check_invalid(userinfo_homepage);

        let mut query_only_homepage = base.clone();
        query_only_homepage.homepage = "https://?queryonly".into();
        check_invalid(query_only_homepage);

        let mut userinfo_download = base.clone();
        userinfo_download.download_url = "https://user:pass@evil.example/dict.linenext".into();
        check_invalid(userinfo_download);

        let mut query_only_download = base.clone();
        query_only_download.download_url = "https://?queryonly".into();
        check_invalid(query_only_download);
    }

    #[test]
    fn resolve_entry_state_covers_all_variants() {
        let entry = sample_entry("https://example.org/dict.linenext", &"a".repeat(64), 1024);
        assert_eq!(
            resolve_entry_state(&entry, &[]),
            EntryInstallState::NotInstalled
        );

        let make_installed = |version: &str| Installed {
            manifest: manifest::parse(&format!(
                r#"{{ "id": "org.example.dictionary", "version": "{version}", "name": "Dictionary",
                "engines": {{ "linen": "^1.0" }}, "main": "main.js",
                "contributes": {{ "commands": [{{ "id": "define", "title": "Define" }}] }},
                "permissions": ["book.selection"] }}"#
            ))
            .unwrap(),
            enabled: true,
            granted: vec!["book.selection".into()],
            builtin: false,
            incompatible: None,
            suspended: false,
            crashes: vec![],
        };

        assert_eq!(
            resolve_entry_state(&entry, &[make_installed("1.2.0")]),
            EntryInstallState::InstalledCurrent
        );
        assert_eq!(
            resolve_entry_state(&entry, &[make_installed("1.0.0")]),
            EntryInstallState::UpdateAvailable {
                installed_version: "1.0.0".into(),
            }
        );

        let mut incompat = entry.clone();
        incompat.engines_linen = "^2.0".into();
        assert!(matches!(
            resolve_entry_state(&incompat, &[]),
            EntryInstallState::Incompatible { .. }
        ));
    }

    #[test]
    fn end_to_end_local_http_fetch_cache_offline_stage_install_and_discard() {
        let (sk, key_id, pubkey) = test_keypair();
        let (pkg_bytes, pkg_sha) = build_package_bytes("org.example.dictionary", "1.2.0");
        let (wrong_id_bytes, wrong_id_sha) = build_package_bytes("org.example.other", "1.2.0");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");

        let good_entry = sample_entry(
            &format!("{base_url}/dict.linenext"),
            &pkg_sha,
            pkg_bytes.len() as u64,
        );
        let mut bad_sha_entry = good_entry.clone();
        bad_sha_entry.id = "org.example.badsha".into();
        bad_sha_entry.sha256 = "0".repeat(64);

        let mut mismatch_entry = good_entry.clone();
        mismatch_entry.id = "org.example.mismatch".into();
        mismatch_entry.download_url = format!("{base_url}/other.linenext");
        mismatch_entry.sha256 = wrong_id_sha;
        mismatch_entry.size_bytes = wrong_id_bytes.len() as u64;

        let doc = CatalogDocument {
            schema_version: 1,
            generated_at: 1_700_000_000_000,
            entries: vec![
                good_entry.clone(),
                bad_sha_entry.clone(),
                mismatch_entry.clone(),
            ],
        };
        let catalog_json = Arc::new(serde_json::to_vec(&doc).unwrap());
        let catalog_sig = Arc::new(sign_minisign(&sk, &key_id, &catalog_json));
        let pkg_bytes = Arc::new(pkg_bytes);
        let wrong_id_bytes = Arc::new(wrong_id_bytes);
        let etag = "\"v1-etag\"";

        let cj = catalog_json.clone();
        let cs = catalog_sig.clone();
        let pb = pkg_bytes.clone();
        let wb = wrong_id_bytes.clone();

        let server = std::thread::spawn(move || {
            // Serve 6 requests: catalog.json, catalog.json.minisig, 304 catalog.json,
            // dict.linenext (good), dict.linenext (bad sha), other.linenext (mismatch),
            // dict.linenext (for discard).
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let path = request_line.split_whitespace().nth(1).unwrap_or("/");
                let mut if_none_match = None;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.eq_ignore_ascii_case("if-none-match") {
                            if_none_match = Some(v.trim().to_string());
                        }
                    }
                }
                match path {
                    "/catalog.json" if if_none_match.as_deref() == Some(etag) => {
                        write!(
                            stream,
                            "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n"
                        )
                        .unwrap();
                    }
                    "/catalog.json" => {
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: {}\r\n\r\n",
                            cj.len()
                        )
                        .unwrap();
                        stream.write_all(&cj).unwrap();
                    }
                    "/catalog.json.minisig" => {
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            cs.len()
                        )
                        .unwrap();
                        stream.write_all(&cs).unwrap();
                    }
                    "/dict.linenext" => {
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            pb.len()
                        )
                        .unwrap();
                        stream.write_all(&pb).unwrap();
                    }
                    "/other.linenext" => {
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            wb.len()
                        )
                        .unwrap();
                        stream.write_all(&wb).unwrap();
                    }
                    _ => {
                        write!(
                            stream,
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                        )
                        .unwrap();
                    }
                }
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let ext_dir = tmp.path().join("Extensions");
        std::fs::create_dir_all(&ext_dir).unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let catalog_url = format!("{base_url}/catalog.json");

        // 1. Initial fetch (200 OK + signature verified + cached).
        let cache = read_cache(&store, &catalog_url, &pubkey).unwrap();
        let outcome = fetch_catalog_network(cache, false, &catalog_url, &pubkey).unwrap();
        assert!(matches!(outcome, FetchOutcome::Updated { .. }));
        let resp = apply_fetch_outcome(&mut store, &[], outcome).unwrap();
        assert!(!resp.offline && !resp.stale);
        assert_eq!(resp.entries.len(), 3);

        // 2. Fresh cache hit (no network request).
        let cache = read_cache(&store, &catalog_url, &pubkey).unwrap();
        let outcome = fetch_catalog_network(cache, false, &catalog_url, &pubkey).unwrap();
        assert!(matches!(outcome, FetchOutcome::FreshCache { .. }));

        // 3. Force refresh hits ETag 304 Not Modified.
        let cache = read_cache(&store, &catalog_url, &pubkey).unwrap();
        let outcome = fetch_catalog_network(cache, true, &catalog_url, &pubkey).unwrap();
        assert!(matches!(outcome, FetchOutcome::NotModified { .. }));
        let resp = apply_fetch_outcome(&mut store, &[], outcome).unwrap();
        assert!(!resp.offline && !resp.stale);

        // 4. Stage & install real .linenext zip.
        let staging = CatalogStaging::default();
        let downloaded = download_and_stage(&store, &ext_dir, &good_entry).unwrap();
        let staged_path = downloaded.path.clone();
        assert!(staged_path.exists());
        let info = staging.insert(downloaded);
        assert_eq!(info.inspection.manifest.id, "org.example.dictionary");

        let taken = staging.take(&info.token).unwrap();
        let installed_manifest = registry::install(
            &mut store,
            &ext_dir,
            &taken.path,
            &taken.inspection.manifest.permissions,
        )
        .unwrap();
        let _ = std::fs::remove_file(&taken.path);
        assert_eq!(installed_manifest.id, "org.example.dictionary");
        assert!(!staged_path.exists());

        // 5. SHA-256 mismatch rejects and deletes staged file.
        let err = download_and_stage(&store, &ext_dir, &bad_sha_entry).unwrap_err();
        assert!(matches!(err, CatalogError::Integrity(_)));
        let remaining: Vec<_> = std::fs::read_dir(ext_dir.join(STAGING_DIR))
            .unwrap()
            .collect();
        assert!(
            remaining.is_empty(),
            "staging dir should be clean after sha mismatch"
        );

        // 6. Manifest ID mismatch rejects and deletes staged file.
        let err = download_and_stage(&store, &ext_dir, &mismatch_entry).unwrap_err();
        assert!(matches!(err, CatalogError::Integrity(_)));
        let remaining: Vec<_> = std::fs::read_dir(ext_dir.join(STAGING_DIR))
            .unwrap()
            .collect();
        assert!(
            remaining.is_empty(),
            "staging dir should be clean after manifest mismatch"
        );

        // 7. Stage & discard deletes staged file.
        let downloaded2 = download_and_stage(&store, &ext_dir, &good_entry).unwrap();
        let staged_path2 = downloaded2.path.clone();
        let info2 = staging.insert(downloaded2);
        staging.discard(&info2.token);
        assert!(!staged_path2.exists());

        server.join().unwrap();

        // 8. Offline fallback after server closes: returns cached catalog with offline=true, stale=true.
        let cache = read_cache(&store, &catalog_url, &pubkey).unwrap();
        let outcome = fetch_catalog_network(cache, true, &catalog_url, &pubkey).unwrap();
        assert!(matches!(outcome, FetchOutcome::OfflineFallback { .. }));
        let installed = registry::list(&store, &ext_dir).unwrap();
        let resp = apply_fetch_outcome(&mut store, &installed, outcome).unwrap();
        assert!(resp.offline && resp.stale);
        assert_eq!(resp.entries[0].state, EntryInstallState::InstalledCurrent);
    }

    #[test]
    fn cache_is_bound_to_active_url_and_pubkey() {
        let (_sk, _key_id, pubkey) = test_keypair();
        let doc = CatalogDocument {
            schema_version: 1,
            generated_at: 1_700_000_000_000,
            entries: vec![sample_entry(
                "https://example.org/dict.linenext",
                &"a".repeat(64),
                1024,
            )],
        };
        let raw_json = serde_json::to_string(&doc).unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let url_a = "https://extensions.linen.app/catalog/v1/catalog.json";
        let url_b = "https://extensions.linen.app/catalog/v2/catalog.json";
        let other_key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

        apply_fetch_outcome(
            &mut store,
            &[],
            FetchOutcome::Updated {
                doc: doc.clone(),
                raw_json,
                etag: Some("\"v1\"".into()),
                fetched_at: now_ms(),
                url: url_a.into(),
                pubkey: pubkey.clone(),
            },
        )
        .unwrap();

        // Matching (url, pubkey) hits cache and finds entry.
        let hit = read_cache(&store, url_a, &pubkey).unwrap();
        assert!(hit.doc.is_some());
        assert_eq!(hit.etag.as_deref(), Some("\"v1\""));
        assert!(find_cached_entry(&store, url_a, &pubkey, "org.example.dictionary").is_ok());

        // Different pubkey misses cache and find_cached_entry.
        let wrong_key = read_cache(&store, url_a, other_key).unwrap();
        assert!(wrong_key.doc.is_none());
        assert!(wrong_key.etag.is_none());
        assert!(wrong_key.fetched_at.is_none());
        assert!(matches!(
            find_cached_entry(&store, url_a, other_key, "org.example.dictionary"),
            Err(CatalogError::NotFound(_))
        ));

        // Different URL misses cache and find_cached_entry.
        let wrong_url = read_cache(&store, url_b, &pubkey).unwrap();
        assert!(wrong_url.doc.is_none());
        assert!(wrong_url.etag.is_none());
        assert!(wrong_url.fetched_at.is_none());
        assert!(matches!(
            find_cached_entry(&store, url_b, &pubkey, "org.example.dictionary"),
            Err(CatalogError::NotFound(_))
        ));

        // Force=true with wrong key does not send stale If-None-Match or accept 304 from old cache.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let local_url = format!("http://127.0.0.1:{port}/catalog.json");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut saw_if_none_match = false;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
                if line.to_ascii_lowercase().starts_with("if-none-match:") {
                    saw_if_none_match = true;
                }
            }
            assert!(
                !saw_if_none_match,
                "wrong-key cache miss must not send stale If-None-Match"
            );
            write!(
                stream,
                "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
        });

        let miss = read_cache(&store, &local_url, other_key).unwrap();
        let err = fetch_catalog_network(miss, true, &local_url, other_key);
        assert!(matches!(err, Err(CatalogError::Network(_))));
        server.join().unwrap();
    }

    #[test]
    fn updating_without_etag_clears_stale_etag() {
        let (_sk, _key_id, pubkey) = test_keypair();
        let doc = CatalogDocument {
            schema_version: 1,
            generated_at: 1_700_000_000_000,
            entries: vec![],
        };
        let raw_json = serde_json::to_string(&doc).unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let url = "https://extensions.linen.app/catalog/v1/catalog.json";

        apply_fetch_outcome(
            &mut store,
            &[],
            FetchOutcome::Updated {
                doc: doc.clone(),
                raw_json: raw_json.clone(),
                etag: Some("\"old-etag\"".into()),
                fetched_at: now_ms(),
                url: url.into(),
                pubkey: pubkey.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            read_cache(&store, url, &pubkey).unwrap().etag.as_deref(),
            Some("\"old-etag\"")
        );

        apply_fetch_outcome(
            &mut store,
            &[],
            FetchOutcome::Updated {
                doc,
                raw_json,
                etag: None,
                fetched_at: now_ms(),
                url: url.into(),
                pubkey: pubkey.clone(),
            },
        )
        .unwrap();
        assert_eq!(read_cache(&store, url, &pubkey).unwrap().etag, None);
    }

    #[test]
    fn clock_rollback_does_not_treat_future_cache_as_fresh() {
        let (sk, key_id, pubkey) = test_keypair();
        let doc = CatalogDocument {
            schema_version: 1,
            generated_at: 1_700_000_000_000,
            entries: vec![sample_entry(
                "https://example.org/dict.linenext",
                &"a".repeat(64),
                1024,
            )],
        };
        let catalog_json = Arc::new(serde_json::to_vec(&doc).unwrap());
        let catalog_sig = Arc::new(sign_minisign(&sk, &key_id, &catalog_json));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/catalog.json");
        let cj = catalog_json.clone();
        let cs = catalog_sig.clone();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                let path = req_line.split_whitespace().nth(1).unwrap_or("/");
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                }
                let body = if path == "/catalog.json.minisig" {
                    &cs
                } else {
                    &cj
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body).unwrap();
            }
        });

        let cache = CachedCatalog {
            doc: Some(doc),
            etag: None,
            fetched_at: Some(now_ms() + 60_000),
        };
        let outcome = fetch_catalog_network(cache, false, &url, &pubkey).unwrap();
        assert!(matches!(outcome, FetchOutcome::Updated { .. }));
        server.join().unwrap();
    }

    #[test]
    fn redirects_resolve_relative_protocol_relative_and_minisig_follows_final_url() {
        let (sk, key_id, pubkey) = test_keypair();
        let doc = CatalogDocument {
            schema_version: 1,
            generated_at: 1_700_000_000_000,
            entries: vec![sample_entry(
                "https://example.org/dict.linenext",
                &"a".repeat(64),
                1024,
            )],
        };
        let catalog_json = Arc::new(serde_json::to_vec(&doc).unwrap());
        let catalog_sig = Arc::new(sign_minisign(&sk, &key_id, &catalog_json));

        // Unit check on cross-host protocol-relative rejection.
        assert!(resolve_redirect(
            "https://extensions.linen.app/v1/catalog.json",
            "extensions.linen.app",
            "//evil.example/catalog.json",
        )
        .is_err());

        // Integration check:
        // /v1/catalog.json -> 302 Location: //127.0.0.1:<port>/v2/catalog.json
        // /v2/catalog.json -> 302 Location: sub/final.json (relative without leading '/')
        // /v2/sub/final.json -> 200 OK
        // /v2/sub/final.json.minisig -> 200 OK (must be requested at final redirected URL)
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/v1/catalog.json");
        let cj = catalog_json.clone();
        let cs = catalog_sig.clone();

        let server = std::thread::spawn(move || {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                let path = req_line.split_whitespace().nth(1).unwrap_or("/");
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                }
                match path {
                    "/v1/catalog.json" => {
                        write!(
                            stream,
                            "HTTP/1.1 302 Found\r\nLocation: //127.0.0.1:{port}/v2/catalog.json\r\nContent-Length: 0\r\n\r\n"
                        )
                        .unwrap();
                    }
                    "/v2/catalog.json" => {
                        write!(
                            stream,
                            "HTTP/1.1 302 Found\r\nLocation: sub/final.json\r\nContent-Length: 0\r\n\r\n"
                        )
                        .unwrap();
                    }
                    "/v2/sub/final.json" => {
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            cj.len()
                        )
                        .unwrap();
                        stream.write_all(&cj).unwrap();
                    }
                    "/v2/sub/final.json.minisig" => {
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                            cs.len()
                        )
                        .unwrap();
                        stream.write_all(&cs).unwrap();
                    }
                    other => panic!("unexpected request path: {other}"),
                }
            }
        });

        let empty_cache = CachedCatalog {
            doc: None,
            etag: None,
            fetched_at: None,
        };
        let outcome = fetch_catalog_network(empty_cache, false, &url, &pubkey).unwrap();
        assert!(matches!(outcome, FetchOutcome::Updated { .. }));
        server.join().unwrap();
    }
}
