//! Offline Minisign keygen and signing tool for the Linen extension catalog.
//!
//!   cargo run --example sign_catalog -- keygen <secret-path> <pub-path>
//!   cargo run --example sign_catalog -- sign <secret-path> <file-path>

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use minisign_verify::{PublicKey, Signature};

const SECRET_LEN: usize = 32;
const KEY_ID_LEN: usize = 8;
const SECRET_BLOB_LEN: usize = KEY_ID_LEN + SECRET_LEN;

fn encode_pubkey(sk: &SigningKey, key_id: &[u8; KEY_ID_LEN]) -> String {
    let mut pk_bytes = Vec::with_capacity(2 + KEY_ID_LEN + 32);
    pk_bytes.extend_from_slice(b"Ed");
    pk_bytes.extend_from_slice(key_id);
    pk_bytes.extend_from_slice(sk.verifying_key().as_bytes());
    base64::engine::general_purpose::STANDARD.encode(pk_bytes)
}

fn keygen(secret_path: &str, pub_path: &str) -> Result<(), String> {
    if Path::new(secret_path).exists() {
        return Err(format!(
            "refusing to overwrite existing secret key at {secret_path}"
        ));
    }

    let mut secret = [0u8; SECRET_LEN];
    let mut key_id = [0u8; KEY_ID_LEN];
    getrandom::fill(&mut secret).map_err(|e| format!("CSPRNG failed: {e}"))?;
    getrandom::fill(&mut key_id).map_err(|e| format!("CSPRNG failed: {e}"))?;

    let sk = SigningKey::from_bytes(&secret);
    let pubkey_b64 = encode_pubkey(&sk, &key_id);
    PublicKey::from_base64(&pubkey_b64)
        .map_err(|e| format!("generated public key failed validation: {e}"))?;

    let mut blob = [0u8; SECRET_BLOB_LEN];
    blob[..KEY_ID_LEN].copy_from_slice(&key_id);
    blob[KEY_ID_LEN..].copy_from_slice(&secret);
    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(blob);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut secret_file = opts
        .open(secret_path)
        .map_err(|e| format!("failed to create {secret_path}: {e}"))?;
    writeln!(secret_file, "{secret_b64}")
        .map_err(|e| format!("failed to write {secret_path}: {e}"))?;
    secret_file
        .flush()
        .map_err(|e| format!("failed to flush {secret_path}: {e}"))?;

    fs::write(pub_path, format!("{pubkey_b64}\n"))
        .map_err(|e| format!("failed to write {pub_path}: {e}"))?;

    println!("wrote public key to {pub_path}: {pubkey_b64}");
    Ok(())
}

fn load_secret(secret_path: &str) -> Result<(SigningKey, [u8; KEY_ID_LEN]), String> {
    let raw = fs::read_to_string(secret_path)
        .map_err(|e| format!("failed to read {secret_path}: {e}"))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| format!("invalid base64 in {secret_path}: {e}"))?;
    if blob.len() != SECRET_BLOB_LEN {
        return Err(format!(
            "invalid secret key length in {secret_path}: expected {SECRET_BLOB_LEN} bytes, got {}",
            blob.len()
        ));
    }
    let key_id: [u8; KEY_ID_LEN] = blob[..KEY_ID_LEN].try_into().unwrap();
    let secret: [u8; SECRET_LEN] = blob[KEY_ID_LEN..].try_into().unwrap();
    Ok((SigningKey::from_bytes(&secret), key_id))
}

fn sign(secret_path: &str, file_path: &str) -> Result<(), String> {
    let (sk, key_id) = load_secret(secret_path)?;
    let pubkey_b64 = encode_pubkey(&sk, &key_id);
    let data = fs::read(file_path).map_err(|e| format!("failed to read {file_path}: {e}"))?;

    let sig = sk.sign(&data);
    let mut sig_line = Vec::with_capacity(2 + KEY_ID_LEN + 64);
    sig_line.extend_from_slice(b"Ed");
    sig_line.extend_from_slice(&key_id);
    sig_line.extend_from_slice(&sig.to_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_line);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock error: {e}"))?
        .as_secs();
    let file_name = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("catalog.json");
    let trusted = format!("timestamp:{ts}\tfile:{file_name}");

    let mut global_msg = Vec::with_capacity(64 + trusted.len());
    global_msg.extend_from_slice(&sig.to_bytes());
    global_msg.extend_from_slice(trusted.as_bytes());
    let global_sig = sk.sign(&global_msg);
    let global_b64 = base64::engine::general_purpose::STANDARD.encode(global_sig.to_bytes());

    let minisig = format!(
        "untrusted comment: signature from linen catalog key\n{sig_b64}\ntrusted comment: {trusted}\n{global_b64}\n"
    );

    let sig_path = format!("{file_path}.minisig");
    fs::write(&sig_path, &minisig).map_err(|e| format!("failed to write {sig_path}: {e}"))?;

    let written =
        fs::read_to_string(&sig_path).map_err(|e| format!("failed to re-read {sig_path}: {e}"))?;
    let pk = PublicKey::from_base64(&pubkey_b64)
        .map_err(|e| format!("public key decode failed: {e}"))?;
    let decoded_sig =
        Signature::decode(&written).map_err(|e| format!("signature decode failed: {e}"))?;
    pk.verify(&data, &decoded_sig, true)
        .map_err(|e| format!("self-verification failed: {e}"))?;

    println!("signed and verified {sig_path}");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [cmd, secret_path, pub_path] if cmd == "keygen" => keygen(secret_path, pub_path),
        [cmd, secret_path, file_path] if cmd == "sign" => sign(secret_path, file_path),
        _ => {
            eprintln!("usage:");
            eprintln!("  sign_catalog keygen <secret-path> <pub-path>");
            eprintln!("  sign_catalog sign <secret-path> <file-path>");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
