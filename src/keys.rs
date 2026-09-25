//! Devnet keypairs, persisted under `.zuri/` so reruns reuse the same mint and
//! accounts (the devnet faucet is too stingy to start over every time).

use {
    anyhow::{Context, Result, anyhow},
    solana_keypair::Keypair,
    solana_zk_sdk::encryption::elgamal::ElGamalKeypair,
    std::{
        fs,
        path::{Path, PathBuf},
    },
};

pub const DIR: &str = ".zuri";

fn path(name: &str) -> PathBuf {
    PathBuf::from(DIR).join(format!("{name}.json"))
}

/// Read a keypair in the solana-keygen JSON format (64-byte array).
pub fn read(path: &Path) -> Result<Keypair> {
    let bytes: Vec<u8> = serde_json::from_str(&fs::read_to_string(path)?)
        .with_context(|| format!("parse {}", path.display()))?;
    Keypair::try_from(bytes.as_slice()).map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// A named project keypair, created on first use.
pub fn keypair(name: &str) -> Result<Keypair> {
    let path = path(name);
    if path.exists() {
        return read(&path);
    }
    let keypair = Keypair::new();
    fs::create_dir_all(DIR)?;
    fs::write(&path, serde_json::to_string(&keypair.to_bytes().to_vec())?)?;
    Ok(keypair)
}

/// The mint's auditor key. Not derived from a signer: in production this
/// belongs to whoever audits the stablecoin, not to either payroll party.
pub fn auditor() -> Result<ElGamalKeypair> {
    let path = path("auditor-elgamal");
    if path.exists() {
        return serde_json::from_str(&fs::read_to_string(&path)?)
            .with_context(|| format!("parse {}", path.display()));
    }
    let keypair = ElGamalKeypair::new_rand();
    fs::create_dir_all(DIR)?;
    fs::write(&path, serde_json::to_string(&keypair)?)?;
    Ok(keypair)
}
