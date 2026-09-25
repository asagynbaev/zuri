use {
    anyhow::{Context, Result, anyhow},
    solana_keypair::Keypair,
    solana_zk_sdk::encryption::elgamal::ElGamalKeypair,
    std::{
        fs,
        path::{Path, PathBuf},
    },
};

/// Local devnet state: keypairs and payroll.json.
pub const DIR: &str = ".zuri";

fn path(name: &str) -> PathBuf {
    PathBuf::from(DIR).join(format!("{name}.json"))
}

/// solana-keygen JSON format.
pub fn read(path: &Path) -> Result<Keypair> {
    let bytes: Vec<u8> = serde_json::from_str(&fs::read_to_string(path)?)
        .with_context(|| format!("parse {}", path.display()))?;
    Keypair::try_from(bytes.as_slice()).map_err(|e| anyhow!("{}: {e}", path.display()))
}

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

pub fn auditor() -> Result<ElGamalKeypair> {
    let path = path("auditor-elgamal");
    if path.exists() {
        return Ok(serde_json::from_str(&fs::read_to_string(&path)?)?);
    }
    let keypair = ElGamalKeypair::new_rand();
    fs::create_dir_all(DIR)?;
    fs::write(&path, serde_json::to_string(&keypair)?)?;
    Ok(keypair)
}
