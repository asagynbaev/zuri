//! `.zuri/payroll.json`: every salary payment with the signatures of all the
//! transactions it took. This is the input for day 2 (locating the transfer
//! ciphertexts on-chain).

use {
    anyhow::Result,
    serde::{Deserialize, Serialize},
    std::{fs, path::PathBuf},
};

#[derive(Serialize, Deserialize, Default)]
pub struct Payroll {
    pub mint: String,
    pub employer: String,
    pub employer_token_account: String,
    pub employee: String,
    pub employee_token_account: String,
    pub transfers: Vec<TransferRecord>,
}

/// One confidential transfer = 5 transactions. The context-state accounts are
/// closed in the last one, so only their addresses and the transaction data
/// remain on-chain afterwards.
#[derive(Serialize, Deserialize, Clone)]
pub struct TransferRecord {
    /// Base units. Kept for debugging only: the prover must re-derive it by
    /// decryption and the verifier never sees it.
    pub amount: u64,
    pub equality_context: String,
    pub validity_context: String,
    pub range_context: String,
    pub record_account: String,
    pub equality_sig: String,
    pub validity_sig: String,
    pub range_sigs: Vec<String>,
    pub transfer_sig: String,
}

fn path() -> PathBuf {
    PathBuf::from(crate::keys::DIR).join("payroll.json")
}

impl Payroll {
    pub fn load() -> Result<Self> {
        let path = path();
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn save(&self) -> Result<()> {
        fs::create_dir_all(crate::keys::DIR)?;
        fs::write(path(), serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}
