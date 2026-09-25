use {
    anyhow::Result,
    serde::{Deserialize, Serialize},
    std::{fs, path::PathBuf},
};

/// What the demo has sent so far, kept in `.zuri/payroll.json`.
#[derive(Serialize, Deserialize, Default)]
pub struct Payroll {
    pub mint: String,
    pub employer: String,
    pub employer_token_account: String,
    pub employee: String,
    pub employee_token_account: String,
    pub transfers: Vec<TransferRecord>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TransferRecord {
    /// Plaintext amount, for debugging only.
    pub amount: u64,
    /// Pay period written by the employer in a memo, YYYY-MM.
    #[serde(default)]
    pub period: Option<String>,
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
