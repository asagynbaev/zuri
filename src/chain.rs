//! Thin RPC layer: one funded payer (the employer) signs and pays for every
//! transaction, including the employee's own account operations.

use {
    anyhow::{Context, Result, bail},
    solana_address::Address,
    solana_commitment_config::CommitmentConfig,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_signature::Signature,
    solana_signer::Signer,
    solana_transaction::Transaction,
    std::time::Duration,
};

pub const DEFAULT_RPC_URL: &str = "https://api.devnet.solana.com";
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

pub struct Chain {
    pub rpc: RpcClient,
    pub payer: Keypair,
}

impl Chain {
    pub fn new(payer: Keypair) -> Self {
        let url = std::env::var("ZURI_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string());
        let rpc = RpcClient::new_with_commitment(url, CommitmentConfig::confirmed());
        Self { rpc, payer }
    }

    pub fn explorer(&self, sig: &Signature) -> String {
        format!("https://explorer.solana.com/tx/{sig}?cluster=devnet")
    }

    /// Sign with the payer plus `signers` (duplicates are dropped), send, and
    /// wait for confirmation.
    pub async fn send(
        &self,
        label: &str,
        ixs: &[Instruction],
        signers: &[&dyn Signer],
    ) -> Result<Signature> {
        let mut all: Vec<&dyn Signer> = vec![&self.payer];
        for s in signers {
            if !all.iter().any(|a| a.pubkey() == s.pubkey()) {
                all.push(*s);
            }
        }
        let blockhash = self.rpc.get_latest_blockhash().await?;
        let tx =
            Transaction::new_signed_with_payer(ixs, Some(&self.payer.pubkey()), &all, blockhash);
        let sig = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .await
            .with_context(|| format!("{label} failed"))?;
        println!("  {label:<28} {sig}");
        Ok(sig)
    }

    /// Plain SOL transfer to the payer from another wallet, which also pays the fee.
    pub async fn fund_payer(&self, from: &Keypair, lamports: u64) -> Result<Signature> {
        let ix = solana_system_interface::instruction::transfer(
            &from.pubkey(),
            &self.payer.pubkey(),
            lamports,
        );
        let blockhash = self.rpc.get_latest_blockhash().await?;
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&from.pubkey()), &[from], blockhash);
        Ok(self.rpc.send_and_confirm_transaction(&tx).await?)
    }

    pub async fn account_data(&self, address: &Address) -> Result<Option<Vec<u8>>> {
        Ok(self
            .rpc
            .get_account_with_commitment(address, self.rpc.commitment())
            .await?
            .value
            .map(|a| a.data))
    }

    /// Top the payer up from the devnet faucet if it is running low.
    pub async fn ensure_sol(&self, min_sol: u64) -> Result<()> {
        let payer = self.payer.pubkey();
        let balance = self.rpc.get_balance(&payer).await?;
        if balance >= min_sol * LAMPORTS_PER_SOL / 2 {
            return Ok(());
        }
        println!("payer {payer} has {balance} lamports, requesting a {min_sol} SOL airdrop");
        let sig = match self.rpc.request_airdrop(&payer, min_sol * LAMPORTS_PER_SOL).await {
            Ok(sig) => sig,
            Err(e) => bail!(
                "airdrop failed ({e}).\nFund {payer} with ~1 SOL at https://faucet.solana.com \
                 (devnet) and rerun."
            ),
        };
        for _ in 0..30 {
            if self.rpc.confirm_transaction(&sig).await? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("airdrop {sig} not confirmed after 30s; check the payer balance and rerun")
    }
}
