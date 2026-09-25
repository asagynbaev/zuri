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

pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

pub fn rpc() -> RpcClient {
    let url = std::env::var("ZURI_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    RpcClient::new_with_commitment(url, CommitmentConfig::confirmed())
}

/// RPC client plus the wallet that pays for every transaction.
pub struct Chain {
    pub rpc: RpcClient,
    pub payer: Keypair,
}

impl Chain {
    pub fn new(payer: Keypair) -> Self {
        Self { rpc: rpc(), payer }
    }

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
        println!("  {label:<22} {sig}");
        Ok(sig)
    }

    pub async fn transfer_sol(&self, from: &Keypair, lamports: u64) -> Result<Signature> {
        let ix = solana_system_interface::instruction::transfer(
            &from.pubkey(),
            &self.payer.pubkey(),
            lamports,
        );
        let blockhash = self.rpc.get_latest_blockhash().await?;
        let tx =
            Transaction::new_signed_with_payer(&[ix], Some(&from.pubkey()), &[from], blockhash);
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

    pub async fn ensure_sol(&self, sol: u64) -> Result<()> {
        let payer = self.payer.pubkey();
        if self.rpc.get_balance(&payer).await? >= sol * LAMPORTS_PER_SOL / 2 {
            return Ok(());
        }
        println!("airdropping {sol} SOL to {payer}");
        let Ok(sig) = self
            .rpc
            .request_airdrop(&payer, sol * LAMPORTS_PER_SOL)
            .await
        else {
            bail!("airdrop failed, fund {payer} at https://faucet.solana.com and retry");
        };
        for _ in 0..30 {
            if self.rpc.confirm_transaction(&sig).await? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("airdrop {sig} not confirmed")
    }
}
