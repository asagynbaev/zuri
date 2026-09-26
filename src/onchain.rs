//! Reads confidential transfers back from the chain.
//!
//! With proofs in context accounts, the Token-2022 `Transfer` instruction only
//! carries the auditor ciphertexts. Its accounts are
//! `[source, mint, destination, equality_ctx, validity_ctx, range_ctx, authority]`.
//! The grouped ciphertexts with the recipient's handles are in the data of the
//! `VerifyBatchedGroupedCiphertext3HandlesValidity` instruction that wrote
//! `validity_ctx` in an earlier transaction:
//!
//! ```text
//! 0         discriminator
//! 1..33     source pubkey
//! 33..65    destination pubkey
//! 65..97    auditor pubkey
//! 97..225   lo: commitment | source | destination | auditor handle
//! 225..353  hi: same
//! 353..     proof
//! ```

use {
    crate::{ct::PERIOD_MEMO, fmt_month, parse_month},
    anyhow::{Context, Result, anyhow, bail, ensure},
    futures::{StreamExt, TryStreamExt, stream},
    solana_address::Address,
    solana_commitment_config::CommitmentConfig,
    solana_rpc_client::{
        nonblocking::rpc_client::RpcClient, rpc_client::GetConfirmedSignaturesForAddress2Config,
    },
    solana_rpc_client_types::config::RpcTransactionConfig,
    solana_signature::Signature,
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_status_client_types::UiTransactionEncoding,
    solana_zk_elgamal_proof_interface::{
        instruction::ProofInstruction,
        proof_data::{
            BatchedGroupedCiphertext3HandlesValidityProofContext,
            BatchedGroupedCiphertext3HandlesValidityProofData, ZkProofData,
        },
    },
    solana_zk_sdk::{
        encryption::{elgamal::ElGamalCiphertext, grouped_elgamal::GroupedElGamalCiphertext},
        zk_elgamal_proof_program::VerifyZkProof,
    },
    solana_zk_sdk_pod::encryption::{
        elgamal::PodElGamalCiphertext, grouped_elgamal::PodGroupedElGamalCiphertext3Handles,
    },
    spl_token_2022_interface::{
        extension::confidential_transfer::instruction::{
            ConfidentialTransferInstruction, TransferInstructionData,
        },
        instruction::{decode_instruction_data, decode_instruction_type},
    },
    std::{
        collections::HashMap,
        str::FromStr,
        sync::{Mutex, OnceLock},
    },
};

/// Handle index of each party in a grouped ciphertext.
pub const SOURCE: usize = 0;
pub const DESTINATION: usize = 1;
pub const AUDITOR: usize = 2;

const CONFIDENTIAL_TRANSFER_EXTENSION: u8 = 27;

#[derive(Clone)]
pub struct Tx {
    pub slot: u64,
    pub block_time: Option<i64>,
    pub tx: VersionedTransaction,
}

// Confirmed transactions don't change, so each one is fetched once per process.
// Proofs are still checked from scratch every time.
fn cache() -> &'static Mutex<HashMap<Signature, Tx>> {
    static CACHE: OnceLock<Mutex<HashMap<Signature, Tx>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

pub async fn fetch_tx(rpc: &RpcClient, sig: &Signature) -> Result<Tx> {
    if let Some(tx) = cache().lock().unwrap().get(sig) {
        return Ok(tx.clone());
    }
    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };
    let encoded = rpc.get_transaction_with_config(sig, config).await?;
    let meta = encoded.transaction.meta.context("no status meta")?;
    ensure!(
        meta.err.is_none(),
        "transaction {sig} failed: {:?}",
        meta.err
    );
    let tx = Tx {
        slot: encoded.slot,
        block_time: encoded.block_time,
        tx: encoded
            .transaction
            .transaction
            .decode()
            .context("decode transaction")?,
    };
    cache().lock().unwrap().insert(*sig, tx.clone());
    Ok(tx)
}

// No lookup tables in our transactions, static keys are enough.
fn instructions(tx: &VersionedTransaction) -> Vec<(Address, Vec<Address>, &[u8])> {
    let keys = tx.message.static_account_keys();
    tx.message
        .instructions()
        .iter()
        .map(|ix| {
            let program = keys[ix.program_id_index as usize];
            let accounts = ix.accounts.iter().map(|&i| keys[i as usize]).collect();
            (program, accounts, ix.data.as_slice())
        })
        .collect()
}

pub struct TransferIx {
    pub source: Address,
    pub mint: Address,
    pub destination: Address,
    pub validity_context: Address,
    pub authority: Address,
    pub auditor_lo: PodElGamalCiphertext,
    pub auditor_hi: PodElGamalCiphertext,
}

pub fn find_transfer(tx: &VersionedTransaction) -> Result<TransferIx> {
    let mut found = instructions(tx).into_iter().filter(|(program, _, data)| {
        *program == spl_token_2022_interface::ID
            && data.first() == Some(&CONFIDENTIAL_TRANSFER_EXTENSION)
            && matches!(
                decode_instruction_type(&data[1..]),
                Ok(ConfidentialTransferInstruction::Transfer)
            )
    });
    let (_, accounts, data) = found.next().context("no confidential transfer")?;
    ensure!(
        found.next().is_none(),
        "more than one confidential transfer"
    );
    let ix: &TransferInstructionData =
        decode_instruction_data(&data[1..]).map_err(|e| anyhow!("transfer data: {e}"))?;
    ensure!(
        ix.equality_proof_instruction_offset == 0
            && ix.ciphertext_validity_proof_instruction_offset == 0
            && ix.range_proof_instruction_offset == 0
            && accounts.len() == 7,
        "transfer does not use context accounts for its proofs"
    );
    Ok(TransferIx {
        source: accounts[0],
        mint: accounts[1],
        destination: accounts[2],
        validity_context: accounts[4],
        authority: accounts[6],
        auditor_lo: ix.transfer_amount_auditor_ciphertext_lo,
        auditor_hi: ix.transfer_amount_auditor_ciphertext_hi,
    })
}

/// Finds the validity proof written into `context` and re-verifies it.
pub fn find_validity_context(
    tx: &VersionedTransaction,
    context: &Address,
) -> Result<Option<BatchedGroupedCiphertext3HandlesValidityProofContext>> {
    for (program, accounts, data) in instructions(tx) {
        if program != solana_zk_elgamal_proof_interface::ID
            || accounts.first() != Some(context)
            || !matches!(
                ProofInstruction::instruction_type(data),
                Some(ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity)
            )
        {
            continue;
        }
        let proof = ProofInstruction::proof_data::<
            BatchedGroupedCiphertext3HandlesValidityProofData,
            BatchedGroupedCiphertext3HandlesValidityProofContext,
        >(data)
        .context("validity proof data")?;
        proof
            .verify_proof()
            .map_err(|e| anyhow!("validity proof: {e}"))?;
        return Ok(Some(*proof.context_data()));
    }
    Ok(None)
}

pub struct Transfer {
    pub signature: Signature,
    pub validity_signature: Signature,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub ix: TransferIx,
    pub validity: BatchedGroupedCiphertext3HandlesValidityProofContext,
    pub memo_period: Option<String>,
}

impl Transfer {
    /// Pay period from the employer's memo, or the month of the block.
    pub fn period(&self) -> Result<String> {
        match &self.memo_period {
            Some(period) => Ok(period.clone()),
            None => Ok(fmt_month(self.block_time.context("no block time")?)),
        }
    }
}

/// A period memo counts only if the transfer authority signed it.
fn find_period_memo(tx: &VersionedTransaction, authority: &Address) -> Option<String> {
    instructions(tx)
        .into_iter()
        .find_map(|(program, accounts, data)| {
            if program != spl_memo_interface::v3::ID || !accounts.contains(authority) {
                return None;
            }
            let period = std::str::from_utf8(data).ok()?.strip_prefix(PERIOD_MEMO)?;
            parse_month(period).ok()?;
            Some(period.to_string())
        })
}

/// A transfer signature, plus the signature of its validity proof if known.
#[derive(Clone, Copy)]
pub struct TransferRef {
    pub transfer: Signature,
    pub validity: Option<Signature>,
}

/// Loads a transfer and its ciphertexts.
///
/// With a hint, the hinted transaction has to write the validity context the
/// transfer uses, and land before it. Only whoever holds the context
/// account's one-off keypair (the sender) can create that account, so the
/// hint can't point at someone else's ciphertexts. Without a hint, the context
/// account's history is searched, which is slower and rate-limited on devnet.
pub async fn fetch_transfer(rpc: &RpcClient, r: TransferRef) -> Result<Transfer> {
    let signature = r.transfer;
    let (transfer, hinted) = match r.validity {
        Some(validity) => {
            let (t, v) = tokio::try_join!(fetch_tx(rpc, &signature), fetch_tx(rpc, &validity))?;
            (t, Some((validity, v)))
        }
        None => (fetch_tx(rpc, &signature).await?, None),
    };
    let ix = find_transfer(&transfer.tx)?;

    let candidates = match hinted {
        Some(found) => vec![found],
        None => {
            let history = rpc
                .get_signatures_for_address_with_config(
                    &ix.validity_context,
                    GetConfirmedSignaturesForAddress2Config {
                        before: Some(signature),
                        commitment: Some(CommitmentConfig::confirmed()),
                        ..Default::default()
                    },
                )
                .await?;
            let mut txs = vec![];
            for entry in history.iter().filter(|e| e.err.is_none()) {
                let sig = Signature::from_str(&entry.signature)?;
                txs.push((sig, fetch_tx(rpc, &sig).await?));
            }
            txs
        }
    };

    for (validity_signature, tx) in candidates {
        let Some(validity) = find_validity_context(&tx.tx, &ix.validity_context)? else {
            continue;
        };
        ensure!(
            tx.slot <= transfer.slot,
            "validity proof for {signature} lands after the transfer"
        );
        let memo_period = find_period_memo(&transfer.tx, &ix.authority);
        return Ok(Transfer {
            signature,
            validity_signature,
            slot: transfer.slot,
            block_time: transfer.block_time,
            ix,
            validity,
            memo_period,
        });
    }
    bail!("no validity proof found for {signature}")
}

/// The public devnet RPC starts answering 429 beyond a few parallel requests.
const RPC_CONCURRENCY: usize = 3;

/// Same as `fetch_transfer` for many transfers, a few at a time, in order.
pub async fn fetch_transfers(rpc: &RpcClient, refs: &[TransferRef]) -> Result<Vec<Transfer>> {
    stream::iter(refs.iter().copied())
        .map(|r| fetch_transfer(rpc, r))
        .buffered(RPC_CONCURRENCY)
        .try_collect()
        .await
}

/// One party's ciphertext out of a grouped ciphertext.
pub fn part(
    grouped: &PodGroupedElGamalCiphertext3Handles,
    index: usize,
) -> Result<ElGamalCiphertext> {
    let grouped: GroupedElGamalCiphertext<3> = (*grouped)
        .try_into()
        .map_err(|e| anyhow!("grouped ciphertext: {e:?}"))?;
    grouped
        .to_elgamal_ciphertext(index)
        .map_err(|e| anyhow!("{e:?}"))
}
