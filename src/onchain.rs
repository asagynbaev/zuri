//! Day 2: recover a confidential transfer's ciphertexts from chain data alone.
//!
//! Layout (context-state proof mode, as sent by `ct::transfer`):
//! - The Token-2022 `Transfer` instruction carries only the auditor's lo/hi
//!   ciphertexts. Its accounts are
//!   `[source, mint, destination, equality_ctx, validity_ctx, range_ctx, authority]`.
//! - The full grouped ciphertexts (one commitment + source/destination/auditor
//!   handles, for lo and hi) live in the instruction data of the ZK ElGamal
//!   proof program's `VerifyBatchedGroupedCiphertext3HandlesValidity`, sent in
//!   an earlier transaction that wrote `validity_ctx`. The context account is
//!   closed afterwards, so the instruction data is the durable copy.
//!
//! Byte offsets in that instruction's data:
//!   0         discriminator
//!   1..33     source ElGamal pubkey
//!   33..65    destination ElGamal pubkey
//!   65..97    auditor ElGamal pubkey
//!   97..225   grouped ciphertext lo: commitment | source | destination | auditor handle
//!   225..353  grouped ciphertext hi: same
//!   353..     sigma proof

use {
    crate::chain::Chain,
    anyhow::{Context, Result, anyhow, bail, ensure},
    solana_address::Address,
    solana_commitment_config::CommitmentConfig,
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
};

/// Index of each party's decrypt handle inside a grouped ciphertext.
pub const SOURCE: usize = 0;
pub const DESTINATION: usize = 1;
pub const AUDITOR: usize = 2;

/// `TokenInstruction::ConfidentialTransferExtension`.
const CONFIDENTIAL_TRANSFER_EXTENSION: u8 = 27;

pub struct Tx {
    pub slot: u64,
    pub block_time: Option<i64>,
    pub tx: VersionedTransaction,
}

pub async fn fetch_tx(chain: &Chain, sig: &Signature) -> Result<Tx> {
    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Base64),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };
    let encoded = chain.rpc.get_transaction_with_config(sig, config).await?;
    let meta = encoded.transaction.meta.context("transaction has no status meta")?;
    ensure!(meta.err.is_none(), "transaction {sig} failed: {:?}", meta.err);
    let tx = encoded.transaction.transaction.decode().context("decode transaction")?;
    Ok(Tx { slot: encoded.slot, block_time: encoded.block_time, tx })
}

/// Instructions of a legacy/v0 transaction without lookup tables, with their
/// program id and account addresses resolved.
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

/// The Token-2022 confidential `Transfer` instruction in a transaction.
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
    let (_, accounts, data) = found.next().context("no confidential Transfer instruction")?;
    ensure!(found.next().is_none(), "more than one confidential Transfer in the transaction");
    let ix: &TransferInstructionData =
        decode_instruction_data(&data[1..]).map_err(|e| anyhow!("transfer data: {e}"))?;
    // All three proofs referenced as context accounts, no instructions sysvar.
    ensure!(
        ix.equality_proof_instruction_offset == 0
            && ix.ciphertext_validity_proof_instruction_offset == 0
            && ix.range_proof_instruction_offset == 0
            && accounts.len() == 7,
        "transfer does not use context-state proofs"
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

/// The ciphertext-validity verification that wrote `context`, re-verified
/// off-chain from the instruction bytes.
pub fn find_validity_context(
    tx: &VersionedTransaction,
    context: &Address,
) -> Result<BatchedGroupedCiphertext3HandlesValidityProofContext> {
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
        proof.verify_proof().map_err(|e| anyhow!("validity proof does not verify: {e}"))?;
        return Ok(*proof.context_data());
    }
    bail!("no validity proof verification into {context}")
}

/// One party's view of a grouped ciphertext.
pub fn part(grouped: &PodGroupedElGamalCiphertext3Handles, index: usize) -> Result<ElGamalCiphertext> {
    let grouped: GroupedElGamalCiphertext<3> =
        (*grouped).try_into().map_err(|e| anyhow!("grouped ciphertext: {e:?}"))?;
    grouped.to_elgamal_ciphertext(index).map_err(|e| anyhow!("{e:?}"))
}
