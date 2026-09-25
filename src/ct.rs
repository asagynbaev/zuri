//! Token-2022 confidential transfer operations, built from raw instructions so
//! we know exactly which transaction carries which bytes (day 2 depends on it).

use {
    crate::{
        DECIMALS,
        chain::Chain,
        store::TransferRecord,
    },
    anyhow::{Context, Result, anyhow, ensure},
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_system_interface::instruction as system,
    solana_zk_elgamal_proof_interface::instruction::{ContextStateInfo, close_context_state},
    solana_zk_sdk::encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        derivation::derive_confidential_keys,
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    spl_associated_token_account_interface::{
        address::get_associated_token_address_with_program_id,
        instruction::create_associated_token_account_idempotent,
    },
    spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
            confidential_transfer::{
                ConfidentialTransferAccount, ConfidentialTransferMint,
                instruction::{
                    BatchedGroupedCiphertext3HandlesValidityProofContext,
                    BatchedRangeProofContext, CiphertextCommitmentEqualityProofContext,
                    ProofContextState, ProofInstruction, apply_pending_balance, configure_account,
                    deposit, initialize_mint as initialize_ct_mint, inner_transfer,
                },
            },
        },
        instruction::{initialize_mint2, mint_to_checked, reallocate},
        state::{Account, Mint},
    },
    spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation,
    spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data,
    solana_zk_sdk::zk_elgamal_proof_program::build_pubkey_validity_proof_data,
    std::mem::size_of,
};

const TOKEN_PROGRAM: Address = spl_token_2022_interface::ID;

/// `RecordData::WRITABLE_START_INDEX`: 1-byte version + 32-byte authority.
const RECORD_PROOF_OFFSET: u32 = 33;
/// Record write payloads that keep each transaction under the 1232-byte limit.
/// The first write also carries create_account + initialize.
const RECORD_FIRST_CHUNK: usize = 750;
const RECORD_WRITE_CHUNK: usize = 900;

pub fn token_account(owner: &Address, mint: &Address) -> Address {
    get_associated_token_address_with_program_id(owner, mint, &TOKEN_PROGRAM)
}

/// ElGamal + AES keys for `owner`'s account, derived by signing the canonical
/// `solana-conf-bal/v1` message with the account address as public seed.
pub fn account_keys(owner: &dyn Signer, token_account: &Address) -> Result<(ElGamalKeypair, AeKey)> {
    derive_confidential_keys(owner, token_account.as_ref()).map_err(|e| anyhow!("derive keys: {e}"))
}

pub struct CtAccount {
    pub public: u64,
    pub ext: ConfidentialTransferAccount,
}

pub async fn fetch_account(chain: &Chain, address: &Address) -> Result<Option<CtAccount>> {
    let Some(data) = chain.account_data(address).await? else {
        return Ok(None);
    };
    let state = StateWithExtensions::<Account>::unpack(&data)?;
    let Ok(ext) = state.get_extension::<ConfidentialTransferAccount>() else {
        return Ok(None);
    };
    Ok(Some(CtAccount { public: state.base.amount, ext: *ext }))
}

async fn auditor_pubkey(chain: &Chain, mint: &Address) -> Result<Option<ElGamalPubkey>> {
    let data = chain.account_data(mint).await?.context("mint not found")?;
    let state = StateWithExtensions::<Mint>::unpack(&data)?;
    let ext = state.get_extension::<ConfidentialTransferMint>()?;
    let pod: Option<PodElGamalPubkey> = ext.auditor_elgamal_pubkey.into();
    pod.map(|p| p.try_into().map_err(|e| anyhow!("auditor pubkey: {e:?}"))).transpose()
}

/// Mint with the ConfidentialTransferMint extension: auto-approved accounts and
/// an auditor who can decrypt every transfer amount. The payer is the mint
/// authority (it's our test stablecoin).
pub async fn create_mint(chain: &Chain, mint: &Keypair, auditor: &ElGamalPubkey) -> Result<()> {
    let authority = chain.payer.pubkey();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])?;
    let rent = chain.rpc.get_minimum_balance_for_rent_exemption(space).await?;
    let ixs = [
        system::create_account(&authority, &mint.pubkey(), rent, space as u64, &TOKEN_PROGRAM),
        initialize_ct_mint(
            &TOKEN_PROGRAM,
            &mint.pubkey(),
            Some(authority),
            true,
            Some(PodElGamalPubkey::from(*auditor)),
        )?,
        initialize_mint2(&TOKEN_PROGRAM, &mint.pubkey(), &authority, None, DECIMALS)?,
    ];
    chain.send("create mint", &ixs, &[mint]).await?;
    Ok(())
}

/// ATA + realloc for the ConfidentialTransferAccount extension + configure
/// (with the pubkey-validity proof inline), all in one transaction.
pub async fn create_account(chain: &Chain, owner: &Keypair, mint: &Address) -> Result<Address> {
    let payer = chain.payer.pubkey();
    let account = token_account(&owner.pubkey(), mint);
    let (elgamal, aes) = account_keys(owner, &account)?;
    let proof = build_pubkey_validity_proof_data(&elgamal).map_err(|e| anyhow!("{e}"))?;

    let mut ixs = vec![
        create_associated_token_account_idempotent(&payer, &owner.pubkey(), mint, &TOKEN_PROGRAM),
        reallocate(
            &TOKEN_PROGRAM,
            &account,
            &payer,
            &owner.pubkey(),
            &[],
            &[ExtensionType::ConfidentialTransferAccount],
        )?,
    ];
    ixs.extend(configure_account(
        &TOKEN_PROGRAM,
        &account,
        mint,
        &aes.encrypt(0).into(),
        spl_token_2022_interface::extension::confidential_transfer::DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER,
        &owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(1.try_into()?, &proof),
    )?);
    chain.send("configure account", &ixs, &[owner]).await?;
    Ok(account)
}

/// Mint public tokens to the payer's account and move them into its pending
/// confidential balance.
pub async fn mint_and_deposit(chain: &Chain, mint: &Address, amount: u64) -> Result<()> {
    let payer = chain.payer.pubkey();
    let account = token_account(&payer, mint);
    let ixs = [
        mint_to_checked(&TOKEN_PROGRAM, mint, &account, &payer, &[], amount, DECIMALS)?,
        deposit(&TOKEN_PROGRAM, &account, mint, amount, DECIMALS, &payer, &[])?,
    ];
    chain.send("mint + deposit", &ixs, &[]).await?;
    Ok(())
}

/// Decrypted confidential balances (base units).
pub struct Balances {
    pub public: u64,
    pub pending: u64,
    pub available: u64,
    pub credit_counter: u64,
}

pub async fn balances(chain: &Chain, owner: &dyn Signer, mint: &Address) -> Result<Balances> {
    let account = token_account(&owner.pubkey(), mint);
    let CtAccount { public, ext } =
        fetch_account(chain, &account).await?.context("account not configured")?;
    let (elgamal, aes) = account_keys(owner, &account)?;
    let decrypt = |ct: &solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext| -> Result<u64> {
        let ct: ElGamalCiphertext = (*ct).try_into().map_err(|e| anyhow!("{e:?}"))?;
        ct.decrypt_u32(elgamal.secret()).context("pending balance outside u32 range")
    };
    let pending = decrypt(&ext.pending_balance_lo)? + (decrypt(&ext.pending_balance_hi)? << 16);
    let available_ct: AeCiphertext =
        ext.decryptable_available_balance.try_into().map_err(|e| anyhow!("{e:?}"))?;
    let available = aes.decrypt(&available_ct).context("decrypt available balance")?;
    Ok(Balances {
        public,
        pending,
        available,
        credit_counter: u64::from(ext.pending_balance_credit_counter),
    })
}

pub async fn apply_pending(chain: &Chain, owner: &Keypair, mint: &Address) -> Result<Option<u64>> {
    let account = token_account(&owner.pubkey(), mint);
    let b = balances(chain, owner, mint).await?;
    if b.credit_counter == 0 {
        return Ok(None);
    }
    let (_, aes) = account_keys(owner, &account)?;
    let ix = apply_pending_balance(
        &TOKEN_PROGRAM,
        &account,
        b.credit_counter,
        &aes.encrypt(b.available + b.pending).into(),
        &owner.pubkey(),
        &[],
    )?;
    chain.send("apply pending", &[ix], &[owner]).await?;
    Ok(Some(b.pending))
}

/// Confidential transfer from `sender`'s account to `recipient`'s. Five
/// transactions (the proofs don't fit in one):
///   1. create + verify the equality proof context
///   2. create + verify the ciphertext-validity proof context. Its instruction
///      data holds the grouped ciphertexts (source/destination/auditor handles)
///   3. stage the range proof into a record account (first chunk)
///   4. rest of the record + create + verify the range proof context from it
///   5. Transfer (references the three contexts) + close them + close record
///
/// The payer is the context-state authority; since the payer is also the
/// employer, the sender adds no extra account keys to the verify transactions.
pub async fn transfer(
    chain: &Chain,
    sender: &Keypair,
    mint: &Address,
    recipient: &Address,
    amount: u64,
) -> Result<TransferRecord> {
    let payer = chain.payer.pubkey();
    let source = token_account(&sender.pubkey(), mint);
    let destination = token_account(recipient, mint);

    let source_state = fetch_account(chain, &source).await?.context("source not configured")?;
    let destination_state =
        fetch_account(chain, &destination).await?.context("destination not configured")?;
    let destination_elgamal: ElGamalPubkey = destination_state
        .ext
        .elgamal_pubkey
        .try_into()
        .map_err(|e| anyhow!("destination pubkey: {e:?}"))?;
    let auditor = auditor_pubkey(chain, mint).await?;

    let (source_elgamal, source_aes) = account_keys(sender, &source)?;
    let available: ElGamalCiphertext =
        source_state.ext.available_balance.try_into().map_err(|e| anyhow!("{e:?}"))?;
    let decryptable: AeCiphertext =
        source_state.ext.decryptable_available_balance.try_into().map_err(|e| anyhow!("{e:?}"))?;
    let current = source_aes.decrypt(&decryptable).context("decrypt sender balance")?;
    ensure!(current >= amount, "sender has {current}, needs {amount}");

    let proofs = transfer_split_proof_data(
        &available,
        &decryptable,
        amount,
        &source_elgamal,
        &source_aes,
        &destination_elgamal,
        auditor.as_ref(),
    )
    .map_err(|e| anyhow!("transfer proofs: {e}"))?;

    let equality = Keypair::new();
    let validity = Keypair::new();
    let range = Keypair::new();
    let record = Keypair::new();
    let (equality_ctx, validity_ctx, range_ctx) = (equality.pubkey(), validity.pubkey(), range.pubkey());
    let rent = |size: usize| chain.rpc.get_minimum_balance_for_rent_exemption(size);

    // 1. equality
    let size = size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>();
    let equality_sig = chain
        .send(
            "equality proof",
            &[
                system::create_account(&payer, &equality.pubkey(), rent(size).await?, size as u64, &solana_zk_elgamal_proof_interface::ID),
                ProofInstruction::VerifyCiphertextCommitmentEquality
                    .encode_verify_proof(Some(ctx(&equality_ctx, &payer)), &proofs.equality_proof_data),
            ],
            &[&equality],
        )
        .await?;

    // 2. ciphertext validity
    let size = size_of::<ProofContextState<BatchedGroupedCiphertext3HandlesValidityProofContext>>();
    let validity_sig = chain
        .send(
            "validity proof",
            &[
                system::create_account(&payer, &validity.pubkey(), rent(size).await?, size as u64, &solana_zk_elgamal_proof_interface::ID),
                ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity.encode_verify_proof(
                    Some(ctx(&validity_ctx, &payer)),
                    &proofs.ciphertext_validity_proof_data_with_ciphertext.proof_data,
                ),
            ],
            &[&validity],
        )
        .await?;

    // 3-4. range proof via a record account
    let proof_bytes = bytemuck::bytes_of(&proofs.range_proof_data);
    let record_space = proof_bytes.len() + RECORD_PROOF_OFFSET as usize;
    let (first, rest) = proof_bytes.split_at(proof_bytes.len().min(RECORD_FIRST_CHUNK));
    let mut range_sigs = vec![
        chain
            .send(
                "range proof: stage 1",
                &[
                    system::create_account(&payer, &record.pubkey(), rent(record_space).await?, record_space as u64, &spl_record::ID),
                    spl_record::instruction::initialize(&record.pubkey(), &payer),
                    spl_record::instruction::write(&record.pubkey(), &payer, 0, first),
                ],
                &[&record],
            )
            .await?,
    ];
    let size = size_of::<ProofContextState<BatchedRangeProofContext>>();
    let verify_range = [
        system::create_account(&payer, &range.pubkey(), rent(size).await?, size as u64, &solana_zk_elgamal_proof_interface::ID),
        ProofInstruction::VerifyBatchedRangeProofU128.encode_verify_proof_from_account(
            Some(ctx(&range_ctx, &payer)),
            &record.pubkey(),
            RECORD_PROOF_OFFSET,
        ),
    ];
    let chunks: Vec<&[u8]> = rest.chunks(RECORD_WRITE_CHUNK).collect();
    let mut offset = first.len();
    for (i, chunk) in chunks.iter().enumerate() {
        let mut ixs = vec![spl_record::instruction::write(&record.pubkey(), &payer, offset as u64, chunk)];
        let mut signers: Vec<&dyn Signer> = vec![];
        if i + 1 == chunks.len() {
            ixs.extend_from_slice(&verify_range);
            signers.push(&range);
        }
        range_sigs.push(chain.send(&format!("range proof: stage {}", i + 2), &ixs, &signers).await?);
        offset += chunk.len();
    }
    if chunks.is_empty() {
        range_sigs.push(chain.send("range proof: verify", &verify_range, &[&range]).await?);
    }

    // 5. transfer + cleanup
    let new_decryptable = source_aes.encrypt(current - amount).into();
    let validity_data = &proofs.ciphertext_validity_proof_data_with_ciphertext;
    let close = |account: &Address| close_context_state(ctx(account, &payer), &payer);
    let ixs = [
        inner_transfer(
            &TOKEN_PROGRAM,
            &source,
            mint,
            &destination,
            &new_decryptable,
            &validity_data.ciphertext_lo,
            &validity_data.ciphertext_hi,
            &sender.pubkey(),
            &[],
            ProofLocation::ContextStateAccount(&equality_ctx),
            ProofLocation::ContextStateAccount(&validity_ctx),
            ProofLocation::ContextStateAccount(&range_ctx),
        )?,
        close(&equality_ctx),
        close(&validity_ctx),
        close(&range_ctx),
        spl_record::instruction::close_account(&record.pubkey(), &payer, &payer),
    ];
    let transfer_sig = chain.send("transfer + close", &ixs, &[sender]).await?;

    Ok(TransferRecord {
        amount,
        equality_context: equality.pubkey().to_string(),
        validity_context: validity.pubkey().to_string(),
        range_context: range.pubkey().to_string(),
        record_account: record.pubkey().to_string(),
        equality_sig: equality_sig.to_string(),
        validity_sig: validity_sig.to_string(),
        range_sigs: range_sigs.iter().map(ToString::to_string).collect(),
        transfer_sig: transfer_sig.to_string(),
    })
}

fn ctx<'a>(account: &'a Address, authority: &'a Address) -> ContextStateInfo<'a> {
    ContextStateInfo { context_state_account: account, context_state_authority: authority }
}
