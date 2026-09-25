use {
    crate::{DECIMALS, chain::Chain, store::TransferRecord},
    anyhow::{Context, Result, anyhow, ensure},
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_system_interface::instruction as system,
    solana_zk_elgamal_proof_interface::instruction::{ContextStateInfo, close_context_state},
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            derivation::derive_confidential_keys,
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
        },
        zk_elgamal_proof_program::build_pubkey_validity_proof_data,
    },
    solana_zk_sdk_pod::encryption::elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
    spl_associated_token_account_interface::{
        address::get_associated_token_address_with_program_id,
        instruction::create_associated_token_account_idempotent,
    },
    spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
            confidential_transfer::{
                ConfidentialTransferAccount, ConfidentialTransferMint,
                DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER,
                instruction::{
                    BatchedGroupedCiphertext3HandlesValidityProofContext, BatchedRangeProofContext,
                    CiphertextCommitmentEqualityProofContext, ProofContextState, ProofInstruction,
                    apply_pending_balance, configure_account, deposit,
                    initialize_mint as initialize_ct_mint, inner_transfer,
                },
            },
        },
        instruction::{initialize_mint2, mint_to_checked, reallocate},
        state::{Account, Mint},
    },
    spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation,
    spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data,
    std::mem::size_of,
};

const TOKEN_PROGRAM: Address = spl_token_2022_interface::ID;
const ZK_PROGRAM: Address = solana_zk_elgamal_proof_interface::ID;

// Record data starts after a 1-byte version and the 32-byte authority.
const RECORD_PROOF_OFFSET: u32 = 33;
// Chunk sizes that keep record writes under the 1232-byte tx limit.
const RECORD_FIRST_CHUNK: usize = 750;
const RECORD_WRITE_CHUNK: usize = 900;

pub fn token_account(owner: &Address, mint: &Address) -> Address {
    get_associated_token_address_with_program_id(owner, mint, &TOKEN_PROGRAM)
}

/// ElGamal and AES keys for a token account, derived from the owner's signature.
pub fn account_keys(owner: &dyn Signer, account: &Address) -> Result<(ElGamalKeypair, AeKey)> {
    derive_confidential_keys(owner, account.as_ref()).map_err(|e| anyhow!("derive keys: {e}"))
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
    Ok(Some(CtAccount {
        public: state.base.amount,
        ext: *ext,
    }))
}

async fn auditor_pubkey(chain: &Chain, mint: &Address) -> Result<Option<ElGamalPubkey>> {
    let data = chain.account_data(mint).await?.context("mint not found")?;
    let state = StateWithExtensions::<Mint>::unpack(&data)?;
    let ext = state.get_extension::<ConfidentialTransferMint>()?;
    let pod: Option<PodElGamalPubkey> = ext.auditor_elgamal_pubkey.into();
    pod.map(|p| p.try_into().map_err(|e| anyhow!("auditor pubkey: {e:?}")))
        .transpose()
}

fn decrypt_u32(ct: &PodElGamalCiphertext, keypair: &ElGamalKeypair) -> Result<u64> {
    let ct: ElGamalCiphertext = (*ct).try_into().map_err(|e| anyhow!("{e:?}"))?;
    ct.decrypt_u32(keypair.secret())
        .context("value out of u32 range")
}

/// Test stablecoin: payer is the mint authority, accounts are auto-approved.
pub async fn create_mint(chain: &Chain, mint: &Keypair, auditor: &ElGamalPubkey) -> Result<()> {
    let authority = chain.payer.pubkey();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])?;
    let rent = chain
        .rpc
        .get_minimum_balance_for_rent_exemption(space)
        .await?;
    let ixs = [
        system::create_account(
            &authority,
            &mint.pubkey(),
            rent,
            space as u64,
            &TOKEN_PROGRAM,
        ),
        initialize_ct_mint(
            &TOKEN_PROGRAM,
            &mint.pubkey(),
            Some(authority),
            true,
            Some((*auditor).into()),
        )?,
        initialize_mint2(&TOKEN_PROGRAM, &mint.pubkey(), &authority, None, DECIMALS)?,
    ];
    chain.send("create mint", &ixs, &[mint]).await?;
    Ok(())
}

/// Creates the owner's ATA and configures it for confidential transfers.
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
        DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER,
        &owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(1.try_into()?, &proof),
    )?);
    chain.send("configure account", &ixs, &[owner]).await?;
    Ok(account)
}

pub async fn mint_and_deposit(chain: &Chain, mint: &Address, amount: u64) -> Result<()> {
    let payer = chain.payer.pubkey();
    let account = token_account(&payer, mint);
    let ixs = [
        mint_to_checked(
            &TOKEN_PROGRAM,
            mint,
            &account,
            &payer,
            &[],
            amount,
            DECIMALS,
        )?,
        deposit(
            &TOKEN_PROGRAM,
            &account,
            mint,
            amount,
            DECIMALS,
            &payer,
            &[],
        )?,
    ];
    chain.send("mint + deposit", &ixs, &[]).await?;
    Ok(())
}

pub struct Balances {
    pub public: u64,
    pub pending: u64,
    pub available: u64,
    pub credit_counter: u64,
}

pub async fn balances(chain: &Chain, owner: &dyn Signer, mint: &Address) -> Result<Balances> {
    let account = token_account(&owner.pubkey(), mint);
    let CtAccount { public, ext } = fetch_account(chain, &account)
        .await?
        .context("account not configured")?;
    let (elgamal, aes) = account_keys(owner, &account)?;
    let pending = decrypt_u32(&ext.pending_balance_lo, &elgamal)?
        + (decrypt_u32(&ext.pending_balance_hi, &elgamal)? << 16);
    let available: AeCiphertext = ext
        .decryptable_available_balance
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))?;
    Ok(Balances {
        public,
        pending,
        available: aes.decrypt(&available).context("decrypt available")?,
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

fn ctx<'a>(account: &'a Address, authority: &'a Address) -> ContextStateInfo<'a> {
    ContextStateInfo {
        context_state_account: account,
        context_state_authority: authority,
    }
}

/// Confidential transfer. The proofs don't fit into one transaction, so this
/// takes five: equality proof, validity proof, two for the range proof (staged
/// in a record account), then the transfer itself, which also closes the
/// proof accounts. The payer owns the proof contexts.
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

    let source_state = fetch_account(chain, &source)
        .await?
        .context("source not configured")?;
    let destination_state = fetch_account(chain, &destination)
        .await?
        .context("destination not configured")?;
    let destination_elgamal: ElGamalPubkey = destination_state
        .ext
        .elgamal_pubkey
        .try_into()
        .map_err(|e| anyhow!("destination pubkey: {e:?}"))?;
    let auditor = auditor_pubkey(chain, mint).await?;

    let (source_elgamal, source_aes) = account_keys(sender, &source)?;
    let available: ElGamalCiphertext = source_state
        .ext
        .available_balance
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))?;
    let decryptable: AeCiphertext = source_state
        .ext
        .decryptable_available_balance
        .try_into()
        .map_err(|e| anyhow!("{e:?}"))?;
    let current = source_aes
        .decrypt(&decryptable)
        .context("decrypt balance")?;
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
    let (equality_ctx, validity_ctx, range_ctx) =
        (equality.pubkey(), validity.pubkey(), range.pubkey());
    let rent = |size: usize| chain.rpc.get_minimum_balance_for_rent_exemption(size);

    let size = size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>();
    let equality_sig = chain
        .send(
            "equality proof",
            &[
                system::create_account(
                    &payer,
                    &equality_ctx,
                    rent(size).await?,
                    size as u64,
                    &ZK_PROGRAM,
                ),
                ProofInstruction::VerifyCiphertextCommitmentEquality.encode_verify_proof(
                    Some(ctx(&equality_ctx, &payer)),
                    &proofs.equality_proof_data,
                ),
            ],
            &[&equality],
        )
        .await?;

    let size = size_of::<ProofContextState<BatchedGroupedCiphertext3HandlesValidityProofContext>>();
    let validity_sig = chain
        .send(
            "validity proof",
            &[
                system::create_account(
                    &payer,
                    &validity_ctx,
                    rent(size).await?,
                    size as u64,
                    &ZK_PROGRAM,
                ),
                ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
                    .encode_verify_proof(
                        Some(ctx(&validity_ctx, &payer)),
                        &proofs
                            .ciphertext_validity_proof_data_with_ciphertext
                            .proof_data,
                    ),
            ],
            &[&validity],
        )
        .await?;

    let proof_bytes = bytemuck::bytes_of(&proofs.range_proof_data);
    let record_space = proof_bytes.len() + RECORD_PROOF_OFFSET as usize;
    let (first, rest) = proof_bytes.split_at(proof_bytes.len().min(RECORD_FIRST_CHUNK));
    let mut range_sigs = vec![
        chain
            .send(
                "range proof 1",
                &[
                    system::create_account(
                        &payer,
                        &record.pubkey(),
                        rent(record_space).await?,
                        record_space as u64,
                        &spl_record::ID,
                    ),
                    spl_record::instruction::initialize(&record.pubkey(), &payer),
                    spl_record::instruction::write(&record.pubkey(), &payer, 0, first),
                ],
                &[&record],
            )
            .await?,
    ];
    let size = size_of::<ProofContextState<BatchedRangeProofContext>>();
    let verify_range = [
        system::create_account(
            &payer,
            &range_ctx,
            rent(size).await?,
            size as u64,
            &ZK_PROGRAM,
        ),
        ProofInstruction::VerifyBatchedRangeProofU128.encode_verify_proof_from_account(
            Some(ctx(&range_ctx, &payer)),
            &record.pubkey(),
            RECORD_PROOF_OFFSET,
        ),
    ];
    let chunks: Vec<&[u8]> = rest.chunks(RECORD_WRITE_CHUNK).collect();
    let mut offset = first.len();
    for (i, chunk) in chunks.iter().enumerate() {
        let mut ixs = vec![spl_record::instruction::write(
            &record.pubkey(),
            &payer,
            offset as u64,
            chunk,
        )];
        let mut signers: Vec<&dyn Signer> = vec![];
        if i + 1 == chunks.len() {
            ixs.extend_from_slice(&verify_range);
            signers.push(&range);
        }
        let label = format!("range proof {}", i + 2);
        range_sigs.push(chain.send(&label, &ixs, &signers).await?);
        offset += chunk.len();
    }
    if chunks.is_empty() {
        range_sigs.push(
            chain
                .send("range proof 2", &verify_range, &[&range])
                .await?,
        );
    }

    let validity_data = &proofs.ciphertext_validity_proof_data_with_ciphertext;
    let close = |account: &Address| close_context_state(ctx(account, &payer), &payer);
    let ixs = [
        inner_transfer(
            &TOKEN_PROGRAM,
            &source,
            mint,
            &destination,
            &source_aes.encrypt(current - amount).into(),
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
    let transfer_sig = chain.send("transfer", &ixs, &[sender]).await?;

    Ok(TransferRecord {
        amount,
        equality_context: equality_ctx.to_string(),
        validity_context: validity_ctx.to_string(),
        range_context: range_ctx.to_string(),
        record_account: record.pubkey().to_string(),
        equality_sig: equality_sig.to_string(),
        validity_sig: validity_sig.to_string(),
        range_sigs: range_sigs.iter().map(ToString::to_string).collect(),
        transfer_sig: transfer_sig.to_string(),
    })
}
