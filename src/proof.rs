//! Income proof: "the transfers I received add up to at least `min`".
//!
//! The employee adds up the recipient halves of the transfer ciphertexts,
//! commits to the total `S` with a fresh Pedersen commitment `C`, and proves
//! 1. `C` and the ciphertext sum hide the same value (equality proof), and
//! 2. `C - min*G` opens to a 64-bit value, i.e. `S - min >= 0` (range proof).
//!
//! The verifier rebuilds the ciphertext sum from chain data on its own, so the
//! only thing it takes from the prover is the two proofs.

use {
    crate::{ct, onchain},
    anyhow::{Context, Result, anyhow, ensure},
    base64::{Engine, engine::general_purpose::STANDARD as BASE64},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    solana_address::Address,
    solana_keypair::Keypair,
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    solana_signature::Signature,
    solana_signer::Signer,
    solana_zk_elgamal_proof_interface::proof_data::{
        BatchedRangeProofU64Data, CiphertextCommitmentEqualityProofData, ZkProofData,
    },
    solana_zk_sdk::{
        encryption::{
            elgamal::{ElGamalCiphertext, ElGamalKeypair},
            pedersen::{Pedersen, PedersenCommitment, PedersenOpening},
        },
        zk_elgamal_proof_program::{
            VerifyZkProof, build_batched_range_proof_u64_data,
            build_ciphertext_commitment_equality_proof_data,
        },
    },
    solana_zk_sdk_pod::encryption::{
        elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
        pedersen::PodPedersenCommitment,
    },
    std::{collections::BTreeSet, str::FromStr},
};

/// Transfer amount ciphertext from its 16-bit and 32-bit halves.
pub fn combine(lo: &ElGamalCiphertext, hi: &ElGamalCiphertext) -> ElGamalCiphertext {
    lo + hi * (1u64 << 16)
}

pub struct Proofs {
    pub equality: CiphertextCommitmentEqualityProofData,
    pub range: BatchedRangeProofU64Data,
}

fn minus_min(commitment: &PedersenCommitment, min: u64) -> PedersenCommitment {
    commitment - Pedersen::with(min, &PedersenOpening::default())
}

pub fn build(
    keypair: &ElGamalKeypair,
    sum: &ElGamalCiphertext,
    total: u64,
    min: u64,
) -> Result<Proofs> {
    ensure!(total >= min, "total is below the threshold");
    let (commitment, opening) = Pedersen::new(total);
    let equality =
        build_ciphertext_commitment_equality_proof_data(keypair, sum, &commitment, &opening, total)
            .map_err(|e| anyhow!("equality proof: {e}"))?;
    let range = build_batched_range_proof_u64_data(
        vec![&minus_min(&commitment, min)],
        vec![total - min],
        vec![64],
        vec![&opening],
    )
    .map_err(|e| anyhow!("range proof: {e}"))?;
    Ok(Proofs { equality, range })
}

pub fn check(
    pubkey: &PodElGamalPubkey,
    sum: &ElGamalCiphertext,
    min: u64,
    proofs: &Proofs,
) -> Result<()> {
    let equality = proofs.equality.context_data();
    ensure!(
        equality.pubkey == *pubkey,
        "equality proof is for another key"
    );
    ensure!(
        equality.ciphertext == PodElGamalCiphertext::from(*sum),
        "equality proof is for another set of transfers"
    );
    proofs
        .equality
        .verify_proof()
        .map_err(|e| anyhow!("equality proof: {e}"))?;

    let commitment: PedersenCommitment = equality
        .commitment
        .try_into()
        .map_err(|e| anyhow!("commitment: {e:?}"))?;
    let range = proofs.range.context_data();
    ensure!(
        range.commitments[0] == PodPedersenCommitment::from(minus_min(&commitment, min)),
        "range proof is for another threshold"
    );
    ensure!(range.bit_lengths[0] == 64, "range proof is not 64-bit");
    proofs
        .range
        .verify_proof()
        .map_err(|e| anyhow!("range proof: {e}"))?;
    Ok(())
}

/// What the employee hands to a landlord or a bank.
#[derive(Serialize, Deserialize)]
pub struct IncomeProof {
    pub mint: String,
    pub employee: String,
    pub min: u64,
    pub transfers: Vec<String>,
    pub equality: String,
    pub range: String,
}

fn encode<T: bytemuck::Pod>(value: &T) -> String {
    BASE64.encode(bytemuck::bytes_of(value))
}

fn decode<T: bytemuck::Pod>(s: &str) -> Result<T> {
    let bytes = BASE64.decode(s)?;
    bytemuck::try_pod_read_unaligned(&bytes).map_err(|e| anyhow!("proof bytes: {e}"))
}

fn recipient_part(t: &onchain::Transfer) -> Result<(ElGamalCiphertext, ElGamalCiphertext)> {
    Ok((
        onchain::part(&t.validity.grouped_ciphertext_lo, onchain::DESTINATION)?,
        onchain::part(&t.validity.grouped_ciphertext_hi, onchain::DESTINATION)?,
    ))
}

/// Returns the proof and the decrypted total.
pub async fn prove(
    rpc: &RpcClient,
    employee: &Keypair,
    mint: &Address,
    transfers: &[Signature],
    min: u64,
) -> Result<(IncomeProof, u64)> {
    let account = ct::token_account(&employee.pubkey(), mint);
    let (keypair, _) = ct::account_keys(employee, &account)?;
    let decrypt = |ct: &ElGamalCiphertext| ct.decrypt_u32(keypair.secret()).context("decrypt");

    let mut sum = ElGamalCiphertext::default();
    let mut total = 0;
    for sig in transfers {
        let t = onchain::fetch_transfer(rpc, sig).await?;
        ensure!(
            t.ix.destination == account,
            "{sig} was not sent to {account}"
        );
        let (lo, hi) = recipient_part(&t)?;
        total += decrypt(&lo)? + (decrypt(&hi)? << 16);
        sum = sum + combine(&lo, &hi);
    }
    let proofs = build(&keypair, &sum, total, min)?;
    let proof = IncomeProof {
        mint: mint.to_string(),
        employee: employee.pubkey().to_string(),
        min,
        transfers: transfers.iter().map(ToString::to_string).collect(),
        equality: encode(&proofs.equality),
        range: encode(&proofs.range),
    };
    Ok((proof, total))
}

pub struct Verdict {
    pub transfers: usize,
    pub first_time: Option<i64>,
    pub last_time: Option<i64>,
    /// sha256 of the sorted transfer signatures.
    pub tx_set_hash: String,
}

/// Checks the proof against chain data. `employer` and `min` come from the
/// verifier, not from the proof file. A proof for a higher threshold also
/// covers a lower one.
pub async fn verify(
    rpc: &RpcClient,
    proof: &IncomeProof,
    employer: &Address,
    min: u64,
) -> Result<Verdict> {
    let mint = Address::from_str(&proof.mint)?;
    let employee = Address::from_str(&proof.employee)?;
    let source = ct::token_account(employer, &mint);
    let destination = ct::token_account(&employee, &mint);
    let proofs = Proofs {
        equality: decode(&proof.equality)?,
        range: decode(&proof.range)?,
    };
    let pubkey = proofs.equality.context_data().pubkey;
    ensure!(
        proof.min >= min,
        "proof only covers {}",
        crate::fmt_amount(proof.min)
    );

    let mut signatures = BTreeSet::new();
    let mut sum = ElGamalCiphertext::default();
    let mut times = vec![];
    for s in &proof.transfers {
        let sig = Signature::from_str(s)?;
        ensure!(signatures.insert(sig), "{sig} is listed twice");
        let t = onchain::fetch_transfer(rpc, &sig).await?;
        ensure!(t.ix.mint == mint, "{sig}: different mint");
        ensure!(t.ix.source == source, "{sig}: not from the employer");
        ensure!(
            t.ix.destination == destination,
            "{sig}: not to the employee"
        );
        ensure!(
            t.validity.second_pubkey == pubkey,
            "{sig}: encrypted to another key"
        );
        let (lo, hi) = recipient_part(&t)?;
        sum = sum + combine(&lo, &hi);
        times.extend(t.block_time);
    }
    ensure!(!signatures.is_empty(), "no transfers");
    check(&pubkey, &sum, proof.min, &proofs)?;

    let mut hasher = Sha256::new();
    for sig in &signatures {
        hasher.update(sig.as_ref());
    }
    Ok(Verdict {
        transfers: signatures.len(),
        first_time: times.iter().min().copied(),
        last_time: times.iter().max().copied(),
        tx_set_hash: hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encrypts each amount the way a confidential transfer does: 16 low bits
    // and 32 high bits separately.
    fn paid(keypair: &ElGamalKeypair, amounts: &[u64]) -> (ElGamalCiphertext, u64) {
        let pubkey = keypair.pubkey();
        amounts
            .iter()
            .fold((ElGamalCiphertext::default(), 0), |(sum, total), &a| {
                let (lo, hi) = (pubkey.encrypt(a & 0xffff), pubkey.encrypt(a >> 16));
                (sum + combine(&lo, &hi), total + a)
            })
    }

    const SALARIES: [u64; 3] = [320000, 345050, 310000];

    #[test]
    fn proves_income_above_threshold() {
        let keypair = ElGamalKeypair::new_rand();
        let (sum, total) = paid(&keypair, &SALARIES);
        let pubkey = keypair.pubkey_owned().into();
        for min in [0, 900000, total] {
            let proofs = build(&keypair, &sum, total, min).unwrap();
            check(&pubkey, &sum, min, &proofs).unwrap();
        }
    }

    #[test]
    fn cannot_claim_more_than_paid() {
        let keypair = ElGamalKeypair::new_rand();
        let (sum, total) = paid(&keypair, &SALARIES);
        assert!(build(&keypair, &sum, total, total + 1).is_err());

        // Skipping the guard: prove the wrapped-around difference instead.
        let min = total + 1;
        let (commitment, opening) = Pedersen::new(total);
        let forged = build_batched_range_proof_u64_data(
            vec![&minus_min(&commitment, min)],
            vec![total.wrapping_sub(min)],
            vec![64],
            vec![&opening],
        );
        if let Ok(range) = forged {
            let equality = build_ciphertext_commitment_equality_proof_data(
                &keypair,
                &sum,
                &commitment,
                &opening,
                total,
            )
            .unwrap();
            let proofs = Proofs { equality, range };
            assert!(check(&keypair.pubkey_owned().into(), &sum, min, &proofs).is_err());
        }
    }

    #[test]
    fn rejects_a_different_threshold() {
        let keypair = ElGamalKeypair::new_rand();
        let (sum, total) = paid(&keypair, &SALARIES);
        let proofs = build(&keypair, &sum, total, 900000).unwrap();
        let pubkey = keypair.pubkey_owned().into();
        assert!(check(&pubkey, &sum, 950000, &proofs).is_err());
        assert!(check(&pubkey, &sum, 800000, &proofs).is_err());
    }

    #[test]
    fn rejects_a_different_transfer_set() {
        let keypair = ElGamalKeypair::new_rand();
        let (sum, total) = paid(&keypair, &SALARIES);
        let proofs = build(&keypair, &sum, total, 900000).unwrap();
        let (fewer, _) = paid(&keypair, &SALARIES[..2]);
        assert!(check(&keypair.pubkey_owned().into(), &fewer, 900000, &proofs).is_err());
    }

    #[test]
    fn rejects_another_key() {
        let keypair = ElGamalKeypair::new_rand();
        let (sum, total) = paid(&keypair, &SALARIES);
        let proofs = build(&keypair, &sum, total, 900000).unwrap();
        let other = ElGamalKeypair::new_rand().pubkey_owned().into();
        assert!(check(&other, &sum, 900000, &proofs).is_err());
    }

    #[test]
    fn proof_bytes_round_trip() {
        let keypair = ElGamalKeypair::new_rand();
        let (sum, total) = paid(&keypair, &SALARIES);
        let proofs = build(&keypair, &sum, total, 900000).unwrap();
        let decoded = Proofs {
            equality: decode(&encode(&proofs.equality)).unwrap(),
            range: decode(&encode(&proofs.range)).unwrap(),
        };
        check(&keypair.pubkey_owned().into(), &sum, 900000, &decoded).unwrap();
    }
}
