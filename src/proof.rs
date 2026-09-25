//! Income proof: "in every period I received at least `min`".
//!
//! For each period (a month, or everything at once) the employee adds up the
//! recipient halves of the transfer ciphertexts, commits to the total `S` with
//! a fresh Pedersen commitment `C`, and proves that `C` and the ciphertext sum
//! hide the same value (equality proof). One batched range proof then shows
//! that every `C - min*G` opens to a 32-bit value, i.e. `S - min >= 0`.
//!
//! The verifier rebuilds each period's ciphertext sum from chain data on its
//! own, so all it takes from the prover is the proofs.

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
        BatchedRangeProofU256Data, CiphertextCommitmentEqualityProofData, ZkProofData,
    },
    solana_zk_sdk::{
        encryption::{
            elgamal::{ElGamalCiphertext, ElGamalKeypair},
            pedersen::{Pedersen, PedersenCommitment, PedersenOpening},
        },
        zk_elgamal_proof_program::{
            VerifyZkProof, build_batched_range_proof_u256_data,
            build_ciphertext_commitment_equality_proof_data,
        },
    },
    solana_zk_sdk_pod::encryption::{
        elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
        pedersen::PodPedersenCommitment,
    },
    std::{
        collections::{BTreeMap, BTreeSet},
        str::FromStr,
    },
};

/// A batched range proof holds up to 8 commitments.
pub const MAX_PERIODS: usize = 8;
/// Room above the threshold per period: 2^32 base units.
const PERIOD_BITS: usize = 32;
const RANGE_BITS: usize = 256;
/// Label of the single period when transfers are not split by month.
pub const ALL: &str = "all";

/// Transfer amount ciphertext from its 16-bit and 32-bit halves.
pub fn combine(lo: &ElGamalCiphertext, hi: &ElGamalCiphertext) -> ElGamalCiphertext {
    lo + hi * (1u64 << 16)
}

pub struct Proofs {
    pub equalities: Vec<CiphertextCommitmentEqualityProofData>,
    pub range: BatchedRangeProofU256Data,
}

fn minus_min(commitment: &PedersenCommitment, min: u64) -> PedersenCommitment {
    commitment - Pedersen::with(min, &PedersenOpening::default())
}

/// `periods` holds each period's ciphertext sum and its decrypted total.
pub fn build(
    keypair: &ElGamalKeypair,
    periods: &[(ElGamalCiphertext, u64)],
    min: u64,
) -> Result<Proofs> {
    ensure!(
        (1..=MAX_PERIODS).contains(&periods.len()),
        "between 1 and {MAX_PERIODS} periods"
    );
    let mut equalities = vec![];
    let (mut commitments, mut amounts, mut bits, mut openings) = (vec![], vec![], vec![], vec![]);
    for (sum, total) in periods {
        ensure!(*total >= min, "income is below the threshold");
        ensure!(
            total - min < 1 << PERIOD_BITS,
            "income exceeds the threshold by more than 2^32 units"
        );
        let (commitment, opening) = Pedersen::new(*total);
        equalities.push(
            build_ciphertext_commitment_equality_proof_data(
                keypair,
                sum,
                &commitment,
                &opening,
                *total,
            )
            .map_err(|e| anyhow!("equality proof: {e}"))?,
        );
        commitments.push(minus_min(&commitment, min));
        amounts.push(total - min);
        bits.push(PERIOD_BITS);
        openings.push(opening);
    }
    // The bit lengths have to add up to exactly 256, fill the rest with zeros.
    let mut left = RANGE_BITS - PERIOD_BITS * periods.len();
    while left > 0 {
        let size = left.min(64);
        let (commitment, opening) = Pedersen::new(0u64);
        commitments.push(commitment);
        amounts.push(0);
        bits.push(size);
        openings.push(opening);
        left -= size;
    }
    let range = build_batched_range_proof_u256_data(
        commitments.iter().collect(),
        amounts,
        bits,
        openings.iter().collect(),
    )
    .map_err(|e| anyhow!("range proof: {e}"))?;
    Ok(Proofs { equalities, range })
}

/// `sums` are the per-period ciphertext sums the verifier computed itself.
pub fn check(
    pubkey: &PodElGamalPubkey,
    sums: &[ElGamalCiphertext],
    min: u64,
    proofs: &Proofs,
) -> Result<()> {
    ensure!(
        (1..=MAX_PERIODS).contains(&sums.len()) && proofs.equalities.len() == sums.len(),
        "wrong number of periods"
    );
    let range = proofs.range.context_data();
    for (i, (equality, sum)) in proofs.equalities.iter().zip(sums).enumerate() {
        let context = equality.context_data();
        ensure!(
            context.pubkey == *pubkey,
            "equality proof is for another key"
        );
        ensure!(
            context.ciphertext == PodElGamalCiphertext::from(*sum),
            "equality proof is for another set of transfers"
        );
        equality
            .verify_proof()
            .map_err(|e| anyhow!("equality proof: {e}"))?;

        let commitment: PedersenCommitment = context
            .commitment
            .try_into()
            .map_err(|e| anyhow!("commitment: {e:?}"))?;
        ensure!(
            range.commitments[i] == PodPedersenCommitment::from(minus_min(&commitment, min)),
            "range proof is for another threshold"
        );
        ensure!(
            usize::from(range.bit_lengths[i]) == PERIOD_BITS,
            "unexpected range proof layout"
        );
    }
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
    pub periods: Vec<Period>,
    pub range: String,
}

#[derive(Serialize, Deserialize)]
pub struct Period {
    /// YYYY-MM, or "all".
    pub label: String,
    pub transfers: Vec<String>,
    pub equality: String,
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

/// Returns the proof and the decrypted total of each period.
pub async fn prove(
    rpc: &RpcClient,
    employee: &Keypair,
    mint: &Address,
    transfers: &[Signature],
    min: u64,
    monthly: bool,
) -> Result<(IncomeProof, Vec<(String, u64)>)> {
    let account = ct::token_account(&employee.pubkey(), mint);
    let (keypair, _) = ct::account_keys(employee, &account)?;
    let decrypt = |ct: &ElGamalCiphertext| ct.decrypt_u32(keypair.secret()).context("decrypt");

    // label -> (signatures, ciphertext sum, total)
    let mut periods: BTreeMap<String, (Vec<String>, ElGamalCiphertext, u64)> = BTreeMap::new();
    for sig in transfers {
        let t = onchain::fetch_transfer(rpc, sig).await?;
        ensure!(
            t.ix.destination == account,
            "{sig} was not sent to {account}"
        );
        let label = if monthly {
            t.period()?
        } else {
            ALL.to_string()
        };
        let (lo, hi) = recipient_part(&t)?;
        let entry = periods.entry(label).or_default();
        entry.0.push(sig.to_string());
        entry.1 = entry.1 + combine(&lo, &hi);
        entry.2 += decrypt(&lo)? + (decrypt(&hi)? << 16);
    }

    let inputs: Vec<_> = periods
        .values()
        .map(|(_, sum, total)| (*sum, *total))
        .collect();
    let proofs = build(&keypair, &inputs, min)?;
    let totals = periods
        .iter()
        .map(|(label, p)| (label.clone(), p.2))
        .collect();
    let proof = IncomeProof {
        mint: mint.to_string(),
        employee: employee.pubkey().to_string(),
        min,
        periods: periods
            .into_iter()
            .zip(&proofs.equalities)
            .map(|((label, (transfers, _, _)), equality)| Period {
                label,
                transfers,
                equality: encode(equality),
            })
            .collect(),
        range: encode(&proofs.range),
    };
    Ok((proof, totals))
}

pub struct Verdict {
    pub periods: Vec<String>,
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
    ensure!(
        proof.min >= min,
        "proof only covers {}",
        crate::fmt_amount(proof.min)
    );
    let proofs = Proofs {
        equalities: proof
            .periods
            .iter()
            .map(|p| decode(&p.equality))
            .collect::<Result<_>>()?,
        range: decode(&proof.range)?,
    };
    let pubkey = proofs
        .equalities
        .first()
        .context("no periods")?
        .context_data()
        .pubkey;

    let mut labels = BTreeSet::new();
    let mut signatures = BTreeSet::new();
    let mut sums = vec![];
    let mut times = vec![];
    for period in &proof.periods {
        ensure!(
            labels.insert(&period.label),
            "period {} listed twice",
            period.label
        );
        ensure!(
            !period.transfers.is_empty(),
            "period {} is empty",
            period.label
        );
        let mut sum = ElGamalCiphertext::default();
        for s in &period.transfers {
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
            if period.label != ALL {
                let paid_for = t.period()?;
                ensure!(
                    paid_for == period.label,
                    "{sig}: paid for {paid_for}, listed under {}",
                    period.label
                );
            }
            let (lo, hi) = recipient_part(&t)?;
            sum = sum + combine(&lo, &hi);
            times.extend(t.block_time);
        }
        sums.push(sum);
    }
    check(&pubkey, &sums, proof.min, &proofs)?;

    let mut hasher = Sha256::new();
    for sig in &signatures {
        hasher.update(sig.as_ref());
    }
    Ok(Verdict {
        periods: proof.periods.iter().map(|p| p.label.clone()).collect(),
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

    fn months(keypair: &ElGamalKeypair, salaries: &[&[u64]]) -> Vec<(ElGamalCiphertext, u64)> {
        salaries.iter().map(|m| paid(keypair, m)).collect()
    }

    fn sums(periods: &[(ElGamalCiphertext, u64)]) -> Vec<ElGamalCiphertext> {
        periods.iter().map(|p| p.0).collect()
    }

    const SALARIES: [u64; 3] = [320000, 345050, 310000];
    const HALF_YEAR: [&[u64]; 6] = [
        &[320000],
        &[150000, 170000],
        &[330000],
        &[325000],
        &[340000],
        &[335000],
    ];

    #[test]
    fn proves_total_above_threshold() {
        let keypair = ElGamalKeypair::new_rand();
        let periods = [paid(&keypair, &SALARIES)];
        let pubkey = keypair.pubkey_owned().into();
        for min in [0, 900000, periods[0].1] {
            let proofs = build(&keypair, &periods, min).unwrap();
            check(&pubkey, &sums(&periods), min, &proofs).unwrap();
        }
    }

    #[test]
    fn proves_every_month_above_threshold() {
        let keypair = ElGamalKeypair::new_rand();
        let periods = months(&keypair, &HALF_YEAR);
        let proofs = build(&keypair, &periods, 300000).unwrap();
        check(
            &keypair.pubkey_owned().into(),
            &sums(&periods),
            300000,
            &proofs,
        )
        .unwrap();
    }

    #[test]
    fn up_to_eight_periods() {
        let keypair = ElGamalKeypair::new_rand();
        let eight = months(&keypair, &[&[320000][..]; 8]);
        let proofs = build(&keypair, &eight, 300000).unwrap();
        check(
            &keypair.pubkey_owned().into(),
            &sums(&eight),
            300000,
            &proofs,
        )
        .unwrap();
        let nine = months(&keypair, &[&[320000][..]; 9]);
        assert!(build(&keypair, &nine, 300000).is_err());
    }

    #[test]
    fn one_short_month_fails() {
        let keypair = ElGamalKeypair::new_rand();
        let mut salaries = HALF_YEAR;
        salaries[3] = &[290000];
        assert!(build(&keypair, &months(&keypair, &salaries), 300000).is_err());
    }

    #[test]
    fn cannot_claim_more_than_paid() {
        let keypair = ElGamalKeypair::new_rand();
        let (sum, total) = paid(&keypair, &SALARIES);
        assert!(build(&keypair, &[(sum, total)], total + 1).is_err());

        // Skipping the guard: prove the wrapped-around difference instead.
        let min = total + 1;
        let (commitment, opening) = Pedersen::new(total);
        let (pad, pad_opening) = Pedersen::new(0u64);
        let forged = build_batched_range_proof_u256_data(
            vec![&minus_min(&commitment, min), &pad, &pad, &pad, &pad],
            vec![total.wrapping_sub(min), 0, 0, 0, 0],
            vec![32, 64, 64, 64, 32],
            vec![
                &opening,
                &pad_opening,
                &pad_opening,
                &pad_opening,
                &pad_opening,
            ],
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
            let proofs = Proofs {
                equalities: vec![equality],
                range,
            };
            assert!(check(&keypair.pubkey_owned().into(), &[sum], min, &proofs).is_err());
        }
    }

    #[test]
    fn rejects_a_different_threshold() {
        let keypair = ElGamalKeypair::new_rand();
        let periods = months(&keypair, &HALF_YEAR);
        let proofs = build(&keypair, &periods, 300000).unwrap();
        let pubkey = keypair.pubkey_owned().into();
        assert!(check(&pubkey, &sums(&periods), 310000, &proofs).is_err());
        assert!(check(&pubkey, &sums(&periods), 250000, &proofs).is_err());
    }

    #[test]
    fn rejects_moved_or_dropped_transfers() {
        let keypair = ElGamalKeypair::new_rand();
        let periods = months(&keypair, &HALF_YEAR);
        let proofs = build(&keypair, &periods, 300000).unwrap();
        let pubkey = keypair.pubkey_owned().into();

        let mut swapped = sums(&periods);
        swapped.swap(0, 2);
        assert!(check(&pubkey, &swapped, 300000, &proofs).is_err());

        let mut fewer = sums(&periods);
        fewer[1] = paid(&keypair, &[150000]).0;
        assert!(check(&pubkey, &fewer, 300000, &proofs).is_err());

        assert!(check(&pubkey, &sums(&periods)[..5], 300000, &proofs).is_err());
    }

    #[test]
    fn rejects_another_key() {
        let keypair = ElGamalKeypair::new_rand();
        let periods = [paid(&keypair, &SALARIES)];
        let proofs = build(&keypair, &periods, 900000).unwrap();
        let other = ElGamalKeypair::new_rand().pubkey_owned().into();
        assert!(check(&other, &sums(&periods), 900000, &proofs).is_err());
    }

    #[test]
    fn proof_bytes_round_trip() {
        let keypair = ElGamalKeypair::new_rand();
        let periods = months(&keypair, &HALF_YEAR);
        let proofs = build(&keypair, &periods, 300000).unwrap();
        let decoded = Proofs {
            equalities: proofs
                .equalities
                .iter()
                .map(|e| decode(&encode(e)).unwrap())
                .collect(),
            range: decode(&encode(&proofs.range)).unwrap(),
        };
        check(
            &keypair.pubkey_owned().into(),
            &sums(&periods),
            300000,
            &decoded,
        )
        .unwrap();
    }
}
