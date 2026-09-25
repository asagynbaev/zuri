//! Day 1 of the Zuri spike: a live confidential payroll on devnet.
//!
//!   cargo run -- fund <kp.json> 1  send SOL from another wallet to the employer
//!   cargo run -- setup              mint + employer/employee accounts + funding
//!   cargo run -- pay 3200 3450.50   one confidential transfer per amount
//!   cargo run -- apply              employee moves pending -> available
//!   cargo run -- balances           decrypted balances of both parties
//!   cargo run -- run                all of the above with three salaries
//!   cargo run -- dump               day 2: locate each transfer's ciphertexts on-chain

use {
    anyhow::{Result, bail},
    solana_signer::Signer,
    zuri::{
        chain::{Chain, LAMPORTS_PER_SOL},
        ct, fmt_amount, keys, onchain, parse_amount,
        store::Payroll,
    },
};

const DEFAULT_SALARIES: [&str; 3] = ["3200", "3450.50", "3100"];
/// Employer tops up its confidential balance in chunks of this size.
const FUNDING_CHUNK: u64 = 50_000_00;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let chain = Chain::new(keys::keypair("employer")?);
    let employee = keys::keypair("employee")?;
    let mint = keys::keypair("mint")?.pubkey();

    match args.first().map(String::as_str) {
        Some("fund") => {
            let [_, path, sol] = &args[..] else { bail!("usage: fund <keypair.json> <sol>") };
            let from = keys::read(std::path::Path::new(path))?;
            let lamports = (sol.parse::<f64>()? * LAMPORTS_PER_SOL as f64) as u64;
            let sig = chain.fund_payer(&from, lamports).await?;
            println!("sent {sol} SOL from {} to {}: {sig}", from.pubkey(), chain.payer.pubkey());
        }
        Some("setup") => setup(&chain, &employee).await?,
        Some("pay") => {
            let amounts = args[1..].iter().map(|a| parse_amount(a)).collect::<Result<Vec<_>>>()?;
            if amounts.is_empty() {
                bail!("usage: pay <amount>...");
            }
            pay(&chain, &employee, &amounts).await?;
        }
        Some("apply") => apply(&chain, &employee).await?,
        Some("balances") => print_balances(&chain, &employee, &mint).await?,
        Some("dump") => dump(&chain, &employee).await?,
        Some("run") => {
            setup(&chain, &employee).await?;
            let amounts = DEFAULT_SALARIES.map(|a| parse_amount(a).unwrap());
            pay(&chain, &employee, &amounts).await?;
            apply(&chain, &employee).await?;
            print_balances(&chain, &employee, &mint).await?;
        }
        _ => bail!("usage: zuri <fund <keypair.json> <sol>|setup|pay <amount>...|apply|balances|run|dump>"),
    }
    Ok(())
}

async fn setup(chain: &Chain, employee: &solana_keypair::Keypair) -> Result<()> {
    let employer = chain.payer.pubkey();
    let mint = keys::keypair("mint")?;
    println!("employer {employer}\nemployee {}\nmint     {}", employee.pubkey(), mint.pubkey());
    chain.ensure_sol(1).await?;

    if chain.account_data(&mint.pubkey()).await?.is_none() {
        ct::create_mint(chain, &mint, keys::auditor()?.pubkey()).await?;
    }
    for owner in [&chain.payer, employee] {
        let account = ct::token_account(&owner.pubkey(), &mint.pubkey());
        if ct::fetch_account(chain, &account).await?.is_none() {
            ct::create_account(chain, owner, &mint.pubkey()).await?;
        }
    }

    let mut payroll = Payroll::load()?;
    payroll.mint = mint.pubkey().to_string();
    payroll.employer = employer.to_string();
    payroll.employer_token_account = ct::token_account(&employer, &mint.pubkey()).to_string();
    payroll.employee = employee.pubkey().to_string();
    payroll.employee_token_account =
        ct::token_account(&employee.pubkey(), &mint.pubkey()).to_string();
    payroll.save()?;
    Ok(())
}

/// Make sure the employer's available confidential balance covers `needed`.
async fn fund_employer(chain: &Chain, mint: &solana_address::Address, needed: u64) -> Result<()> {
    let b = ct::balances(chain, &chain.payer, mint).await?;
    if b.available >= needed {
        return Ok(());
    }
    if b.pending + b.available < needed {
        let top_up = (needed - b.available - b.pending).div_ceil(FUNDING_CHUNK) * FUNDING_CHUNK;
        ct::mint_and_deposit(chain, mint, top_up).await?;
    }
    ct::apply_pending(chain, &chain.payer, mint).await?;
    Ok(())
}

async fn pay(chain: &Chain, employee: &solana_keypair::Keypair, amounts: &[u64]) -> Result<()> {
    let mint = keys::keypair("mint")?.pubkey();
    let mut payroll = Payroll::load()?;
    fund_employer(chain, &mint, amounts.iter().sum()).await?;
    for &amount in amounts {
        println!("salary {}:", fmt_amount(amount));
        let record = ct::transfer(chain, &chain.payer, &mint, &employee.pubkey(), amount).await?;
        println!("  {}", chain.explorer(&record.transfer_sig.parse()?));
        payroll.transfers.push(record);
        payroll.save()?;
    }
    Ok(())
}

async fn apply(chain: &Chain, employee: &solana_keypair::Keypair) -> Result<()> {
    let mint = keys::keypair("mint")?.pubkey();
    match ct::apply_pending(chain, employee, &mint).await? {
        Some(pending) => println!("employee applied {} pending", fmt_amount(pending)),
        None => println!("employee has nothing pending"),
    }
    Ok(())
}

async fn print_balances(
    chain: &Chain,
    employee: &solana_keypair::Keypair,
    mint: &solana_address::Address,
) -> Result<()> {
    for (name, owner) in [("employer", &chain.payer), ("employee", employee)] {
        let b = ct::balances(chain, owner, mint).await?;
        println!(
            "{name}: public {} | pending {} | available {} (credits {})",
            fmt_amount(b.public),
            fmt_amount(b.pending),
            fmt_amount(b.available),
            b.credit_counter
        );
    }
    Ok(())
}

/// For every recorded salary: fetch the Transfer and validity-proof
/// transactions, check they link up, and decrypt the employee's part.
async fn dump(chain: &Chain, employee: &solana_keypair::Keypair) -> Result<()> {
    let payroll = Payroll::load()?;
    let mint = keys::keypair("mint")?.pubkey();
    let employer_account = ct::token_account(&chain.payer.pubkey(), &mint);
    let employee_account = ct::token_account(&employee.pubkey(), &mint);
    let (employee_elgamal, _) = ct::account_keys(employee, &employee_account)?;
    let employer_elgamal = ct::fetch_account(chain, &employer_account).await?.unwrap().ext.elgamal_pubkey;
    let employee_onchain = ct::fetch_account(chain, &employee_account).await?.unwrap().ext.elgamal_pubkey;

    let mut total = 0;
    for (i, t) in payroll.transfers.iter().enumerate() {
        let transfer_tx = onchain::fetch_tx(chain, &t.transfer_sig.parse()?).await?;
        let ix = onchain::find_transfer(&transfer_tx.tx)?;
        let validity_tx = onchain::fetch_tx(chain, &t.validity_sig.parse()?).await?;
        let ctx = onchain::find_validity_context(&validity_tx.tx, &ix.validity_context)?;

        println!("transfer #{i} slot {} time {:?}", transfer_tx.slot, transfer_tx.block_time);
        println!("  source {} -> destination {} (authority {})", ix.source, ix.destination, ix.authority);
        println!("  validity context {} written in slot {}", ix.validity_context, validity_tx.slot);
        println!("  pubkeys: source {} | destination {} | auditor {}", ctx.first_pubkey, ctx.second_pubkey, ctx.third_pubkey);

        let checks = [
            ("source is employer's account", ix.source == employer_account),
            ("destination is employee's account", ix.destination == employee_account),
            ("mint matches", ix.mint == mint),
            ("source pubkey = employer's ElGamal key", ctx.first_pubkey == employer_elgamal),
            ("destination pubkey = employee's ElGamal key", ctx.second_pubkey == employee_onchain),
            ("validity written before transfer", validity_tx.slot <= transfer_tx.slot),
            (
                "auditor lo/hi in Transfer = auditor part of grouped ciphertexts",
                solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext::from(
                    onchain::part(&ctx.grouped_ciphertext_lo, onchain::AUDITOR)?,
                ) == ix.auditor_lo
                    && solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext::from(
                        onchain::part(&ctx.grouped_ciphertext_hi, onchain::AUDITOR)?,
                    ) == ix.auditor_hi,
            ),
        ];
        for (name, ok) in checks {
            println!("  [{}] {name}", if ok { "ok" } else { "FAIL" });
        }

        let lo = onchain::part(&ctx.grouped_ciphertext_lo, onchain::DESTINATION)?;
        let hi = onchain::part(&ctx.grouped_ciphertext_hi, onchain::DESTINATION)?;
        let lo_amount = lo.decrypt_u32(employee_elgamal.secret()).unwrap();
        let hi_amount = hi.decrypt_u32(employee_elgamal.secret()).unwrap();
        let amount = lo_amount + (hi_amount << 16);
        println!(
            "  employee decrypts lo {lo_amount} + 2^16 * hi {hi_amount} = {} (recorded {})",
            fmt_amount(amount),
            fmt_amount(t.amount)
        );
        total += amount;
    }
    println!("total {}", fmt_amount(total));
    Ok(())
}
