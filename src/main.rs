use {
    anyhow::{Result, bail},
    solana_address::Address,
    solana_keypair::Keypair,
    solana_signature::Signature,
    solana_signer::Signer,
    std::{path::Path, str::FromStr},
    zuri::{
        chain::{Chain, LAMPORTS_PER_SOL},
        ct, fmt_amount, keys, onchain, parse_amount, proof,
        store::Payroll,
    },
};

const USAGE: &str = "usage: zuri <command>

  setup                  create the mint and both confidential accounts
  pay <amount>...        pay salaries from employer to employee
  apply                  employee applies pending balance
  balances               decrypted balances of both sides
  demo                   setup + three salaries + apply + balances
  inspect                read every paid salary back from the chain
  prove <min> [file]     employee proves total income >= min
  fund <keypair> <sol>   send SOL to the employer from another wallet";

const DEMO_SALARIES: [&str; 3] = ["3200", "3450.50", "3100"];
// 50,000.00 in base units.
const FUNDING_CHUNK: u64 = 5_000_000;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let chain = Chain::new(keys::keypair("employer")?);
    let employee = keys::keypair("employee")?;
    let mint = keys::keypair("mint")?.pubkey();

    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["setup"] => setup(&chain, &employee).await?,
        ["pay", ..] if args.len() > 1 => {
            let amounts = args[1..]
                .iter()
                .map(|a| parse_amount(a))
                .collect::<Result<Vec<_>>>()?;
            pay(&chain, &employee, &mint, &amounts).await?;
        }
        ["apply"] => apply(&chain, &employee, &mint).await?,
        ["balances"] => balances(&chain, &employee, &mint).await?,
        ["demo"] => {
            setup(&chain, &employee).await?;
            let amounts = DEMO_SALARIES.map(|a| parse_amount(a).unwrap());
            pay(&chain, &employee, &mint, &amounts).await?;
            apply(&chain, &employee, &mint).await?;
            balances(&chain, &employee, &mint).await?;
        }
        ["inspect"] => inspect(&chain, &employee, &mint).await?,
        ["prove", min] => prove(&chain, &employee, &mint, min, ".zuri/proof.json").await?,
        ["prove", min, out] => prove(&chain, &employee, &mint, min, out).await?,
        ["fund", path, sol] => {
            let from = keys::read(Path::new(path))?;
            let lamports = (sol.parse::<f64>()? * LAMPORTS_PER_SOL as f64) as u64;
            let sig = chain.transfer_sol(&from, lamports).await?;
            println!("sent {sol} SOL to {}: {sig}", chain.payer.pubkey());
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}

async fn setup(chain: &Chain, employee: &Keypair) -> Result<()> {
    let employer = chain.payer.pubkey();
    let mint = keys::keypair("mint")?;
    println!("employer {employer}");
    println!("employee {}", employee.pubkey());
    println!("mint     {}", mint.pubkey());
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
    payroll.save()
}

async fn fund_employer(chain: &Chain, mint: &Address, needed: u64) -> Result<()> {
    let b = ct::balances(chain, &chain.payer, mint).await?;
    if b.available >= needed {
        return Ok(());
    }
    if b.pending + b.available < needed {
        let missing = needed - b.available - b.pending;
        ct::mint_and_deposit(chain, mint, missing.div_ceil(FUNDING_CHUNK) * FUNDING_CHUNK).await?;
    }
    ct::apply_pending(chain, &chain.payer, mint).await?;
    Ok(())
}

async fn pay(chain: &Chain, employee: &Keypair, mint: &Address, amounts: &[u64]) -> Result<()> {
    let mut payroll = Payroll::load()?;
    fund_employer(chain, mint, amounts.iter().sum()).await?;
    for &amount in amounts {
        println!("salary {}", fmt_amount(amount));
        let record = ct::transfer(chain, &chain.payer, mint, &employee.pubkey(), amount).await?;
        payroll.transfers.push(record);
        payroll.save()?;
    }
    Ok(())
}

async fn apply(chain: &Chain, employee: &Keypair, mint: &Address) -> Result<()> {
    match ct::apply_pending(chain, employee, mint).await? {
        Some(pending) => println!("applied {}", fmt_amount(pending)),
        None => println!("nothing pending"),
    }
    Ok(())
}

async fn balances(chain: &Chain, employee: &Keypair, mint: &Address) -> Result<()> {
    for (name, owner) in [("employer", &chain.payer), ("employee", employee)] {
        let b = ct::balances(chain, owner, mint).await?;
        println!(
            "{name}: public {}, pending {}, available {}",
            fmt_amount(b.public),
            fmt_amount(b.pending),
            fmt_amount(b.available)
        );
    }
    Ok(())
}

fn transfer_signatures() -> Result<Vec<Signature>> {
    Payroll::load()?
        .transfers
        .iter()
        .map(|t| Ok(Signature::from_str(&t.transfer_sig)?))
        .collect()
}

async fn inspect(chain: &Chain, employee: &Keypair, mint: &Address) -> Result<()> {
    let employer_account = ct::token_account(&chain.payer.pubkey(), mint);
    let employee_account = ct::token_account(&employee.pubkey(), mint);
    let (keypair, _) = ct::account_keys(employee, &employee_account)?;
    let employer_key = ct::fetch_account(chain, &employer_account)
        .await?
        .map(|a| a.ext.elgamal_pubkey);
    let employee_key = ct::fetch_account(chain, &employee_account)
        .await?
        .map(|a| a.ext.elgamal_pubkey);

    let mut total = 0;
    for sig in transfer_signatures()? {
        let t = onchain::fetch_transfer(&chain.rpc, &sig).await?;
        let (lo, hi) = (
            &t.validity.grouped_ciphertext_lo,
            &t.validity.grouped_ciphertext_hi,
        );
        let auditor_matches = t.ix.auditor_lo == onchain::part(lo, onchain::AUDITOR)?.into()
            && t.ix.auditor_hi == onchain::part(hi, onchain::AUDITOR)?.into();
        let lo_amount = onchain::part(lo, onchain::DESTINATION)?
            .decrypt_u32(keypair.secret())
            .unwrap();
        let hi_amount = onchain::part(hi, onchain::DESTINATION)?
            .decrypt_u32(keypair.secret())
            .unwrap();
        let amount = lo_amount + (hi_amount << 16);
        total += amount;

        println!("{sig}");
        println!(
            "  slot {}, validity context {}",
            t.slot, t.ix.validity_context
        );
        for (ok, what) in [
            (t.ix.source == employer_account, "from employer"),
            (t.ix.destination == employee_account, "to employee"),
            (t.ix.mint == *mint, "mint"),
            (Some(t.validity.first_pubkey) == employer_key, "source key"),
            (
                Some(t.validity.second_pubkey) == employee_key,
                "destination key",
            ),
            (auditor_matches, "auditor ciphertexts"),
        ] {
            println!("  {} {what}", if ok { "ok  " } else { "FAIL" });
        }
        println!(
            "  {lo_amount} + {hi_amount} * 2^16 = {}",
            fmt_amount(amount)
        );
    }
    println!("total {}", fmt_amount(total));
    Ok(())
}

async fn prove(
    chain: &Chain,
    employee: &Keypair,
    mint: &Address,
    min: &str,
    out: &str,
) -> Result<()> {
    let min = parse_amount(min)?;
    let transfers = transfer_signatures()?;
    let (proof, total) = proof::prove(&chain.rpc, employee, mint, &transfers, min).await?;
    std::fs::write(out, serde_json::to_string_pretty(&proof)?)?;
    println!(
        "{} transfers, total {}, proved >= {} -> {out}",
        transfers.len(),
        fmt_amount(total),
        fmt_amount(min)
    );
    Ok(())
}
