//! Standalone verifier. Knows nothing about amounts, only reads public chain
//! data and the proof file.

use {
    anyhow::{Context, Result, bail, ensure},
    solana_address::Address,
    std::str::FromStr,
    zuri::{chain, fmt_amount, fmt_date, parse_amount, parse_month, proof},
};

const USAGE: &str =
    "usage: zuri-verify <proof.json> --employer <address> --min <amount> [--months <n>]";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut path, mut employer, mut min, mut months) = (None, None, None, None);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--employer" => employer = Some(Address::from_str(it.next().context(USAGE)?)?),
            "--min" => min = Some(parse_amount(it.next().context(USAGE)?)?),
            "--months" => months = Some(it.next().context(USAGE)?.parse::<usize>()?),
            _ if path.is_none() => path = Some(arg.clone()),
            _ => bail!("{USAGE}"),
        }
    }
    let (Some(path), Some(employer), Some(min)) = (path, employer, min) else {
        bail!("{USAGE}");
    };

    let proof: proof::IncomeProof = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let result = async {
        let verdict = proof::verify(&chain::rpc(), &proof, &employer, min).await?;
        if let Some(n) = months {
            consecutive_months(&verdict.periods, n)?;
        }
        Ok::<_, anyhow::Error>(verdict)
    };
    match result.await {
        Ok(v) => {
            let (first, last) = (&v.periods[0], &v.periods[v.periods.len() - 1]);
            if first == proof::ALL {
                println!(
                    "YES  {} earned at least {}",
                    proof.employee,
                    fmt_amount(min)
                );
            } else {
                println!(
                    "YES  {} earned at least {} in each of {} months, {first} to {last}",
                    proof.employee,
                    fmt_amount(min),
                    v.periods.len()
                );
            }
            println!("     from {employer}, {} transfers", v.transfers);
            if let (Some(first), Some(last)) = (v.first_time, v.last_time) {
                println!(
                    "     paid between {} and {}",
                    fmt_date(first),
                    fmt_date(last)
                );
            }
            println!("     tx set {}", v.tx_set_hash);
            Ok(())
        }
        Err(e) => {
            println!("NO   {e:#}");
            std::process::exit(1);
        }
    }
}

/// At least `n` calendar months in a row, no gaps. Labels come sorted.
fn consecutive_months(periods: &[String], n: usize) -> Result<()> {
    let months = periods
        .iter()
        .map(|p| parse_month(p))
        .collect::<Result<Vec<_>>>()
        .context("proof is not split by month")?;
    ensure!(
        months.len() >= n,
        "covers {} months, need {n}",
        months.len()
    );
    ensure!(
        months.windows(2).all(|w| w[1] == w[0] + 1),
        "months are not consecutive"
    );
    Ok(())
}
