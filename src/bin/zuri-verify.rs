//! Standalone verifier. Knows nothing about amounts, only reads public chain
//! data and the proof file.

use {
    anyhow::{Context, Result, bail},
    solana_address::Address,
    std::str::FromStr,
    zuri::{chain, fmt_amount, fmt_date, parse_amount, proof},
};

const USAGE: &str = "usage: zuri-verify <proof.json> --employer <address> --min <amount>";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut path, mut employer, mut min) = (None, None, None);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--employer" => employer = Some(Address::from_str(it.next().context(USAGE)?)?),
            "--min" => min = Some(parse_amount(it.next().context(USAGE)?)?),
            _ if path.is_none() => path = Some(arg.clone()),
            _ => bail!("{USAGE}"),
        }
    }
    let (Some(path), Some(employer), Some(min)) = (path, employer, min) else {
        bail!("{USAGE}");
    };

    let proof: proof::IncomeProof = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    match proof::verify(&chain::rpc(), &proof, &employer, min).await {
        Ok(v) => {
            println!(
                "YES  {} earned at least {}",
                proof.employee,
                fmt_amount(min)
            );
            println!("     from {employer}, {} transfers", v.transfers);
            if let (Some(first), Some(last)) = (v.first_time, v.last_time) {
                println!("     between {} and {}", fmt_date(first), fmt_date(last));
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
