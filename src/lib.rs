pub mod chain;
pub mod ct;
pub mod keys;
pub mod onchain;
pub mod store;

/// Test stablecoin decimals. Two decimals keeps every balance well under the
/// 2^32 ceiling of `decrypt_u32`, the fast ElGamal decryption path.
pub const DECIMALS: u8 = 2;

/// "3450.50" -> 345050 base units.
pub fn parse_amount(s: &str) -> anyhow::Result<u64> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    anyhow::ensure!(frac.len() <= DECIMALS as usize, "at most {DECIMALS} decimals: {s}");
    let frac = format!("{frac:0<width$}", width = DECIMALS as usize);
    Ok(whole.parse::<u64>()? * 10u64.pow(DECIMALS as u32) + frac.parse::<u64>()?)
}

pub fn fmt_amount(units: u64) -> String {
    let scale = 10u64.pow(DECIMALS as u32);
    format!("{}.{:0width$}", units / scale, units % scale, width = DECIMALS as usize)
}
