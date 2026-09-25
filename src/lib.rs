pub mod chain;
pub mod ct;
pub mod keys;
pub mod onchain;
pub mod proof;
pub mod store;

/// Keeps balances under 2^32 so `decrypt_u32` works.
pub const DECIMALS: u8 = 2;

pub fn parse_amount(s: &str) -> anyhow::Result<u64> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    anyhow::ensure!(frac.len() <= DECIMALS as usize, "too many decimals: {s}");
    let frac = format!("{frac:0<width$}", width = DECIMALS as usize);
    Ok(whole.parse::<u64>()? * 10u64.pow(DECIMALS as u32) + frac.parse::<u64>()?)
}

pub fn fmt_amount(units: u64) -> String {
    let scale = 10u64.pow(DECIMALS as u32);
    format!(
        "{}.{:0w$}",
        units / scale,
        units % scale,
        w = DECIMALS as usize
    )
}

/// Unix time to YYYY-MM-DD (UTC).
pub fn fmt_date(unix: i64) -> String {
    // Howard Hinnant's civil_from_days
    let z = unix.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts() {
        assert_eq!(parse_amount("3450.5").unwrap(), 345050);
        assert_eq!(parse_amount("3200").unwrap(), 320000);
        assert!(parse_amount("1.234").is_err());
        assert_eq!(fmt_amount(975050), "9750.50");
    }

    #[test]
    fn dates() {
        assert_eq!(fmt_date(0), "1970-01-01");
        assert_eq!(fmt_date(1790178410), "2026-09-23");
    }
}
