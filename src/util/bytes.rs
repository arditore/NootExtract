//! Byte-count parsing and formatting.
//!
//! All arithmetic is checked: forensic images routinely exceed 32-bit ranges and
//! a silently wrapped segment size would produce a corrupt image set.

use crate::error::{Error, Result};

/// Formats a byte count using binary (IEC) units for operator output.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("B");
    if unit == 0 {
        format!("{bytes} {name}")
    } else {
        format!("{value:.2} {name}")
    }
}

/// Parses a human-written size such as `512`, `64K`, `2M`, `4G` or `1TiB`.
///
/// Both `K` and `KiB` denote 1024 bytes; decimal SI units are intentionally not
/// supported so that segment sizes are unambiguous.
pub fn parse_size(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(Error::Usage("size value is empty".into()));
    }
    let digits_end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(digits_end);
    if digits.is_empty() {
        return Err(Error::Usage(format!("size `{input}` has no numeric part")));
    }
    let value: u64 = digits
        .parse()
        .map_err(|_| Error::Usage(format!("size `{input}` is out of range")))?;

    let multiplier: u64 = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KI" | "KIB" => 1 << 10,
        "M" | "MI" | "MIB" => 1 << 20,
        "G" | "GI" | "GIB" => 1 << 30,
        "T" | "TI" | "TIB" => 1 << 40,
        other => {
            return Err(Error::Usage(format!(
                "unknown size suffix `{other}` (expected one of B, K, M, G, T)"
            )));
        }
    };

    value
        .checked_mul(multiplier)
        .ok_or_else(|| Error::Usage(format!("size `{input}` overflows a 64-bit byte count")))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::default_trait_access,
        clippy::format_push_string,
        clippy::integer_division,
        clippy::cast_sign_loss
    )]
    use super::*;

    #[test]
    fn formats_binary_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn parses_supported_suffixes() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1B").unwrap(), 1);
        assert_eq!(parse_size("2K").unwrap(), 2048);
        assert_eq!(parse_size("2KiB").unwrap(), 2048);
        assert_eq!(parse_size("4M").unwrap(), 4 * 1024 * 1024);
        assert_eq!(parse_size(" 2G ").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1T").unwrap(), 1 << 40);
    }

    #[test]
    fn rejects_malformed_sizes() {
        assert!(parse_size("").is_err());
        assert!(parse_size("G").is_err());
        assert!(parse_size("12Z").is_err());
        assert!(parse_size("-5M").is_err());
        assert!(parse_size("1.5G").is_err());
    }

    #[test]
    fn rejects_overflowing_sizes() {
        // 2^63 TiB cannot be represented; the multiplication must not wrap.
        assert!(parse_size("18446744073709551615T").is_err());
        assert!(parse_size("99999999999999999999").is_err());
    }
}
