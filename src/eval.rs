//! Evaluation values (EVAL, §8.1).

use crate::error::{Error, Result};

/// "No value".
pub const NONE: i32 = i32::MIN;
/// Largest magnitude of an ordinary value in units 1 and 3.
pub const NORMAL_MAX: i32 = (1 << 24) - 1;
/// Mate values are ±(2³⁰ − n); ±2³⁰ is a mate of unknown length.
pub const MATE: i32 = 1 << 30;
pub const MAX_MATE_PLIES: u32 = 65_535;
/// Winning rates are expected scores in units of 1/10000.
pub const WINRATE_MAX: i32 = 10_000;

/// Unit of an engine's ordinary values (§7.12, §8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unit {
    /// 1: points based on a pawn.
    Cp,
    /// 2: expected score in 1/10000.
    WinRate,
    /// 3: an engine-specific value whose negation is the other side's value.
    Raw,
    /// A value reserved in v1.0, seen in a file of a newer minor version (§12.1).
    Unknown(u8),
}

impl Unit {
    pub fn code(self) -> u8 {
        match self {
            Unit::Cp => 1,
            Unit::WinRate => 2,
            Unit::Raw => 3,
            Unit::Unknown(c) => c,
        }
    }

    pub fn from_code(c: u8) -> Unit {
        match c {
            1 => Unit::Cp,
            2 => Unit::WinRate,
            3 => Unit::Raw,
            other => Unit::Unknown(other),
        }
    }

    pub fn name(self) -> Option<&'static str> {
        match self {
            Unit::Cp => Some("cp"),
            Unit::WinRate => Some("winrate"),
            Unit::Raw => Some("raw"),
            Unit::Unknown(_) => None,
        }
    }

    pub fn from_name(s: &str) -> Option<Unit> {
        match s {
            "cp" => Some(Unit::Cp),
            "winrate" => Some(Unit::WinRate),
            "raw" => Some(Unit::Raw),
            _ => None,
        }
    }
}

/// A mate value: positive `plies` when the viewpoint side mates, `None` when unknown.
pub fn mate(win: bool, plies: Option<u32>) -> i32 {
    let v = match plies {
        Some(n) if (1..=MAX_MATE_PLIES).contains(&n) => MATE - n as i32,
        _ => MATE,
    };
    if win { v } else { -v }
}

pub fn is_mate(v: i32) -> bool {
    v != NONE && v.unsigned_abs() >= (MATE as u32 - MAX_MATE_PLIES) && v.unsigned_abs() <= MATE as u32
}

/// (wins, plies) of a mate value.
pub fn mate_parts(v: i32) -> Option<(bool, Option<u32>)> {
    if !is_mate(v) {
        return None;
    }
    let n = MATE as u32 - v.unsigned_abs();
    Some((v > 0, (n > 0).then_some(n)))
}

/// Whether `v` is a valid EVAL for `unit` (excluding `NONE`).
pub fn is_valid(v: i32, unit: Unit) -> bool {
    if v == NONE {
        return false;
    }
    if is_mate(v) {
        return true;
    }
    match unit {
        Unit::Cp | Unit::Raw => (-NORMAL_MAX..=NORMAL_MAX).contains(&v),
        Unit::WinRate => (0..=WINRATE_MAX).contains(&v),
        Unit::Unknown(_) => true, // cannot be judged; values are not used (§12.1)
    }
}

/// The value seen from the other side (§8.1).
pub fn flip(v: i32, unit: Unit) -> Result<i32> {
    if v == NONE || is_mate(v) {
        return Ok(if v == NONE { NONE } else { -v });
    }
    match unit {
        Unit::Cp | Unit::Raw => Ok(-v),
        Unit::WinRate => Ok(WINRATE_MAX - v),
        Unit::Unknown(c) => Err(Error::Unsupported(format!("cannot change the viewpoint of unit {c}"))),
    }
}

/// `.spgt` notation (§9.3): `48`, `mate:+3`, `mate:-?`.
pub fn to_text(v: i32) -> String {
    match mate_parts(v) {
        Some((win, n)) => format!("mate:{}{}", if win { '+' } else { '-' }, n.map_or("?".to_owned(), |n| n.to_string())),
        None => v.to_string(),
    }
}

pub fn from_text(s: &str) -> Option<i32> {
    if let Some(rest) = s.strip_prefix("mate:") {
        let (win, n) = match rest.as_bytes().first()? {
            b'+' => (true, &rest[1..]),
            b'-' => (false, &rest[1..]),
            _ => return None,
        };
        if n == "?" {
            return Some(mate(win, None));
        }
        let plies = parse_uint(n)?;
        return (1..=u64::from(MAX_MATE_PLIES)).contains(&plies).then(|| mate(win, Some(plies as u32)));
    }
    let v = parse_int(s)?;
    let v = i32::try_from(v).ok()?;
    (v != NONE && !is_mate(v)).then_some(v)
}

/// `-?[0-9]+` without leading zeros (§9.3).
pub fn parse_int(s: &str) -> Option<i64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || (digits.len() > 1 && digits.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

pub fn parse_uint(s: &str) -> Option<u64> {
    if s.starts_with('-') {
        return None;
    }
    parse_int(s).map(|v| v as u64).or_else(|| {
        // values above i64::MAX
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && !(s.len() > 1 && s.starts_with('0'))).then(|| s.parse().ok()).flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values() {
        assert!(is_valid(48, Unit::Cp));
        assert!(!is_valid(NORMAL_MAX + 1, Unit::Cp));
        assert!(is_valid(mate(true, Some(3)), Unit::WinRate));
        assert!(!is_valid(10_001, Unit::WinRate));
        assert_eq!(flip(3000, Unit::WinRate), Ok(7000));
        assert_eq!(flip(mate(true, Some(3)), Unit::Cp), Ok(mate(false, Some(3))));
        for t in ["48", "-120", "mate:+3", "mate:-?", "0"] {
            assert_eq!(to_text(from_text(t).unwrap_or(NONE)), t);
        }
        for bad in ["+3", "007", "mate:3", "mate:+0", "mate:+65536", "-0x1"] {
            assert_eq!(from_text(bad), None, "{bad}");
        }
    }
}
