//! Checks on the logical data: the writer requirements and invariants of §13.2 that do not
//! depend on the byte layout. Writers run them before writing; readers run them after
//! decoding (a failure there means the file is corrupt).

use std::collections::{HashMap, HashSet};

use crate::error::{Error, Result};
use crate::eval::{self, Unit};
use crate::model::*;
use crate::moves::Move;
use crate::position::{Encoded, Position};

/// Largest number of edges of one position (§7.16).
pub const MAX_EDGES: usize = 593;
/// Largest number of moves in one move list (§7.19–7.21).
pub const MAX_MOVE_LIST: usize = 65_535;

#[derive(Clone, Copy, Debug)]
pub struct Checks {
    /// Accept annotation keys that v1.0 does not define and reserved value types. Needed
    /// when rewriting files written by newer minor versions (§8.2: keep unknown keys).
    pub allow_unknown: bool,
    /// Check every edge and record move against the rules of §6.7.
    pub legality: bool,
}

impl Default for Checks {
    fn default() -> Self {
        Checks { allow_unknown: false, legality: true }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Position,
    Edge,
    Node { event: bool },
    Record,
    File,
    Engine,
    Analysis,
    Source,
}

/// Annotation key syntax (§7.11): words of `[a-z0-9_-]` separated by dots.
pub fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.split('.').all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'))
}

fn parts(key: &str) -> usize {
    key.split('.').count()
}

/// Whether a key is defined by v1.0 or reserved for extensions (`x.*`, `src.*`).
pub fn known_key(key: &str) -> bool {
    matches!(key, "comment" | "bookmark" | "event.raw" | "rights" | "src.engine" | "src.partial" | "stat.rule" | "merge.rule")
        || ((key.starts_with("src.") || key.starts_with("x.")) && parts(key) >= 3)
}

/// The value type a key's schema fixes, if any (§8.2, §9.3).
pub fn schema_type(key: &str) -> Option<SchemaType> {
    match key {
        "comment" | "bookmark" | "event.raw" | "src.engine" | "src.partial" | "stat.rule" | "merge.rule" => Some(SchemaType::Str),
        "rights" => Some(SchemaType::Int),
        k if k.starts_with("src.range.") && parts(k) >= 3 => Some(SchemaType::Str),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SchemaType {
    Str,
    Int,
}

fn check_anno(a: &Anno, target: Target, spg: &Spg, checks: &Checks) -> Result<()> {
    let k = a.key.as_str();
    if !valid_key(k) {
        return Err(Error::invalid(format!("bad annotation key {k:?}")));
    }
    let allowed: &[Target] = match k {
        "comment" => &[Target::Position, Target::Edge, Target::Node { event: false }, Target::Node { event: true }, Target::Record, Target::File, Target::Engine, Target::Source],
        "bookmark" => &[Target::Node { event: false }, Target::Node { event: true }],
        "event.raw" => &[Target::Node { event: true }],
        "rights" => &[Target::Position, Target::Edge, Target::Node { event: false }, Target::Node { event: true }, Target::Record, Target::File, Target::Analysis, Target::Source],
        "src.engine" => &[Target::Engine],
        "src.partial" | "stat.rule" | "merge.rule" => &[Target::File],
        k if k.starts_with("src.range.") && parts(k) >= 3 => &[Target::Edge, Target::Analysis, Target::Node { event: false }, Target::Node { event: true }, Target::Record, Target::Engine],
        _ => &[],
    };
    let known = known_key(k);
    if !known && !checks.allow_unknown {
        return Err(Error::invalid(format!("annotation key {k:?} is not defined by SPG 1.0; use x.<provider>.<name>")));
    }
    if !allowed.is_empty() && !allowed.contains(&target) {
        return Err(Error::invalid(format!("annotation {k:?} cannot target {target:?}")));
    }
    if target == Target::Analysis && !(k == "rights" || k.starts_with("src.") || k.starts_with("x.")) {
        return Err(Error::invalid(format!("annotation {k:?} cannot target an analysis entry")));
    }
    match (schema_type(k), &a.value) {
        (_, Value::Reserved { .. }) if !checks.allow_unknown => return Err(Error::invalid("reserved annotation value type")),
        (Some(SchemaType::Str), Value::Str(_)) | (Some(SchemaType::Int), Value::Int(_)) | (None, _) => {}
        (Some(_), Value::Reserved { .. }) => {}
        _ => return Err(Error::invalid(format!("annotation {k:?} has the wrong value type"))),
    }
    match &a.value {
        Value::Real(f) if !f.is_finite() => return Err(Error::invalid("non-finite real annotation")),
        Value::Moves(m) => check_moves(m)?,
        Value::Str(s) => check_str(s)?,
        _ => {}
    }
    if k == "rights" {
        let Value::Int(i) = a.value else { return Err(Error::invalid("rights must be an integer")) };
        if i < 0 || i as u64 >= spg.rights.len() as u64 {
            return Err(Error::invalid(format!("rights index {i} out of range")));
        }
    }
    for &r in &a.rights {
        if r >= spg.rights.len() as u64 {
            return Err(Error::invalid(format!("rights index {r} out of range")));
        }
    }
    Ok(())
}

fn check_annos(annos: &[Anno], target: Target, spg: &Spg, checks: &Checks, at: &dyn Fn() -> String) -> Result<()> {
    for a in annos {
        check_anno(a, target, spg, checks).map_err(|e| context(e, at))?;
    }
    Ok(())
}

fn context(e: Error, at: &dyn Fn() -> String) -> Error {
    match e {
        Error::Invalid(m) => Error::Invalid(format!("{}: {m}", at())),
        other => other,
    }
}

pub fn check_str(s: &str) -> Result<()> {
    if s.len() > u32::MAX as usize {
        return Err(Error::invalid("string longer than 2^32 - 1 bytes"));
    }
    Ok(())
}

fn check_moves(m: &[Move]) -> Result<()> {
    if m.len() > MAX_MOVE_LIST {
        return Err(Error::invalid("move list longer than 65535"));
    }
    if let Some(bad) = m.iter().find(|m| !m.is_valid()) {
        return Err(Error::invalid(format!("invalid Move16 {:#06x}", bad.0)));
    }
    Ok(())
}

fn engine_unit(spg: &Spg, engine: u16) -> Result<Unit> {
    spg.engines.get(usize::from(engine)).map(|e| e.unit).ok_or_else(|| Error::invalid(format!("engine index {engine} out of range")))
}

fn check_edge_eval(spg: &Spg, e: &EdgeEval) -> Result<()> {
    let unit = engine_unit(spg, e.engine)?;
    if !eval::is_valid(e.value, unit) {
        return Err(Error::invalid(format!("evaluation {} out of range for the engine's unit", e.value)));
    }
    if e.depth == Some(u16::MAX) {
        return Err(Error::invalid("edge depth 65535 is reserved for \"none\""));
    }
    Ok(())
}

fn check_stats(s: &Stats) -> Result<()> {
    if s.wins.checked_add(s.draws).is_none_or(|n| n > s.games) {
        return Err(Error::invalid("wins + draws exceed games"));
    }
    Ok(())
}

fn check_analysis(spg: &Spg, a: &Analysis, checks: &Checks) -> Result<()> {
    let unit = engine_unit(spg, a.engine)?;
    if (matches!(a.context, Context::Unknown(_)) || matches!(a.bound, Bound::Unknown(_))) && !checks.allow_unknown {
        return Err(Error::invalid("reserved analysis context or bound"));
    }
    if let Some(v) = a.eval
        && !eval::is_valid(v, unit) {
            return Err(Error::invalid(format!("analysis evaluation {v} out of range for the engine's unit")));
        }
    if a.winrate.is_some_and(|w| i32::from(w) > eval::WINRATE_MAX) {
        return Err(Error::invalid("winning rate above 10000"));
    }
    if let Some(pv) = &a.pv {
        check_moves(pv)?;
    }
    Ok(())
}

/// Effective rights of an item (§8.3): its own `rights` annotations, or `parent`'s.
fn own_rights(annos: &[Anno]) -> Option<Vec<i64>> {
    let mut v: Vec<i64> = annos.iter().filter(|a| a.key == "rights").filter_map(|a| if let Value::Int(i) = a.value { Some(i) } else { None }).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    v.dedup();
    Some(v)
}

fn check_prov(spg: &Spg, prov: &[Prov], is_edge: bool, own: Option<&Stats>, rights: &[i64], file_rights: &[i64]) -> Result<()> {
    let mut seen = HashSet::new();
    let mut sum = Stats::default();
    let mut with_stats = false;
    let mut union: Vec<i64> = Vec::new();
    for p in prov {
        let src = spg.sources.get(p.source as usize).ok_or_else(|| Error::invalid(format!("source index {} out of range", p.source)))?;
        if !seen.insert(p.source) {
            return Err(Error::invalid(format!("two PROV entries for source {}", p.source)));
        }
        if !is_edge && (p.disabled || p.weight.is_some() || p.eval.is_some() || p.stats.is_some()) {
            return Err(Error::invalid("PROV entries of positions carry no values"));
        }
        if let Some(e) = &p.eval {
            check_edge_eval(spg, e)?;
        }
        if let Some(s) = &p.stats {
            check_stats(s)?;
            with_stats = true;
            sum.games = sum.games.saturating_add(s.games);
            sum.wins = sum.wins.saturating_add(s.wins);
            sum.draws = sum.draws.saturating_add(s.draws);
        }
        union.extend(own_rights(&src.annos).unwrap_or_else(|| file_rights.to_vec()));
    }
    if with_stats && own.copied().unwrap_or_default() != sum {
        return Err(Error::invalid("edge statistics differ from the sum of its PROV statistics"));
    }
    if !prov.is_empty() {
        union.sort_unstable();
        union.dedup();
        if union != rights {
            return Err(Error::invalid("rights of a merged item must be the union of its sources' rights (§8.3)"));
        }
    }
    Ok(())
}

/// Check everything a conforming writer must guarantee about the logical data.
pub fn validate(spg: &Spg, checks: &Checks) -> Result<()> {
    let file_rights = own_rights(&spg.file_annos).unwrap_or_default();
    check_annos(&spg.file_annos, Target::File, spg, checks, &|| "file".into())?;
    let mut groups: HashMap<u64, (usize, u16)> = HashMap::new();
    let mut target_no = 0usize;
    let mut check_group = |a: &Analysis, target: usize| -> Result<()> {
        if a.group != 0 {
            let e = groups.entry(a.group).or_insert((target, a.engine));
            if *e != (target, a.engine) {
                return Err(Error::invalid(format!("search group {} spans several targets or engines", a.group)));
            }
        }
        Ok(())
    };
    for (i, r) in spg.rights.iter().enumerate() {
        let at = || format!("rights {i}");
        if matches!(r.role, Role::Unknown(_)) && !checks.allow_unknown {
            return Err(Error::invalid(format!("{}: reserved role", at())));
        }
        for s in [Some(&r.name), r.copyright.as_ref(), Some(&r.license), r.license_text.as_ref(), r.url.as_ref(), r.date.as_ref()].into_iter().flatten() {
            check_str(s)?;
        }
        if !valid_license(&r.license) {
            return Err(Error::invalid(format!("{}: {:?} is not an SPDX license expression", at(), r.license)));
        }
        if r.license.contains("LicenseRef-") && r.license_text.is_none() {
            return Err(Error::invalid(format!("{}: LicenseRef- needs the license text", at())));
        }
        if let Some(d) = &r.date
            && !valid_date(d) {
                return Err(Error::invalid(format!("{}: date {d:?} is not an RFC 3339 full-date", at())));
            }
    }
    for (i, s) in spg.sources.iter().enumerate() {
        check_annos(&s.annos, Target::Source, spg, checks, &|| format!("source {i}"))?;
    }
    if spg.engines.len() > usize::from(u16::MAX) {
        return Err(Error::invalid("more than 65535 engines"));
    }
    for (i, e) in spg.engines.iter().enumerate() {
        let at = || format!("engine {i}");
        if matches!(e.unit, Unit::Unknown(_)) && !checks.allow_unknown {
            return Err(Error::invalid(format!("{}: reserved unit", at())));
        }
        if e.unit == Unit::WinRate && e.pawn != 0 {
            return Err(Error::invalid(format!("{}: unit winrate has no pawn value", at())));
        }
        check_annos(&e.annos, Target::Engine, spg, checks, &at)?;
    }
    let mut seen = HashSet::new();
    let has_prov = spg.positions.iter().any(|p| !p.prov.is_empty() || p.edges.iter().any(|e| !e.prov.is_empty()));
    if has_prov && !spg.file_annos.iter().any(|a| a.key == "merge.rule") {
        return Err(Error::invalid("files with PROV must state merge.rule (§8.4)"));
    }
    for p in &spg.positions {
        let sfen = p.position.to_sfen();
        let at = || format!("position {sfen}");
        if !seen.insert(p.position.encode()) {
            return Err(Error::invalid(format!("{}: listed twice", at())));
        }
        check_annos(&p.annos, Target::Position, spg, checks, &at)?;
        for a in &p.analyses {
            check_analysis(spg, a, checks).map_err(|e| context(e, &at))?;
            check_annos(&a.annos, Target::Analysis, spg, checks, &at)?;
            check_group(a, target_no)?;
        }
        target_no += 1;
        let pos_rights = own_rights(&p.annos).unwrap_or_else(|| file_rights.clone());
        check_prov(spg, &p.prov, false, None, &pos_rights, &file_rights).map_err(|e| context(e, &at))?;
        if p.edges.len() > MAX_EDGES {
            return Err(Error::invalid(format!("{}: more than {MAX_EDGES} edges", at())));
        }
        let legal = if checks.legality { Some(p.position.legal_moves()) } else { None };
        let mut moves = HashSet::new();
        for e in &p.edges {
            let at = || format!("position {sfen} edge {}", e.mv.to_usi());
            if !e.mv.is_valid() {
                return Err(Error::invalid(format!("{}: invalid Move16", at())));
            }
            if !moves.insert(e.mv) {
                return Err(Error::invalid(format!("{}: listed twice", at())));
            }
            if legal.as_ref().is_some_and(|l| !l.contains(&e.mv)) {
                return Err(Error::invalid(format!("{}: illegal move", at())));
            }
            if let Some(ev) = &e.eval {
                check_edge_eval(spg, ev).map_err(|x| context(x, &at))?;
            }
            if let Some(s) = &e.stats {
                check_stats(s).map_err(|x| context(x, &at))?;
            }
            check_annos(&e.annos, Target::Edge, spg, checks, &at)?;
            for a in &e.analyses {
                check_analysis(spg, a, checks).map_err(|x| context(x, &at))?;
                check_annos(&a.annos, Target::Analysis, spg, checks, &at)?;
                check_group(a, target_no)?;
            }
            target_no += 1;
            let edge_rights = own_rights(&e.annos).unwrap_or_else(|| pos_rights.clone());
            check_prov(spg, &e.prov, true, e.stats.as_ref(), &edge_rights, &file_rights).map_err(|x| context(x, &at))?;
        }
    }
    for (ri, r) in spg.records.iter().enumerate() {
        let at = || format!("record {ri}");
        if matches!(r.result, GameResult::Reserved(_)) && !checks.allow_unknown {
            return Err(Error::invalid(format!("{}: reserved result", at())));
        }
        if let Some(raw) = r.raw
            && raw >= spg.raws.len() as u64 {
                return Err(Error::invalid(format!("{}: RAWS index out of range", at())));
            }
        for (k, v) in &r.meta {
            check_str(k)?;
            check_str(v)?;
        }
        if r.meta.len() > u32::MAX as usize {
            return Err(Error::invalid(format!("{}: too many meta items", at())));
        }
        check_annos(&r.annos, Target::Record, spg, checks, &at)?;
        check_record_tree(r, checks).map_err(|e| context(e, &at))?;
        for (ni, n) in r.nodes.iter().enumerate() {
            let at = || format!("record {ri} node {ni}");
            let event = matches!(n.kind, NodeKind::Event(_));
            check_annos(&n.annos, Target::Node { event }, spg, checks, &at)?;
            for a in &n.analyses {
                check_analysis(spg, a, checks).map_err(|x| context(x, &at))?;
                check_annos(&a.annos, Target::Analysis, spg, checks, &at)?;
                check_group(a, target_no)?;
            }
            target_no += 1;
        }
    }
    for r in &spg.raws {
        check_str(&r.format)?;
        if matches!(r.compression, Compression::Reserved(_)) && !checks.allow_unknown {
            return Err(Error::invalid("reserved RAWS compression method"));
        }
    }
    Ok(())
}

/// Tree rules of §7.24 for one record, plus move legality when asked.
pub fn check_record_tree(r: &Record, checks: &Checks) -> Result<()> {
    if r.nodes.is_empty() || r.nodes[0].kind != NodeKind::Root {
        return Err(Error::invalid("the first node must be the root"));
    }
    if r.nodes.len() > u32::MAX as usize {
        return Err(Error::invalid("more than 2^32 - 1 nodes"));
    }
    // The chain from the previous node to the root; a pre-order parent must be on it.
    let mut chain: Vec<usize> = vec![0];
    let mut positions: Vec<Option<Position>> = Vec::with_capacity(r.nodes.len());
    positions.push(Some(r.start.clone()));
    for (i, n) in r.nodes.iter().enumerate().skip(1) {
        if n.kind == NodeKind::Root {
            return Err(Error::invalid(format!("node {i}: a record has exactly one root")));
        }
        let parent = n.parent as usize;
        while chain.last().is_some_and(|&c| c != parent) {
            chain.pop();
        }
        if chain.is_empty() {
            return Err(Error::invalid(format!("node {i}: nodes are not in pre-order")));
        }
        if matches!(r.nodes[parent].kind, NodeKind::Event(_)) {
            return Err(Error::invalid(format!("node {i}: events have no children")));
        }
        if n.time_ms == Some(u32::MAX) {
            return Err(Error::invalid(format!("node {i}: time 4294967295 is reserved for \"none\"")));
        }
        let pos = match n.kind {
            NodeKind::Move(m) => {
                if !m.is_valid() {
                    return Err(Error::invalid(format!("node {i}: invalid Move16")));
                }
                match &positions[parent] {
                    Some(p) if checks.legality => Some(p.play(m).map_err(|_| Error::invalid(format!("node {i}: illegal move {}", m.to_usi())))?),
                    Some(p) => Some(p.play_unchecked(m)),
                    None => None,
                }
            }
            NodeKind::Event(code) => {
                if !crate::model::event::is_defined(code) && !checks.allow_unknown {
                    return Err(Error::invalid(format!("node {i}: undefined event code {code}")));
                }
                // §8.5: a game won or lost by default is the root followed by that event only.
                if matches!(code, crate::model::event::DEFAULT_WIN | crate::model::event::DEFAULT_LOSS) && (i != 1 || r.nodes.len() != 2) {
                    return Err(Error::invalid(format!("node {i}: a default win or loss must be the only node after the root")));
                }
                None
            }
            NodeKind::Root => None,
        };
        positions.push(pos);
        chain.push(i);
    }
    Ok(())
}

/// Positions of every node of a record (`None` for events).
pub fn record_positions(r: &Record) -> Vec<Option<Position>> {
    let mut out: Vec<Option<Position>> = Vec::with_capacity(r.nodes.len());
    for (i, n) in r.nodes.iter().enumerate() {
        let p = match n.kind {
            NodeKind::Root => Some(r.start.clone()),
            NodeKind::Move(m) if i > 0 => out.get(n.parent as usize).cloned().flatten().map(|p| p.play_unchecked(m)),
            _ => None,
        };
        out.push(p);
    }
    out
}

/// SPDX license expression, checked for its lexical shape (identifiers, `WITH`, `AND`,
/// `OR`, parentheses, `+`), or `NOASSERTION` / `NONE`.
pub fn valid_license(s: &str) -> bool {
    if s.is_empty() || s.len() > 4096 {
        return false;
    }
    let spaced = s.replace('(', " ( ").replace(')', " ) ");
    let mut depth = 0i32;
    let mut expect_id = true;
    for tok in spaced.split_whitespace() {
        match tok {
            "(" if expect_id => depth += 1,
            ")" if !expect_id => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            "AND" | "OR" | "WITH" if !expect_id => expect_id = true,
            t if expect_id => {
                let id = t.strip_suffix('+').unwrap_or(t);
                let id = id.strip_prefix("DocumentRef-").map_or(id, |r| r.split_once(':').map_or("", |(_, b)| b));
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
                    return false;
                }
                expect_id = false;
            }
            _ => return false,
        }
    }
    !expect_id && depth == 0
}

/// RFC 3339 full-date `YYYY-MM-DD` with a valid day of month.
pub fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> { s.get(r).filter(|t| t.bytes().all(|c| c.is_ascii_digit()))?.parse().ok() };
    let (Some(y), Some(m), Some(d)) = (num(0..4), num(5..7), num(8..10)) else { return false };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d)
}

/// The positions of the table, keyed by their encoding, with their order (§7.16).
pub fn canonical_order(spg: &Spg) -> Vec<(Encoded, usize)> {
    let mut v: Vec<(Encoded, usize)> = spg.positions.iter().enumerate().map(|(i, p)| (p.position.encode(), i)).collect();
    v.sort_by(|a, b| a.0.sort_key().cmp(&b.0.sort_key()));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn licenses_and_dates() {
        for ok in ["MIT", "NOASSERTION", "MIT OR Apache-2.0", "(MIT AND BSD-3-Clause) OR GPL-2.0+", "LicenseRef-Foo", "GPL-2.0 WITH Classpath-exception-2.0"] {
            assert!(valid_license(ok), "{ok}");
        }
        for bad in ["", "MIT OR", "(MIT", "MIT)", "M I T", "MIT AND AND BSD"] {
            assert!(!valid_license(bad), "{bad}");
        }
        assert!(valid_date("2026-11-06"));
        assert!(valid_date("2024-02-29"));
        assert!(!valid_date("2023-02-29"));
        assert!(!valid_date("2026-13-01"));
        assert!(!valid_date("26-11-06"));
    }

    #[test]
    fn keys() {
        assert!(valid_key("x.sakiyomi.mark"));
        assert!(!valid_key("X.a.b"));
        assert!(!valid_key("a..b"));
        assert!(known_key("src.yane.ply"));
        assert!(!known_key("src.yane"));
        assert!(!known_key("foo"));
        assert_eq!(schema_type("src.range.ms"), Some(SchemaType::Str));
        assert_eq!(schema_type("x.a.b"), None);
    }
}
