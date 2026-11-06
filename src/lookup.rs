//! Probing a book the way an engine does (§7.15): bucket range from KBKT, binary search in
//! PKEY, confirmation by CPE, then the edges. Only the blocks that are touched are checked
//! (§11.2, §11.3), and [`Book::verify_for_play`] re-checks them right before a move is
//! played (§11.4). Nothing is decoded up front, so opening is cheap even for large files.

use crate::container::Container;
use crate::error::{Error, Result};
use crate::eval;
use crate::layout::*;
use crate::model::{EdgeEval, Stats};
use crate::moves::Move;
use crate::position::{Encoded, Position};
use crate::validate::MAX_EDGES;

/// One edge as stored.
#[derive(Clone, Debug, PartialEq)]
pub struct EdgeView {
    pub mv: Move,
    pub disabled: bool,
    pub weight: Option<u32>,
    pub eval: Option<EdgeEval>,
    pub stats: Option<Stats>,
    /// Global index of the child position, when it is in the file set.
    pub child: Option<u64>,
}

pub struct Book<'a> {
    c: Container<'a>,
    b: u8,
    s: u8,
    kbkt: usize,
    pkey: usize,
    posn: usize,
    edges: usize,
    compact: bool,
    common_engine: u16,
    positions: u64,
    edge_count: u64,
    engine_units: Vec<eval::Unit>,
}

impl<'a> Book<'a> {
    /// Open with the open-time checks of §13.1.
    pub fn open(bytes: &'a [u8]) -> Result<Book<'a>> {
        let c = Container::open(bytes)?;
        c.verify_tail()?;
        if c.header.kind == FileKind::RecordsOnly {
            return Err(Error::rejected("a records-only file has no positions"));
        }
        let idx = |t| c.index(t).ok_or_else(|| Error::rejected("missing section"));
        let kbkt = idx(KBKT)?;
        let (_, _, spec) = c.prelude(kbkt);
        let (b, s) = (spec[0], spec[1]);
        let (pkey, posn) = (idx(PKEY)?, idx(POSN)?);
        let compact = c.index(EDGC).is_some();
        let edges = if compact { idx(EDGC)? } else { idx(EDGE)? };
        let positions = c.prelude(posn).0;
        if c.prelude(pkey).0 != positions {
            return Err(Error::corrupt_in(PKEY, "PKEY and POSN counts differ"));
        }
        let common_engine = if compact { u16_at(c.prelude(edges).2, 0).unwrap_or(NONE16) } else { NONE16 };
        let mut engine_units = Vec::new();
        if let Some(e) = c.index(ENGN) {
            c.verify(e, 0..c.entries[e].len)?;
            let raw = c.raw(e);
            engine_units = (0..c.prelude(e).0 as usize).map(|k| eval::Unit::from_code(raw[PRELUDE_LEN + k * 24 + 16])).collect();
        }
        let edge_count = c.prelude(edges).0;
        Ok(Book { c, b, s, kbkt, pkey, posn, edges, compact, common_engine, positions, edge_count, engine_units })
    }

    pub fn container(&self) -> &Container<'a> {
        &self.c
    }

    fn record(&self, sec: usize, rec: usize, k: u64, fresh: bool) -> Result<&'a [u8]> {
        let start = PRELUDE_LEN + usize::try_from(k).map_err(|_| Error::corrupt("index overflow"))? * rec;
        let range = start..start + rec;
        if fresh { self.c.verify_fresh(sec, range.clone())? } else { self.c.verify(sec, range.clone())? };
        self.c.raw(sec).get(range).ok_or_else(|| Error::corrupt("record out of range"))
    }

    fn key_at(&self, k: u64) -> Result<u64> {
        Ok(u64_at(self.record(self.pkey, 8, k, false)?, 0).unwrap_or(0))
    }

    /// Local index of a position (§7.15 steps 1–5).
    pub fn find(&self, pos: &Position) -> Result<Option<u64>> {
        let enc = pos.encode();
        let key = enc.key();
        if self.s > 0 && u64::from(shard_of(key, self.s)) != u64::from(self.c.header.shard) {
            return Ok(None);
        }
        let i = bucket(key, self.b, self.s);
        let lo = u64_at(self.record(self.kbkt, 8, i, false)?, 0).unwrap_or(0);
        let hi = u64_at(self.record(self.kbkt, 8, i + 1, false)?, 0).unwrap_or(0);
        if lo > hi || hi > self.positions {
            return Err(Error::corrupt_in(KBKT, "bucket range out of bounds"));
        }
        // Lower bound of `key` in [lo, hi).
        let (mut a, mut b) = (lo, hi);
        while a < b {
            let m = a + (b - a) / 2;
            if self.key_at(m)? < key {
                a = m + 1;
            } else {
                b = m;
            }
        }
        let mut k = a;
        while k < hi && self.key_at(k)? == key {
            let row = self.record(self.posn, 48, k, false)?;
            let flags = u16_at(row, 42).unwrap_or(0);
            let same = match &enc {
                Encoded::Cpe(c) => flags & 1 == 0 && row[..32] == c[..],
                Encoded::Sfen(s) => flags & 1 != 0 && self.string(u64_at(row, 0).unwrap_or(0))?.as_deref() == Some(s.as_str()),
            };
            if same {
                return Ok(Some(k));
            }
            k += 1;
        }
        Ok(None)
    }

    fn string(&self, at: u64) -> Result<Option<String>> {
        let Some(si) = self.c.index(STRS) else { return Ok(None) };
        let at = usize::try_from(at).map_err(|_| Error::corrupt("string offset"))?;
        let raw = self.c.raw(si);
        let len = u32_at(raw, at).ok_or_else(|| Error::corrupt_in(STRS, "string out of range"))? as usize;
        let end = at.checked_add(4 + len).filter(|&e| e <= raw.len() && at >= PRELUDE_LEN).ok_or_else(|| Error::corrupt_in(STRS, "string out of range"))?;
        self.c.verify(si, at..end)?;
        Ok(std::str::from_utf8(&raw[at + 4..end]).ok().map(str::to_owned))
    }

    fn edges_with(&self, k: u64, fresh: bool) -> Result<Vec<EdgeView>> {
        let row = self.record(self.posn, 48, k, fresh)?;
        let start = u64_at(row, 32).unwrap_or(0);
        let n = u64::from(u16_at(row, 40).unwrap_or(0));
        if n as usize > MAX_EDGES || start.checked_add(n).is_none_or(|e| e > self.edge_count) {
            return Err(Error::corrupt_in(POSN, "edge range out of bounds"));
        }
        let mut out = Vec::with_capacity(n as usize);
        for j in start..start + n {
            let e = self.record(self.edges, if self.compact { 16 } else { 48 }, j, fresh)?;
            out.push(self.edge(e)?);
        }
        Ok(out)
    }

    /// Edges of a position, with the access-time checks of §11.3.
    pub fn edges(&self, k: u64) -> Result<Vec<EdgeView>> {
        self.edges_with(k, false)
    }

    fn edge(&self, e: &[u8]) -> Result<EdgeView> {
        let tag = if self.compact { EDGC } else { EDGE };
        let corrupt = |m: &str| Error::corrupt_in(tag, m.to_owned());
        let mv = Move(u16_at(e, 0).unwrap_or(0));
        if !mv.is_valid() {
            return Err(corrupt("invalid Move16"));
        }
        let f = u16_at(e, 2).unwrap_or(0);
        let strict = self.c.strict();
        let unit = |engine: u16| self.engine_units.get(usize::from(engine)).copied();
        if self.compact {
            if strict && f & !(1 | 2 | 8 | 32) != 0 {
                return Err(corrupt("reserved flag bits"));
            }
            let v = i32_at(e, 4).unwrap_or(0);
            let eval = if f & 2 != 0 {
                let u = unit(self.common_engine).ok_or_else(|| corrupt("engine index out of range"))?;
                if !eval::is_valid(v, u) {
                    return Err(corrupt("value out of range"));
                }
                Some(EdgeEval { value: v, engine: self.common_engine, depth: None })
            } else {
                None
            };
            let child = u64_at(e, 8).unwrap_or(NONE64);
            return Ok(EdgeView { mv, disabled: f & 1 != 0, weight: None, eval, stats: None, child: (child != NONE64).then_some(child) });
        }
        if strict && f & !63 != 0 {
            return Err(corrupt("reserved flag bits"));
        }
        let (depth, engine, weight, v) = (u16_at(e, 4).unwrap_or(0), u16_at(e, 6).unwrap_or(0), u32_at(e, 8).unwrap_or(0), i32_at(e, 12).unwrap_or(0));
        let eval = if f & 2 != 0 {
            let u = unit(engine).ok_or_else(|| corrupt("engine index out of range"))?;
            if !eval::is_valid(v, u) {
                return Err(corrupt("value out of range"));
            }
            Some(EdgeEval { value: v, engine, depth: (depth != NONE16).then_some(depth) })
        } else {
            if v != eval::NONE || engine != NONE16 || depth != NONE16 {
                return Err(corrupt("evaluation fields without the flag"));
            }
            None
        };
        let s = Stats { games: u64_at(e, 24).unwrap_or(0), wins: u64_at(e, 32).unwrap_or(0), draws: u64_at(e, 40).unwrap_or(0) };
        let stats = if f & 4 != 0 {
            if s.wins.checked_add(s.draws).is_none_or(|x| x > s.games) {
                return Err(corrupt("wins + draws exceed games"));
            }
            Some(s)
        } else {
            None
        };
        if f & 16 == 0 && weight != 0 {
            return Err(corrupt("weight without the flag"));
        }
        let child = u64_at(e, 16).unwrap_or(NONE64);
        Ok(EdgeView { mv, disabled: f & 1 != 0, weight: (f & 16 != 0).then_some(weight), eval, stats, child: (child != NONE64).then_some(child) })
    }

    /// The re-verification right before playing `mv` from `pos` (§11.4): the position's
    /// record and edges are hashed again and the move is checked for legality.
    pub fn verify_for_play(&self, pos: &Position, mv: Move) -> Result<bool> {
        let Some(k) = self.find(pos)? else { return Ok(false) };
        let row = self.record(self.posn, 48, k, true)?;
        let _ = row;
        let edges = self.edges_with(k, true)?;
        Ok(edges.iter().any(|e| e.mv == mv && !e.disabled) && pos.is_legal(mv))
    }
}
