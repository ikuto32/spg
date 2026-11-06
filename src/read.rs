//! Decoding `.spg` files into the logical model, with the full checks of a verification
//! tool (§13.1): every block, every record, every invariant of §13.2, derived data against
//! the data it is derived from, and (by default) the legality of every move.

use std::collections::{HashMap, HashSet};

use crate::container::{Container, tag_str};
use crate::error::{Error, Result};
use crate::eval;
use crate::layout::*;
use crate::model::*;
use crate::moves::Move;
use crate::position::{Encoded, Position};
use crate::validate::{self, Checks, MAX_EDGES};

#[derive(Clone, Debug)]
pub struct ReadOptions {
    /// Check move legality (§6.7) of every edge, record move and the derived child links.
    pub legality: bool,
    /// Upper bound on bytes decoded into strings and move lists, as a multiple of the file
    /// size plus a constant (guards against references that repeat one large item).
    pub expansion_factor: u64,
}

impl Default for ReadOptions {
    fn default() -> Self {
        ReadOptions { legality: true, expansion_factor: 8 }
    }
}

/// What a read found besides the data.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ReadInfo {
    pub kind: Option<FileKind>,
    pub minor: u16,
    pub build_id: u64,
    pub used_tail_copy: bool,
    /// Merkle root of BLK3 when present (only meaningful against a signed manifest).
    pub blk3_root: Option<[u8; 32]>,
    pub edge_form_compact: bool,
    /// Bucket parameters (b, s).
    pub buckets: Option<(u8, u8)>,
}

/// One decoded file before files of a set are linked together.
pub(crate) struct Part {
    pub info: ReadInfo,
    pub first_global: u64,
    pub spg: Spg,
    /// Per position, per edge: the stored child index.
    pub children: Vec<Vec<u64>>,
    pub record_start_global: Vec<u64>,
    pub occr: Option<Vec<(u64, u64, u64)>>,
    pub keys: Vec<u64>,
    pub kbkt: Vec<u64>,
}

struct Budget(u64);

impl Budget {
    fn take(&mut self, n: u64) -> Result<()> {
        self.0 = self.0.checked_sub(n).ok_or_else(|| Error::Limit("references expand to too much data".into()))?;
        Ok(())
    }
}

struct Ctx<'a, 'b> {
    c: &'b Container<'a>,
    strict: bool,
    budget: Budget,
    strs: Option<(usize, HashSet<u64>)>,
    mvls: Option<(usize, u64)>,
}

fn bad(tag: Tag, m: impl Into<String>) -> Error {
    Error::corrupt_in(tag, m)
}

impl<'a> Ctx<'a, '_> {
    fn section(&self, tag: Tag) -> Option<(usize, &'a [u8], u64)> {
        let i = self.c.index(tag)?;
        let (count, _, _) = self.c.prelude(i);
        Some((i, self.c.raw(i), count))
    }

    fn string(&mut self, at: u64, tag: Tag) -> Result<String> {
        let Some((si, set)) = &self.strs else { return Err(bad(tag, "string reference without STRS")) };
        if !set.contains(&at) {
            return Err(bad(tag, format!("string reference {at} does not point to a string")));
        }
        let b = self.c.raw(*si);
        let at = at as usize;
        let len = u32_at(b, at).unwrap_or(0) as usize;
        self.budget.take(len as u64)?;
        let s = std::str::from_utf8(&b[at + 4..at + 4 + len]).map_err(|_| bad(STRS, "invalid UTF-8"))?;
        Ok(s.to_owned())
    }

    fn opt_string(&mut self, at: u64, tag: Tag) -> Result<Option<String>> {
        if at == NONE64 { Ok(None) } else { self.string(at, tag).map(Some) }
    }

    fn moves(&mut self, v: u64, tag: Tag) -> Result<Vec<Move>> {
        let Some((mi, n)) = self.mvls else { return Err(bad(tag, "move list without MVLS")) };
        let start = v & ((1 << 48) - 1);
        let len = v >> 48;
        if start.checked_add(len).is_none_or(|e| e > n) {
            return Err(bad(tag, "move list out of range"));
        }
        self.budget.take(len * 2)?;
        let b = self.c.raw(mi);
        Ok((start..start + len).map(|k| Move(u16_at(b, PRELUDE_LEN + k as usize * 2).unwrap_or(0))).collect())
    }

    fn reserved_zero(&self, tag: Tag, row: &[u8], range: std::ops::Range<usize>) -> Result<()> {
        if self.strict && row[range].iter().any(|&b| b != 0) {
            return Err(bad(tag, "reserved field is not zero"));
        }
        Ok(())
    }

    fn rows(&self, tag: Tag, rec: usize) -> Vec<&'a [u8]> {
        match self.section(tag) {
            Some((_, b, n)) => (0..n as usize).map(|k| &b[PRELUDE_LEN + k * rec..PRELUDE_LEN + (k + 1) * rec]).collect(),
            None => Vec::new(),
        }
    }
}

fn r16(b: &[u8], at: usize) -> u16 {
    u16_at(b, at).unwrap_or(0)
}
fn r32(b: &[u8], at: usize) -> u32 {
    u32_at(b, at).unwrap_or(0)
}
fn r64(b: &[u8], at: usize) -> u64 {
    u64_at(b, at).unwrap_or(0)
}
fn ri32(b: &[u8], at: usize) -> i32 {
    i32_at(b, at).unwrap_or(0)
}

fn check_move(m: Move, tag: Tag) -> Result<Move> {
    if m.is_valid() { Ok(m) } else { Err(bad(tag, format!("invalid Move16 {:#06x}", m.0))) }
}

/// Read a single `.spg` file (no manifest).
pub fn read(bytes: &[u8], opts: &ReadOptions) -> Result<(Spg, ReadInfo)> {
    let c = Container::open(bytes)?;
    if c.header.kind == FileKind::PositionShard {
        return Err(Error::rejected("a position shard is read through its manifest (.spgm)"));
    }
    let part = decode(&c, opts)?;
    if part.info.buckets.is_some_and(|(_, s)| s != 0) {
        return Err(Error::corrupt_in(KBKT, "a single file has s = 0"));
    }
    let total = part.spg.positions.len() as u64;
    let (spg, mut infos) = link(vec![part], total, opts)?;
    Ok((spg, infos.remove(0)))
}

pub(crate) fn decode(c: &Container, opts: &ReadOptions) -> Result<Part> {
    c.verify_all()?;
    c.verify_layout()?;
    let blk3_root = c.verify_blk3()?;
    let mut x = Ctx {
        c,
        strict: c.strict(),
        budget: Budget((c.bytes.len() as u64).saturating_mul(opts.expansion_factor).saturating_add(64 << 20)),
        strs: None,
        mvls: None,
    };
    let first_global = c.header.first_global;

    // STRS: walk every string (§13.2.11).
    if let Some((si, b, count)) = x.section(STRS) {
        let mut starts = HashSet::new();
        let mut at = PRELUDE_LEN;
        while at < b.len() {
            let len = u32_at(b, at).ok_or_else(|| bad(STRS, "truncated string"))? as usize;
            let end = at.checked_add(4 + len).filter(|&e| e <= b.len()).ok_or_else(|| bad(STRS, "string runs past the section"))?;
            std::str::from_utf8(&b[at + 4..end]).map_err(|_| bad(STRS, "invalid UTF-8"))?;
            starts.insert(at as u64);
            at = end;
        }
        if starts.len() as u64 != count {
            return Err(bad(STRS, "string count does not match the prelude"));
        }
        x.strs = Some((si, starts));
    }
    if let Some((mi, _, count)) = x.section(MVLS) {
        let b = c.raw(mi);
        for k in 0..count as usize {
            check_move(Move(r16(b, PRELUDE_LEN + k * 2)), MVLS)?;
        }
        x.mvls = Some((mi, count));
    }

    // Dictionaries.
    let mut keys = Vec::new();
    for row in x.rows(AKEY, 8) {
        let k = x.string(r64(row, 0), AKEY)?;
        if !validate::valid_key(&k) || keys.contains(&k) {
            return Err(bad(AKEY, format!("bad or duplicate key {k:?}")));
        }
        keys.push(k);
    }
    let mut spg = Spg::default();
    for row in x.rows(ENGN, 24) {
        x.reserved_zero(ENGN, row, 17..18)?;
        x.reserved_zero(ENGN, row, 20..24)?;
        let unit = eval::Unit::from_code(row[16]);
        if x.strict && matches!(unit, eval::Unit::Unknown(_)) {
            return Err(bad(ENGN, "reserved unit"));
        }
        spg.engines.push(Engine { name: x.string(r64(row, 0), ENGN)?, version: x.string(r64(row, 8), ENGN)?, unit, pawn: r16(row, 18), annos: Vec::new() });
    }
    for row in x.rows(RGHT, 64) {
        x.reserved_zero(RGHT, row, 1..8)?;
        x.reserved_zero(RGHT, row, 56..64)?;
        let role = Role::from_code(row[0]);
        if x.strict && matches!(role, Role::Unknown(_)) {
            return Err(bad(RGHT, "reserved role"));
        }
        spg.rights.push(Rights {
            role,
            name: x.string(r64(row, 8), RGHT)?,
            copyright: x.opt_string(r64(row, 16), RGHT)?,
            license: x.string(r64(row, 24), RGHT)?,
            license_text: x.opt_string(r64(row, 32), RGHT)?,
            url: x.opt_string(r64(row, 40), RGHT)?,
            date: x.opt_string(r64(row, 48), RGHT)?,
        });
    }
    for row in x.rows(SRCS, 24) {
        x.reserved_zero(SRCS, row, 16..24)?;
        spg.sources.push(Source { name: x.string(r64(row, 0), SRCS)?, uri: x.opt_string(r64(row, 8), SRCS)?, annos: Vec::new() });
    }

    // Positions and edges.
    let mut keys_col = Vec::new();
    let mut kbkt = Vec::new();
    let mut buckets = None;
    let mut children: Vec<Vec<u64>> = Vec::new();
    let mut pos_flags = Vec::new();
    let mut edge_flags = Vec::new();
    let mut compact = false;
    if c.header.kind != FileKind::RecordsOnly {
        let (ki, kb, kn) = x.section(KBKT).ok_or_else(|| Error::rejected("KBKT missing"))?;
        let (_, _, spec) = c.prelude(ki);
        buckets = Some((spec[0], spec[1]));
        kbkt = (0..kn as usize).map(|k| r64(kb, PRELUDE_LEN + k * 8)).collect();
        keys_col = x.rows(PKEY, 8).iter().map(|r| r64(r, 0)).collect();
        let posn = x.rows(POSN, 48);
        if posn.len() != keys_col.len() {
            return Err(bad(PKEY, "PKEY and POSN have different counts"));
        }
        let (edge_tag, rec) = if c.index(EDGC).is_some() { (EDGC, 16) } else { (EDGE, 48) };
        compact = edge_tag == EDGC;
        let edges = x.rows(edge_tag, rec);
        let common_engine = if compact { c.index(EDGC).map(|i| r16(c.prelude(i).2, 0)) } else { None };
        let mut next_edge = 0u64;
        for (pi, row) in posn.iter().enumerate() {
            let flags = r16(row, 42);
            if x.strict && flags & !7 != 0 {
                return Err(bad(POSN, "reserved flag bits"));
            }
            x.reserved_zero(POSN, row, 44..48)?;
            let extended = flags & 1 != 0;
            let position = if extended {
                x.reserved_zero(POSN, row, 8..32)?;
                let s = x.string(r64(row, 0), POSN)?;
                let p = Position::from_sfen(&s).map_err(|_| bad(POSN, format!("not a canonical SFEN: {s:?}")))?;
                if p.is_normal() {
                    return Err(bad(POSN, "a normal position stored as SFEN"));
                }
                p
            } else {
                let cpe: [u8; 32] = row[..32].try_into().map_err(|_| bad(POSN, "short row"))?;
                Position::from_cpe(&cpe).map_err(|e| e.in_section(POSN))?
            };
            let start = r64(row, 32);
            let n = r16(row, 40) as usize;
            if start != next_edge || n > MAX_EDGES || start + n as u64 > edges.len() as u64 {
                return Err(bad(POSN, format!("position {pi}: edge range out of order or out of bounds")));
            }
            next_edge += n as u64;
            let mut entry = PositionEntry::new(position);
            let mut ch = Vec::with_capacity(n);
            for e in &edges[start as usize..start as usize + n] {
                let mv = Move(r16(e, 0));
                if mv.0 == 0 {
                    return Err(bad(edge_tag, "edge move 0x0000"));
                }
                check_move(mv, edge_tag)?;
                let f = r16(e, 2);
                let mut edge = Edge::new(mv);
                edge.disabled = f & 1 != 0;
                if compact {
                    if x.strict && f & !(1 | 2 | 8 | 32) != 0 {
                        return Err(bad(EDGC, "reserved flag bits"));
                    }
                    let v = ri32(e, 4);
                    if f & 2 != 0 {
                        let engine = common_engine.unwrap_or(NONE16);
                        edge.eval = Some(EdgeEval { value: v, engine, depth: None });
                    } else if v != eval::NONE {
                        return Err(bad(EDGC, "value without the evaluation flag"));
                    }
                    ch.push(r64(e, 8));
                } else {
                    if x.strict && f & !63 != 0 {
                        return Err(bad(EDGE, "reserved flag bits"));
                    }
                    let (depth, engine, weight, v) = (r16(e, 4), r16(e, 6), r32(e, 8), ri32(e, 12));
                    if f & 2 != 0 {
                        edge.eval = Some(EdgeEval { value: v, engine, depth: (depth != NONE16).then_some(depth) });
                    } else if v != eval::NONE || engine != NONE16 || depth != NONE16 {
                        return Err(bad(EDGE, "evaluation fields without the evaluation flag"));
                    }
                    if f & 16 != 0 {
                        edge.weight = Some(weight);
                    } else if weight != 0 {
                        return Err(bad(EDGE, "weight without the weight flag"));
                    }
                    let s = Stats { games: r64(e, 24), wins: r64(e, 32), draws: r64(e, 40) };
                    if f & 4 != 0 {
                        edge.stats = Some(s);
                    } else if s != Stats::default() {
                        return Err(bad(EDGE, "statistics without the statistics flag"));
                    }
                    ch.push(r64(e, 16));
                }
                edge_flags.push(f);
                entry.edges.push(edge);
            }
            children.push(ch);
            pos_flags.push(flags);
            spg.positions.push(entry);
        }
        if next_edge != edges.len() as u64 {
            return Err(bad(edge_tag, "edges not covered by any position"));
        }
        if let Some(e) = common_engine {
            let any = spg.positions.iter().any(|p| p.edges.iter().any(|e| e.eval.is_some()));
            if any == (e == NONE16) {
                return Err(bad(EDGC, "common engine must be set exactly when an edge has a value"));
            }
        }
    }

    // Records.
    let rnod = x.rows(RNOD, 16);
    let meta = x.rows(META, 16);
    let mut covered = vec![false; rnod.len()];
    let mut record_start_global = Vec::new();
    let mut rnod_flags = vec![0u16; rnod.len()];
    let mut node_owner: Vec<(usize, usize)> = vec![(usize::MAX, 0); rnod.len()];
    let mut rec_flags = Vec::new();
    for (ri, row) in x.rows(RECS, 80).iter().enumerate() {
        let flags = row[77];
        if x.strict && flags & !7 != 0 {
            return Err(bad(RECS, "reserved flag bits"));
        }
        x.reserved_zero(RECS, row, 78..80)?;
        let start = if flags & 1 != 0 {
            x.reserved_zero(RECS, row, 8..32)?;
            let s = x.string(r64(row, 0), RECS)?;
            let p = Position::from_sfen(&s).map_err(|_| bad(RECS, "bad start SFEN"))?;
            if p.is_normal() {
                return Err(bad(RECS, "a normal start position stored as SFEN"));
            }
            p
        } else {
            let cpe: [u8; 32] = row[..32].try_into().map_err(|_| bad(RECS, "short row"))?;
            Position::from_cpe(&cpe).map_err(|e| e.in_section(RECS))?
        };
        let (first, meta_first, raw, n, mn) = (r64(row, 40), r64(row, 48), r64(row, 56), r32(row, 64) as u64, r32(row, 68) as u64);
        if n == 0 || first.checked_add(n).is_none_or(|e| e > rnod.len() as u64) {
            return Err(bad(RECS, format!("record {ri}: node range out of bounds")));
        }
        if (mn == 0 && meta_first != 0) || meta_first.checked_add(mn).is_none_or(|e| e > meta.len() as u64) {
            return Err(bad(RECS, format!("record {ri}: meta range out of bounds")));
        }
        let result = GameResult::from_code(row[76]);
        if x.strict && matches!(result, GameResult::Reserved(_)) {
            return Err(bad(RECS, "reserved result"));
        }
        let mut rec = Record::new(start);
        rec.start_ply = r32(row, 72);
        rec.result = result;
        rec.nongame = flags & 2 != 0;
        rec.raw = (raw != NONE64).then_some(raw);
        rec.nodes.clear();
        for k in 0..mn as usize {
            let m = meta[meta_first as usize + k];
            rec.meta.push((x.string(r64(m, 0), META)?, x.string(r64(m, 8), META)?));
        }
        for k in 0..n as usize {
            let gi = first as usize + k;
            if std::mem::replace(&mut covered[gi], true) {
                return Err(bad(RNOD, "a node belongs to two records"));
            }
            node_owner[gi] = (ri, k);
            let nr = rnod[gi];
            let (dist, mv, kind, code, t, f) = (r32(nr, 0), Move(r16(nr, 4)), nr[6], nr[7], r32(nr, 8), r16(nr, 12));
            if x.strict && f & !3 != 0 {
                return Err(bad(RNOD, "reserved flag bits"));
            }
            x.reserved_zero(RNOD, nr, 14..16)?;
            let node_kind = match kind {
                0 if k == 0 && dist == 0 && mv.0 == 0 && code == 0 => NodeKind::Root,
                1 if k > 0 && dist >= 1 && dist as usize <= k && mv.0 != 0 && code == 0 => NodeKind::Move(check_move(mv, RNOD)?),
                2 if k > 0 && dist >= 1 && dist as usize <= k && mv.0 == 0 => {
                    if !event::is_defined(code) && (x.strict || code == 0) {
                        return Err(bad(RNOD, format!("undefined event code {code}")));
                    }
                    NodeKind::Event(code)
                }
                _ => return Err(bad(RNOD, format!("record {ri} node {k}: fields do not match the node kind"))),
            };
            let mut node = RecordNode::new(if k == 0 { 0 } else { (k - dist as usize) as u32 }, node_kind);
            node.time_ms = (t != NONE32).then_some(t);
            rnod_flags[gi] = f;
            rec.nodes.push(node);
        }
        rec_flags.push(flags);
        record_start_global.push(r64(row, 32));
        spg.records.push(rec);
    }
    if covered.iter().any(|c| !c) {
        return Err(bad(RNOD, "nodes not covered by any record"));
    }
    // Analyses (flat, in file order).
    let mut flat_anls: Vec<(u8, u64, Option<Analysis>)> = Vec::new();
    let mut prev = (0u8, 0u64);
    for row in x.rows(ANLS, 56) {
        let (kind, ctx, rank, engine, bound, flags, target) = (row[0], row[1], r16(row, 2), r16(row, 4), row[6], row[7], r64(row, 8));
        if !(1..=3).contains(&kind) {
            return Err(bad(ANLS, "reserved target kind"));
        }
        if (kind, target) < prev {
            return Err(bad(ANLS, "entries out of order"));
        }
        prev = (kind, target);
        if x.strict && flags & 0x80 != 0 {
            return Err(bad(ANLS, "reserved flag bit"));
        }
        x.reserved_zero(ANLS, row, 38..40)?;
        let mut a = Analysis::new(Context::from_code(ctx), engine);
        a.rank = rank;
        a.bound = Bound::from_code(bound);
        if x.strict && (matches!(a.context, Context::Unknown(_)) || matches!(a.bound, Bound::Unknown(_))) {
            return Err(bad(ANLS, "reserved context or bound"));
        }
        let v = ri32(row, 16);
        a.eval = (v != eval::NONE).then_some(v);
        let field = |bit: u8, present: bool, zero: bool| -> Result<bool> {
            if flags & (1 << bit) != 0 {
                Ok(present)
            } else if !zero {
                Err(bad(ANLS, "a field without its flag is not zero"))
            } else {
                Ok(false)
            }
        };
        let (d, sd, nodes, ms, wr, pv) = (r16(row, 20), r16(row, 22), r64(row, 24), r32(row, 32), r16(row, 36), r64(row, 40));
        if field(0, true, d == 0)? {
            a.depth = Some(d);
        }
        if field(1, true, sd == 0)? {
            a.seldepth = Some(sd);
        }
        if field(2, true, nodes == 0)? {
            a.nodes = Some(nodes);
        }
        if field(3, true, ms == 0)? {
            a.time_ms = Some(ms);
        }
        if field(4, true, pv == 0)? {
            a.pv = Some(x.moves(pv, ANLS)?);
        }
        if field(5, true, wr == 0)? {
            a.winrate = Some(wr);
        }
        a.viewpoint_unknown = flags & 0x40 != 0;
        a.group = r64(row, 48);
        flat_anls.push((kind, target, Some(a)));
    }

    // Annotations (flat), kind-7 entries folded into their targets.
    let mut flat_anno: Vec<(u8, u64, Option<Anno>)> = Vec::new();
    let mut rights_of: Vec<(u64, u64)> = Vec::new();
    let mut prev = (0u8, 0u64);
    for (ai, row) in x.rows(ANNO, 24).iter().enumerate() {
        let (kind, ty, key, target, value) = (row[0], row[1], r32(row, 4), r64(row, 8), r64(row, 16));
        x.reserved_zero(ANNO, row, 2..4)?;
        if !(1..=9).contains(&kind) {
            return Err(bad(ANNO, "reserved target kind"));
        }
        if (kind, target) < prev {
            return Err(bad(ANNO, "entries out of order"));
        }
        prev = (kind, target);
        let key = keys.get(key as usize).cloned().ok_or_else(|| bad(ANNO, "key index out of range"))?;
        let value = match ty {
            1 => Value::Int(value as i64),
            2 => {
                let f = f64::from_bits(value);
                if !f.is_finite() {
                    return Err(bad(ANNO, "non-finite real"));
                }
                Value::Real(f)
            }
            3 => Value::Str(x.string(value, ANNO)?),
            4 => Value::Moves(x.moves(value, ANNO)?),
            5 => match value {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                _ => return Err(bad(ANNO, "boolean other than 0 or 1")),
            },
            0 => return Err(bad(ANNO, "reserved value type 0")),
            ty => Value::Reserved { ty, raw: value },
        };
        if kind == 7 {
            let Value::Int(r) = value else { return Err(bad(ANNO, "rights must be an integer")) };
            if key != "rights" || target == ai as u64 {
                return Err(bad(ANNO, "an annotation-entry annotation must be rights of another entry"));
            }
            rights_of.push((target, r as u64));
            flat_anno.push((7, target, None));
            continue;
        }
        flat_anno.push((kind, target, Some(Anno { key, value, rights: Vec::new() })));
    }

    for (t, r) in rights_of {
        match flat_anno.get_mut(t as usize) {
            Some((k, _, Some(a))) if *k != 7 => a.rights.push(r),
            _ => return Err(bad(ANNO, "rights target is not an annotation entry")),
        }
    }
    // Attach analyses' annotations, then distribute everything.
    for (kind, target, a) in &mut flat_anno {
        if *kind == 8 {
            let anno = a.take();
            match flat_anls.get_mut(*target as usize) {
                Some((_, _, Some(an))) => an.annos.extend(anno),
                _ => return Err(bad(ANNO, "analysis target out of range")),
            }
        }
    }
    let n_pos = spg.positions.len() as u64;
    let edge_owner: Vec<(usize, usize)> = spg.positions.iter().enumerate().flat_map(|(p, e)| (0..e.edges.len()).map(move |k| (p, k))).collect();
    let node_index: Vec<(usize, usize)> = node_owner.clone();
    for (kind, target, a) in flat_anls {
        let Some(a) = a else { continue };
        if usize::from(a.engine) >= spg.engines.len() {
            return Err(bad(ANLS, "engine index out of range"));
        }
        match kind {
            1 => {
                let local = target.checked_sub(first_global).filter(|&l| l < n_pos).ok_or_else(|| bad(ANLS, "position target out of range"))?;
                spg.positions[local as usize].analyses.push(a);
            }
            2 => {
                let &(p, e) = edge_owner.get(target as usize).ok_or_else(|| bad(ANLS, "edge target out of range"))?;
                spg.positions[p].edges[e].analyses.push(a);
            }
            _ => {
                let &(r, n) = node_index.get(target as usize).ok_or_else(|| bad(ANLS, "node target out of range"))?;
                spg.records[r].nodes[n].analyses.push(a);
            }
        }
    }
    for (kind, target, a) in flat_anno {
        let Some(a) = a else { continue };
        let oob = || bad(ANNO, format!("target {target} of kind {kind} out of range"));
        match kind {
            1 => {
                let local = target.checked_sub(first_global).filter(|&l| l < n_pos).ok_or_else(oob)?;
                spg.positions[local as usize].annos.push(a);
            }
            2 => {
                let &(p, e) = edge_owner.get(target as usize).ok_or_else(oob)?;
                spg.positions[p].edges[e].annos.push(a);
            }
            3 => {
                let &(r, n) = node_index.get(target as usize).ok_or_else(oob)?;
                spg.records[r].nodes[n].annos.push(a);
            }
            4 => spg.records.get_mut(target as usize).ok_or_else(oob)?.annos.push(a),
            5 if target == 0 => spg.file_annos.push(a),
            6 => spg.engines.get_mut(target as usize).ok_or_else(oob)?.annos.push(a),
            9 => spg.sources.get_mut(target as usize).ok_or_else(oob)?.annos.push(a),
            _ => return Err(oob()),
        }
    }

    // Flags against contents (§13.2.10).
    for (p, &f) in spg.positions.iter().zip(&pos_flags) {
        if (f & 2 != 0) != !p.annos.is_empty() || (f & 4 != 0) != !p.analyses.is_empty() {
            return Err(bad(POSN, "annotation/analysis flags do not match"));
        }
    }
    for ((p, k), &f) in edge_owner.iter().zip(&edge_flags) {
        let e = &spg.positions[*p].edges[*k];
        if (f & 8 != 0) != !e.annos.is_empty() || (f & 32 != 0) != !e.analyses.is_empty() {
            return Err(bad(EDGE, "annotation/analysis flags do not match"));
        }
    }
    for (gi, &(r, n)) in node_owner.iter().enumerate() {
        let node = &spg.records[r].nodes[n];
        let f = rnod_flags[gi];
        if (f & 1 != 0) != !node.annos.is_empty() || (f & 2 != 0) != !node.analyses.is_empty() {
            return Err(bad(RNOD, "annotation/analysis flags do not match"));
        }
    }
    for (r, &f) in spg.records.iter().zip(&rec_flags) {
        if (f & 4 != 0) != !r.annos.is_empty() {
            return Err(bad(RECS, "annotation flag does not match"));
        }
    }

    // PROV.
    let mut prev = (0u8, 0u64, 0u32);
    let mut first_prov = true;
    for row in x.rows(PROV, 64) {
        let (kind, f, depth, engine, weight, v, target, source) = (row[0], r16(row, 2), r16(row, 4), r16(row, 6), r32(row, 8), ri32(row, 12), r64(row, 16), r32(row, 48));
        x.reserved_zero(PROV, row, 1..2)?;
        x.reserved_zero(PROV, row, 52..64)?;
        if x.strict && f & !(1 | 2 | 4 | 16) != 0 {
            return Err(bad(PROV, "reserved flag bits"));
        }
        let key = (kind, target, source);
        if !first_prov && key <= prev {
            return Err(bad(PROV, "entries out of order or duplicated"));
        }
        first_prov = false;
        prev = key;
        let mut p = Prov { source, disabled: f & 1 != 0, ..Default::default() };
        if f & 2 != 0 {
            p.eval = Some(EdgeEval { value: v, engine, depth: (depth != NONE16).then_some(depth) });
        } else if v != eval::NONE || engine != NONE16 || depth != NONE16 {
            return Err(bad(PROV, "evaluation fields without the flag"));
        }
        if f & 16 != 0 {
            p.weight = Some(weight);
        } else if weight != 0 {
            return Err(bad(PROV, "weight without the flag"));
        }
        let s = Stats { games: r64(row, 24), wins: r64(row, 32), draws: r64(row, 40) };
        if f & 4 != 0 {
            p.stats = Some(s);
        } else if s != Stats::default() {
            return Err(bad(PROV, "statistics without the flag"));
        }
        match kind {
            1 => {
                let local = target.checked_sub(first_global).filter(|&l| l < n_pos).ok_or_else(|| bad(PROV, "target out of range"))?;
                spg.positions[local as usize].prov.push(p);
            }
            2 => {
                let &(pi, e) = edge_owner.get(target as usize).ok_or_else(|| bad(PROV, "target out of range"))?;
                spg.positions[pi].edges[e].prov.push(p);
            }
            _ => return Err(bad(PROV, "reserved target kind")),
        }
    }

    // RAWS.
    if let Some((_, b, n)) = x.section(RAWS) {
        let dir_end = PRELUDE_LEN + n as usize * 48;
        for k in 0..n as usize {
            let row = &b[PRELUDE_LEN + k * 48..PRELUDE_LEN + (k + 1) * 48];
            x.reserved_zero(RAWS, row, 41..48)?;
            let (at, len, orig) = (r64(row, 0), r64(row, 8), r64(row, 16));
            let range = usize::try_from(at).ok().zip(usize::try_from(len).ok()).and_then(|(a, l)| Some(a..a.checked_add(l)?)).filter(|r| r.start >= dir_end && r.end <= b.len()).ok_or_else(|| bad(RAWS, "original out of range"))?;
            let compression = Compression::from_code(row[40]);
            if x.strict && matches!(compression, Compression::Reserved(_)) {
                return Err(bad(RAWS, "reserved compression method"));
            }
            if compression == Compression::None && orig != len {
                return Err(bad(RAWS, "uncompressed original with a different length"));
            }
            spg.raws.push(Raw {
                format: x.string(r64(row, 24), RAWS)?,
                filename: x.opt_string(r64(row, 32), RAWS)?,
                compression,
                stored: b[range].to_vec(),
                original_len: orig,
            });
        }
    }

    // OCCR (derived; compared after linking).
    let occr = x.section(OCCR).map(|(_, b, n)| (0..n as usize).map(|k| (r64(b, PRELUDE_LEN + k * 24), r64(b, PRELUDE_LEN + k * 24 + 8), r64(b, PRELUDE_LEN + k * 24 + 16))).collect());

    // Unknown sections without the required and derived flags are kept (§7.6).
    for (i, e) in c.entries.iter().enumerate() {
        if (known(&e.tag).is_none() || e.tag == KFLT) && e.flags & (DIR_REQUIRED | DIR_DERIVED) == 0 {
            spg.opaque.push(OpaqueSection { tag: e.tag, flags: e.flags, bytes: c.raw(i).to_vec() });
        }
    }
    // Conditional required sections (§7.4).
    let cond = [
        (spg.engines.is_empty() && (spg.positions.iter().any(|p| p.edges.iter().any(|e| e.eval.is_some())) || c.index(ANLS).is_some()), "ENGN"),
        (c.index(ANNO).is_some() && c.index(AKEY).is_none(), "AKEY"),
        (spg.records.iter().any(|r| !r.meta.is_empty()) && c.index(META).is_none(), "META"),
        (spg.records.iter().any(|r| r.raw.is_some()) && c.index(RAWS).is_none(), "RAWS"),
        (has_rights(&spg) && c.index(RGHT).is_none(), "RGHT"),
        (c.index(PROV).is_some() && c.index(SRCS).is_none(), "SRCS"),
    ];
    if let Some((_, t)) = cond.iter().find(|(missing, _)| *missing) {
        return Err(Error::rejected(format!("section {t} is required by the file's contents")));
    }
    let _ = tag_str;
    Ok(Part {
        info: ReadInfo {
            kind: Some(c.header.kind),
            minor: c.header.minor,
            build_id: c.header.build_id,
            used_tail_copy: c.used_tail_copy,
            blk3_root,
            edge_form_compact: compact,
            buckets,
        },
        first_global,
        spg,
        children,
        record_start_global,
        occr,
        keys: keys_col,
        kbkt,
    })
}

fn has_rights(spg: &Spg) -> bool {
    fn any(a: &[Anno]) -> bool {
        a.iter().any(|x| x.key == "rights" || !x.rights.is_empty())
    }
    any(&spg.file_annos)
        || spg.positions.iter().any(|p| any(&p.annos) || p.edges.iter().any(|e| any(&e.annos)))
        || spg.records.iter().any(|r| any(&r.annos) || r.nodes.iter().any(|n| any(&n.annos)))
}

/// Link the decoded files of a set: check the derived data and global indices (§13.2.2–6,
/// .9) and merge them into one model. `parts` are in shard order.
pub(crate) fn link(parts: Vec<Part>, total: u64, opts: &ReadOptions) -> Result<(Spg, Vec<ReadInfo>)> {
    // Positions in global order with their keys.
    let mut all: Vec<(Encoded, u64)> = Vec::new();
    for p in &parts {
        for (k, e) in p.spg.positions.iter().enumerate() {
            all.push((e.position.encode(), p.first_global + k as u64));
        }
    }
    if all.len() as u64 != total {
        return Err(Error::rejected("position count does not match the manifest"));
    }
    let mut global: HashMap<Encoded, u64> = HashMap::with_capacity(all.len());
    for (i, (enc, g)) in all.iter().enumerate() {
        if *g != i as u64 {
            return Err(Error::rejected("global indices are not contiguous"));
        }
        if i > 0 && all[i - 1].0.sort_key() >= enc.sort_key() {
            return Err(Error::corrupt_in(PKEY, "positions are not in key order or repeat"));
        }
        global.insert(enc.clone(), *g);
    }
    for p in &parts {
        // PKEY and KBKT (derived) against the positions.
        for (k, e) in p.spg.positions.iter().enumerate() {
            if p.keys.get(k) != Some(&e.position.key()) {
                return Err(Error::corrupt_in(PKEY, format!("key {k} does not match its position (derived data: can be rebuilt)")));
            }
        }
        if let Some((b, s)) = p.info.buckets {
            let n = 1usize << b;
            let mut counts = vec![0u64; n + 1];
            for key in &p.keys {
                counts[bucket(*key, b, s) as usize + 1] += 1;
            }
            for j in 1..=n {
                counts[j] += counts[j - 1];
            }
            if counts != p.kbkt {
                return Err(Error::corrupt_in(KBKT, "bucket table does not match PKEY (derived data: can be rebuilt)"));
            }
        }
        // Children (derived).
        for (k, e) in p.spg.positions.iter().enumerate() {
            let legal = if opts.legality { Some(e.position.legal_moves()) } else { None };
            for (j, edge) in e.edges.iter().enumerate() {
                if legal.as_ref().is_some_and(|l| !l.contains(&edge.mv)) {
                    return Err(Error::corrupt(format!("illegal edge move {} in {}", edge.mv.to_usi(), e.position.to_sfen())));
                }
                let want = global.get(&e.position.play_unchecked(edge.mv).encode()).copied().unwrap_or(NONE64);
                if p.children[k][j] != want {
                    return Err(Error::corrupt(format!("child index of edge {} in {} is wrong (derived data: can be rebuilt)", edge.mv.to_usi(), e.position.to_sfen())));
                }
            }
        }
        // Record start indices.
        for (r, &g) in p.spg.records.iter().zip(&p.record_start_global) {
            let want = global.get(&r.start.encode()).copied().unwrap_or(NONE64);
            if g != want {
                return Err(Error::corrupt_in(RECS, "start position index is wrong"));
            }
        }
        // OCCR (derived).
        if let Some(occ) = &p.occr {
            let mut want = Vec::new();
            for (ri, r) in p.spg.records.iter().enumerate() {
                let base: u64 = p.spg.records[..ri].iter().map(|r| r.nodes.len() as u64).sum();
                for (ni, pos) in validate::record_positions(r).iter().enumerate() {
                    if let Some(g) = pos.as_ref().and_then(|x| global.get(&x.encode())) {
                        want.push((*g, ri as u64, base + ni as u64));
                    }
                }
            }
            want.sort_unstable();
            if *occ != want {
                return Err(Error::corrupt_in(OCCR, "occurrence index does not match the records (derived data: can be rebuilt)"));
            }
        }
    }
    // Merge.
    let mut infos = Vec::new();
    let mut out = Spg::default();
    let mut first = true;
    for p in parts {
        infos.push(p.info.clone());
        let s = p.spg;
        if first {
            out.file_annos = s.file_annos;
            out.rights = s.rights;
            out.sources = s.sources;
            out.engines = s.engines;
            first = false;
        } else if out.rights != s.rights || own_rights(&out.file_annos) != own_rights(&s.file_annos) {
            return Err(Error::rejected("file-level rights differ between the files of the set (§8.3)"));
        } else if out.engines.len() != s.engines.len() || out.sources.len() != s.sources.len() {
            return Err(Error::rejected("engine or source tables differ between the files of the set"));
        }
        out.positions.extend(s.positions);
        if !s.records.is_empty() {
            // Records refer to raws by index within their own file.
            let base = out.raws.len() as u64;
            out.records.extend(s.records.into_iter().map(|mut r| {
                r.raw = r.raw.map(|x| x + base);
                r
            }));
        }
        out.raws.extend(s.raws);
        out.opaque.extend(s.opaque);
    }
    let checks = Checks { allow_unknown: true, legality: opts.legality };
    validate::validate(&out, &checks).map_err(|e| match e {
        Error::Invalid(m) => Error::corrupt(m),
        other => other,
    })?;
    Ok((out, infos))
}

fn own_rights(annos: &[Anno]) -> Vec<Value> {
    annos.iter().filter(|a| a.key == "rights").map(|a| a.value.clone()).collect()
}
