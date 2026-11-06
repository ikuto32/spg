//! Writing `.spg` files (§7, §11).

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::eval;
use crate::hash::{blake3_leaf, xxh3};
use crate::layout::*;
use crate::model::*;
use crate::moves::Move;
use crate::position::{Encoded, Position};
use crate::validate::{self, Checks};

/// How edges are stored (§7.17, §7.18).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EdgeForm {
    /// The compact form when it loses nothing, else the full form.
    #[default]
    Auto,
    Full,
    /// The compact form; information it cannot hold moves to ANLS where possible, and what
    /// is lost (weights, statistics) is recorded in `src.partial` (§7.18).
    Compact,
}

#[derive(Clone, Debug, Default)]
pub struct WriteOptions {
    pub edges: EdgeForm,
    /// Add a BLK3 section (§11.8).
    pub blk3: bool,
    /// Build ID; a fresh random value when `None` (§11.7).
    pub build_id: Option<u64>,
    pub checks: Checks,
    /// Write a single file (kind 0) even when there are no positions; otherwise a file with
    /// only records is written as a records-only file (kind 2).
    pub force_single: bool,
}

/// What a write did besides writing: losses of a forced compact form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    pub dropped_weights: usize,
    pub dropped_stats: usize,
    pub compact: bool,
}

/// A random 64-bit build ID (§11.7), from the OS-seeded hasher and the clock.
pub fn random_build_id() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        h.write_u128(d.as_nanos());
    }
    h.write_u32(std::process::id());
    h.finish()
}

/// Write `spg` as one `.spg` file.
pub fn write(spg: &Spg, opts: &WriteOptions) -> Result<(Vec<u8>, WriteReport)> {
    validate::validate(spg, &opts.checks)?;
    let (spg, report) = prepare_edges(spg, opts.edges);
    let order = validate::canonical_order(&spg);
    let global: HashMap<Encoded, u64> = order.iter().enumerate().map(|(g, (e, _))| (e.clone(), g as u64)).collect();
    let positions: Vec<(&PositionEntry, Encoded)> = order.iter().map(|(e, i)| (&spg.positions[*i], e.clone())).collect();
    let kind = if positions.is_empty() && !spg.records.is_empty() && !opts.force_single { FileKind::RecordsOnly } else { FileKind::Single };
    let spec = FileSpec {
        kind,
        shard: if kind == FileKind::RecordsOnly { NONE32 } else { 0 },
        s: 0,
        first_global: 0,
        build_id: opts.build_id.unwrap_or_else(random_build_id),
        compact: report.compact,
        blk3: opts.blk3,
        positions: &positions,
        global: &global,
        records: if kind == FileKind::RecordsOnly || kind == FileKind::Single { &spg.records } else { &[] },
        spg: &spg,
    };
    Ok((write_file(&spec)?, report))
}

/// Order the edges of every position (§7.17/§7.18) and, for the compact form, move what it
/// cannot hold into ANLS.
pub(crate) fn prepare_edges(spg: &Spg, form: EdgeForm) -> (Spg, WriteReport) {
    let mut spg = spg.clone();
    let edges = || spg.positions.iter().flat_map(|p| p.edges.iter());
    let mut engines: HashMap<u16, usize> = HashMap::new();
    for e in edges() {
        if let Some(ev) = &e.eval {
            *engines.entry(ev.engine).or_default() += 1;
        }
    }
    let lossless = edges().all(|e| e.weight.is_none() && e.stats.is_none() && e.eval.is_none_or(|v| v.depth.is_none())) && engines.len() <= 1;
    let compact = match form {
        EdgeForm::Auto => lossless,
        EdgeForm::Full => false,
        EdgeForm::Compact => true,
    };
    let mut report = WriteReport { compact, ..Default::default() };
    if compact && !lossless {
        let common = engines.iter().max_by_key(|(e, n)| (**n, std::cmp::Reverse(**e))).map(|(e, _)| *e);
        for p in &mut spg.positions {
            for e in &mut p.edges {
                if let Some(ev) = e.eval
                    && (Some(ev.engine) != common || ev.depth.is_some())
                {
                    let mut a = Analysis::new(Context::Book, ev.engine);
                    a.eval = Some(ev.value);
                    a.depth = ev.depth;
                    e.analyses.push(a);
                    if Some(ev.engine) != common {
                        e.eval = None;
                    } else {
                        e.eval = Some(EdgeEval { depth: None, ..ev });
                    }
                }
                if e.weight.take().is_some() {
                    report.dropped_weights += 1;
                }
                if e.stats.take().is_some() {
                    report.dropped_stats += 1;
                }
            }
        }
        if report.dropped_weights + report.dropped_stats > 0 {
            spg.note_partial(format!(
                "compact edges (EDGC): dropped {} selection weights and {} game statistics",
                report.dropped_weights, report.dropped_stats
            ));
        }
    }
    for p in &mut spg.positions {
        if compact {
            p.edges.sort_by(|a, b| {
                let ka = a.eval.map(|v| v.value);
                let kb = b.eval.map(|v| v.value);
                match (ka, kb) {
                    (Some(x), Some(y)) => y.cmp(&x),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
                .then(a.mv.0.cmp(&b.mv.0))
            });
        } else {
            p.edges.sort_by(|a, b| match (a.weight, b.weight) {
                (Some(x), Some(y)) => y.cmp(&x).then(a.mv.0.cmp(&b.mv.0)),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.mv.0.cmp(&b.mv.0),
            });
        }
        for e in &mut p.edges {
            e.prov.sort_by_key(|x| x.source);
        }
        p.prov.sort_by_key(|x| x.source);
    }
    (spg, report)
}

/// One file of a file set.
pub(crate) struct FileSpec<'a> {
    pub kind: FileKind,
    pub shard: u32,
    pub s: u8,
    pub first_global: u64,
    pub build_id: u64,
    pub compact: bool,
    pub blk3: bool,
    /// This file's positions in canonical order, with their encodings.
    pub positions: &'a [(&'a PositionEntry, Encoded)],
    /// Global index of every position of the file set.
    pub global: &'a HashMap<Encoded, u64>,
    pub records: &'a [Record],
    /// Dictionaries, file annotations, raws and opaque sections.
    pub spg: &'a Spg,
}

#[derive(Default)]
struct Strs {
    buf: Vec<u8>,
    map: HashMap<String, u64>,
    count: u64,
}

impl Strs {
    fn add(&mut self, s: &str) -> u64 {
        if let Some(&o) = self.map.get(s) {
            return o;
        }
        let off = (PRELUDE_LEN + self.buf.len()) as u64;
        self.buf.extend_from_slice(&(s.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(s.as_bytes());
        self.map.insert(s.to_owned(), off);
        self.count += 1;
        off
    }

    fn opt(&mut self, s: &Option<String>) -> u64 {
        s.as_deref().map_or(NONE64, |s| self.add(s))
    }
}

#[derive(Default)]
struct Pools {
    strs: Strs,
    keys: Vec<String>,
    key_index: HashMap<String, u32>,
    mvls: Vec<u16>,
}

impl Pools {
    fn key(&mut self, k: &str) -> u32 {
        if let Some(&i) = self.key_index.get(k) {
            return i;
        }
        let i = self.keys.len() as u32;
        self.keys.push(k.to_owned());
        self.key_index.insert(k.to_owned(), i);
        i
    }

    fn moves(&mut self, m: &[Move]) -> Result<u64> {
        let start = self.mvls.len() as u64;
        if start >= 1 << 48 {
            return Err(Error::Limit("MVLS larger than 2^48 moves".into()));
        }
        self.mvls.extend(m.iter().map(|m| m.0));
        Ok(start | ((m.len() as u64) << 48))
    }
}

/// An annotation row before final indices are known.
struct AnnoRow<'a> {
    kind: u8,
    target: Target,
    anno: &'a Anno,
}

#[derive(Clone, Copy)]
enum Target {
    Index(u64),
    /// An ANLS entry by (target kind, position within that kind's list).
    Analysis(u8, usize),
}

struct AnlsRow<'a> {
    kind: u8,
    target: u64,
    a: &'a Analysis,
}

fn anno_value(p: &mut Pools, v: &Value) -> Result<(u8, u64)> {
    Ok(match v {
        Value::Int(i) => (1, *i as u64),
        Value::Real(f) => (2, f.to_bits()),
        Value::Str(s) => (3, p.strs.add(s)),
        Value::Moves(m) => (4, p.moves(m)?),
        Value::Bool(b) => (5, u64::from(*b)),
        Value::Reserved { ty, raw } => (*ty, *raw),
    })
}

fn edge_bytes(
    out: &mut Vec<u8>,
    flags: u16,
    disabled: bool,
    weight: Option<u32>,
    ev: Option<EdgeEval>,
    stats: Option<Stats>,
) -> u16 {
    let mut f = flags;
    if disabled {
        f |= 1;
    }
    if ev.is_some() {
        f |= 2;
    }
    if stats.is_some() {
        f |= 4;
    }
    if weight.is_some() {
        f |= 16;
    }
    put16(out, f);
    put16(out, ev.and_then(|e| e.depth).unwrap_or(NONE16));
    put16(out, ev.map_or(NONE16, |e| e.engine));
    put32(out, weight.unwrap_or(0));
    out.extend_from_slice(&ev.map_or(eval::NONE, |e| e.value).to_le_bytes());
    f
}

fn stats_bytes(out: &mut Vec<u8>, s: Option<Stats>) {
    let s = s.unwrap_or_default();
    put64(out, s.games);
    put64(out, s.wins);
    put64(out, s.draws);
}

fn position_bytes(out: &mut Vec<u8>, enc: &Encoded, strs: &mut Strs) {
    match enc {
        Encoded::Cpe(c) => out.extend_from_slice(c),
        Encoded::Sfen(s) => {
            put64(out, strs.add(s));
            out.extend_from_slice(&[0; 24]);
        }
    }
}

struct Section {
    tag: Tag,
    flags: u32,
    bytes: Vec<u8>,
}

fn table(tag: Tag, record_len: u32, rows: Vec<u8>, flags: u32) -> Section {
    let count = if record_len == 0 { 0 } else { (rows.len() / record_len as usize) as u64 };
    let mut bytes = prelude(count, record_len, &[]);
    bytes.extend_from_slice(&rows);
    Section { tag, flags, bytes }
}

pub(crate) fn write_file(spec: &FileSpec) -> Result<Vec<u8>> {
    let spg = spec.spg;
    let mut pools = Pools::default();
    let mut annos: [Vec<AnnoRow>; 10] = Default::default();
    let mut anls: [Vec<AnlsRow>; 4] = Default::default();
    let mut sections: Vec<Section> = Vec::new();
    let global = |e: &Encoded| spec.global.get(e).copied();

    // ------------------------------------------------ positions and edges
    let mut posn = Vec::with_capacity(spec.positions.len() * 48);
    let mut pkey = Vec::with_capacity(spec.positions.len() * 8);
    let mut edge_rows = Vec::new();
    let mut prov_rows: Vec<(u8, u64, u32, Vec<u8>)> = Vec::new();
    let mut edge_index = 0u64;
    let mut edc_engine = NONE16;
    for (pi, (p, enc)) in spec.positions.iter().enumerate() {
        let g = spec.first_global + pi as u64;
        put64(&mut pkey, enc.key());
        position_bytes(&mut posn, enc, &mut pools.strs);
        put64(&mut posn, edge_index);
        put16(&mut posn, p.edges.len() as u16);
        let flags = u16::from(enc.is_extended()) | (u16::from(!p.annos.is_empty()) << 1) | (u16::from(!p.analyses.is_empty()) << 2);
        put16(&mut posn, flags);
        put32(&mut posn, 0);
        annos[1].extend(p.annos.iter().map(|a| AnnoRow { kind: 1, target: Target::Index(g), anno: a }));
        anls[1].extend(p.analyses.iter().map(|a| AnlsRow { kind: 1, target: g, a }));
        for pr in &p.prov {
            let mut row = Vec::with_capacity(64);
            row.extend_from_slice(&[1, 0]);
            edge_bytes(&mut row, 0, false, None, None, None);
            put64(&mut row, g);
            stats_bytes(&mut row, None);
            put32(&mut row, pr.source);
            row.extend_from_slice(&[0; 12]);
            prov_rows.push((1, g, pr.source, row));
        }
        for e in &p.edges {
            let child = global(&p.position.play_unchecked(e.mv).encode()).unwrap_or(NONE64);
            let extra = (u16::from(!e.annos.is_empty()) << 3) | (u16::from(!e.analyses.is_empty()) << 5);
            put16(&mut edge_rows, e.mv.0);
            if spec.compact {
                let mut f = extra;
                if e.disabled {
                    f |= 1;
                }
                if let Some(ev) = e.eval {
                    f |= 2;
                    edc_engine = ev.engine;
                }
                put16(&mut edge_rows, f);
                edge_rows.extend_from_slice(&e.eval.map_or(eval::NONE, |v| v.value).to_le_bytes());
                put64(&mut edge_rows, child);
            } else {
                edge_bytes(&mut edge_rows, extra, e.disabled, e.weight, e.eval, e.stats);
                put64(&mut edge_rows, child);
                stats_bytes(&mut edge_rows, e.stats);
            }
            annos[2].extend(e.annos.iter().map(|a| AnnoRow { kind: 2, target: Target::Index(edge_index), anno: a }));
            anls[2].extend(e.analyses.iter().map(|a| AnlsRow { kind: 2, target: edge_index, a }));
            for pr in &e.prov {
                let mut row = Vec::with_capacity(64);
                row.extend_from_slice(&[2, 0]);
                edge_bytes(&mut row, 0, pr.disabled, pr.weight, pr.eval, pr.stats);
                put64(&mut row, edge_index);
                stats_bytes(&mut row, pr.stats);
                put32(&mut row, pr.source);
                row.extend_from_slice(&[0; 12]);
                prov_rows.push((2, edge_index, pr.source, row));
            }
            edge_index += 1;
        }
    }

    // ------------------------------------------------ records
    let mut recs = Vec::new();
    let mut rnod = Vec::new();
    let mut meta = Vec::new();
    let mut occr: Vec<(u64, u64, u64)> = Vec::new();
    let mut node_base = 0u64;
    let mut meta_base = 0u64;
    for (ri, r) in spec.records.iter().enumerate() {
        let enc = r.start.encode();
        position_bytes(&mut recs, &enc, &mut pools.strs);
        put64(&mut recs, global(&enc).unwrap_or(NONE64));
        put64(&mut recs, node_base);
        put64(&mut recs, if r.meta.is_empty() { 0 } else { meta_base });
        put64(&mut recs, r.raw.unwrap_or(NONE64));
        put32(&mut recs, r.nodes.len() as u32);
        put32(&mut recs, r.meta.len() as u32);
        put32(&mut recs, r.start_ply);
        recs.push(r.result.code());
        recs.push(u8::from(enc.is_extended()) | (u8::from(r.nongame) << 1) | (u8::from(!r.annos.is_empty()) << 2));
        put16(&mut recs, 0);
        annos[4].extend(r.annos.iter().map(|a| AnnoRow { kind: 4, target: Target::Index(ri as u64), anno: a }));
        for (k, v) in &r.meta {
            let (k, v) = (pools.strs.add(k), pools.strs.add(v));
            put64(&mut meta, k);
            put64(&mut meta, v);
        }
        meta_base += r.meta.len() as u64;
        let positions = if spec.global.is_empty() { Vec::new() } else { validate::record_positions(r) };
        for (ni, n) in r.nodes.iter().enumerate() {
            let idx = node_base + ni as u64;
            put32(&mut rnod, if ni == 0 { 0 } else { (ni - n.parent as usize) as u32 });
            let (mv, kind, code) = match n.kind {
                NodeKind::Root => (0, 0, 0),
                NodeKind::Move(m) => (m.0, 1, 0),
                NodeKind::Event(c) => (0, 2, c),
            };
            put16(&mut rnod, mv);
            rnod.push(kind);
            rnod.push(code);
            put32(&mut rnod, n.time_ms.unwrap_or(NONE32));
            put16(&mut rnod, u16::from(!n.annos.is_empty()) | (u16::from(!n.analyses.is_empty()) << 1));
            put16(&mut rnod, 0);
            annos[3].extend(n.annos.iter().map(|a| AnnoRow { kind: 3, target: Target::Index(idx), anno: a }));
            anls[3].extend(n.analyses.iter().map(|a| AnlsRow { kind: 3, target: idx, a }));
            if let Some(Some(p)) = positions.get(ni)
                && let Some(g) = global(&p.encode()) {
                    occr.push((g, ri as u64, idx));
                }
        }
        node_base += r.nodes.len() as u64;
    }
    occr.sort_unstable();

    // ------------------------------------------------ dictionaries
    annos[5].extend(spg.file_annos.iter().map(|a| AnnoRow { kind: 5, target: Target::Index(0), anno: a }));
    let mut engn = Vec::new();
    for (i, e) in spg.engines.iter().enumerate() {
        put64(&mut engn, pools.strs.add(&e.name));
        put64(&mut engn, pools.strs.add(&e.version));
        engn.push(e.unit.code());
        engn.push(0);
        put16(&mut engn, e.pawn);
        put32(&mut engn, 0);
        annos[6].extend(e.annos.iter().map(|a| AnnoRow { kind: 6, target: Target::Index(i as u64), anno: a }));
    }
    let mut rght = Vec::new();
    for r in &spg.rights {
        rght.push(r.role.code());
        rght.extend_from_slice(&[0; 7]);
        put64(&mut rght, pools.strs.add(&r.name));
        put64(&mut rght, pools.strs.opt(&r.copyright));
        put64(&mut rght, pools.strs.add(&r.license));
        put64(&mut rght, pools.strs.opt(&r.license_text));
        put64(&mut rght, pools.strs.opt(&r.url));
        put64(&mut rght, pools.strs.opt(&r.date));
        put64(&mut rght, 0);
    }
    let mut srcs = Vec::new();
    for (i, s) in spg.sources.iter().enumerate() {
        put64(&mut srcs, pools.strs.add(&s.name));
        put64(&mut srcs, pools.strs.opt(&s.uri));
        put64(&mut srcs, 0);
        annos[9].extend(s.annos.iter().map(|a| AnnoRow { kind: 9, target: Target::Index(i as u64), anno: a }));
    }

    // ------------------------------------------------ analyses
    let anls_base = [0, 0, anls[1].len(), anls[1].len() + anls[2].len()];
    let mut anls_rows = Vec::new();
    for (k, rows) in anls.iter().enumerate().skip(1) {
        for (local, row) in rows.iter().enumerate() {
            let a = row.a;
            let mut flags = 0u8;
            for (bit, on) in [a.depth.is_some(), a.seldepth.is_some(), a.nodes.is_some(), a.time_ms.is_some(), a.pv.is_some(), a.winrate.is_some(), a.viewpoint_unknown].into_iter().enumerate() {
                if on {
                    flags |= 1 << bit;
                }
            }
            anls_rows.push(row.kind);
            anls_rows.push(a.context.code());
            put16(&mut anls_rows, a.rank);
            put16(&mut anls_rows, a.engine);
            anls_rows.push(a.bound.code());
            anls_rows.push(flags);
            put64(&mut anls_rows, row.target);
            anls_rows.extend_from_slice(&a.eval.unwrap_or(eval::NONE).to_le_bytes());
            put16(&mut anls_rows, a.depth.unwrap_or(0));
            put16(&mut anls_rows, a.seldepth.unwrap_or(0));
            put64(&mut anls_rows, a.nodes.unwrap_or(0));
            put32(&mut anls_rows, a.time_ms.unwrap_or(0));
            put16(&mut anls_rows, a.winrate.unwrap_or(0));
            put16(&mut anls_rows, 0);
            let pv = match &a.pv {
                Some(pv) => pools.moves(pv)?,
                None => 0,
            };
            put64(&mut anls_rows, pv);
            put64(&mut anls_rows, a.group);
            annos[8].extend(a.annos.iter().map(|x| AnnoRow { kind: 8, target: Target::Analysis(k as u8, local), anno: x }));
        }
    }

    // ------------------------------------------------ annotations (§7.19 order)
    let n7: usize = annos.iter().flatten().map(|r| r.anno.rights.len()).sum();
    let before7: usize = (1..=6).map(|k| annos[k].len()).sum();
    let mut anno_rows = Vec::new();
    let mut rights_rows: Vec<(u64, u64)> = Vec::new(); // (target anno index, rights index)
    let mut index = 0u64;
    for k in [1usize, 2, 3, 4, 5, 6, 8, 9] {
        if k == 8 {
            index = (before7 + n7) as u64;
        }
        for row in &annos[k] {
            let (ty, value) = anno_value(&mut pools, &row.anno.value)?;
            let target = match row.target {
                Target::Index(i) => i,
                Target::Analysis(kind, local) => (anls_base[kind as usize] + local) as u64,
            };
            anno_rows.push((row.kind, ty, pools.key(&row.anno.key), target, value));
            rights_rows.extend(row.anno.rights.iter().map(|&r| (index, r)));
            index += 1;
        }
    }
    let rights_key = if n7 > 0 { pools.key("rights") } else { 0 };
    let mut anno_bytes = Vec::with_capacity((anno_rows.len() + n7) * 24);
    let emit = |out: &mut Vec<u8>, (kind, ty, key, target, value): (u8, u8, u32, u64, u64)| {
        out.push(kind);
        out.push(ty);
        put16(out, 0);
        put32(out, key);
        put64(out, target);
        put64(out, value);
    };
    for (i, row) in anno_rows.iter().enumerate() {
        if i == before7 {
            for &(t, r) in &rights_rows {
                emit(&mut anno_bytes, (7, 1, rights_key, t, r));
            }
        }
        emit(&mut anno_bytes, *row);
    }
    if anno_rows.len() == before7 {
        for &(t, r) in &rights_rows {
            emit(&mut anno_bytes, (7, 1, rights_key, t, r));
        }
    }

    // ------------------------------------------------ raws
    let mut raws_section = None;
    if !spg.raws.is_empty() && spec.kind != FileKind::PositionShard {
        let n = spg.raws.len();
        let mut dir = Vec::new();
        let mut body = Vec::new();
        let mut at = (PRELUDE_LEN + n * 48) as u64;
        for r in &spg.raws {
            put64(&mut dir, at);
            put64(&mut dir, r.stored.len() as u64);
            put64(&mut dir, r.original_len);
            put64(&mut dir, pools.strs.add(&r.format));
            put64(&mut dir, pools.strs.opt(&r.filename));
            dir.push(r.compression.code());
            dir.extend_from_slice(&[0; 7]);
            body.extend_from_slice(&r.stored);
            at += r.stored.len() as u64;
        }
        let mut bytes = prelude(n as u64, 48, &[]);
        bytes.extend_from_slice(&dir);
        bytes.extend_from_slice(&body);
        raws_section = Some(Section { tag: RAWS, flags: 0, bytes });
    }

    // ------------------------------------------------ sections in the order of §7.7
    let has_positions_sections = spec.kind != FileKind::RecordsOnly;
    // Key names are the last strings to enter the pool.
    let mut akey = Vec::with_capacity(pools.keys.len() * 8);
    for k in std::mem::take(&mut pools.keys) {
        put64(&mut akey, pools.strs.add(&k));
    }
    if pools.strs.count > 0 {
        let mut bytes = prelude(pools.strs.count, 0, &[]);
        bytes.extend_from_slice(&pools.strs.buf);
        sections.push(Section { tag: STRS, flags: 0, bytes });
    }
    if !akey.is_empty() {
        sections.push(table(AKEY, 8, akey, 0));
    }
    if !spg.engines.is_empty() {
        sections.push(table(ENGN, 24, engn, 0));
    }
    if !spg.rights.is_empty() {
        sections.push(table(RGHT, 64, rght, 0));
    }
    if !spg.sources.is_empty() {
        sections.push(table(SRCS, 24, srcs, 0));
    }
    if has_positions_sections {
        let b = BUCKET_BITS;
        let n = 1usize << b;
        let mut counts = vec![0u64; n + 1];
        for (_, enc) in spec.positions {
            counts[bucket(enc.key(), b, spec.s) as usize + 1] += 1;
        }
        for j in 1..=n {
            counts[j] += counts[j - 1];
        }
        let mut bytes = prelude((n + 1) as u64, 8, &[b, spec.s]);
        for c in counts {
            put64(&mut bytes, c);
        }
        sections.push(Section { tag: KBKT, flags: DIR_REQUIRED | DIR_DERIVED, bytes });
        sections.push(table(PKEY, 8, pkey, DIR_REQUIRED | DIR_DERIVED));
        sections.push(table(POSN, 48, posn, DIR_REQUIRED));
        if spec.compact {
            let mut bytes = prelude(edge_index, 16, &edc_engine.to_le_bytes());
            bytes.extend_from_slice(&edge_rows);
            sections.push(Section { tag: EDGC, flags: DIR_REQUIRED, bytes });
        } else {
            sections.push(table(EDGE, 48, edge_rows, DIR_REQUIRED));
        }
    }
    if !anno_bytes.is_empty() {
        sections.push(table(ANNO, 24, anno_bytes, 0));
    }
    if !anls_rows.is_empty() {
        sections.push(table(ANLS, 56, anls_rows, 0));
    }
    if !pools.mvls.is_empty() {
        let mut rows = Vec::with_capacity(pools.mvls.len() * 2);
        for m in &pools.mvls {
            put16(&mut rows, *m);
        }
        sections.push(table(MVLS, 2, rows, 0));
    }
    if !prov_rows.is_empty() {
        prov_rows.sort_by_key(|r| (r.0, r.1, r.2));
        sections.push(table(PROV, 64, prov_rows.into_iter().flat_map(|r| r.3).collect(), 0));
    }
    let records_required = spec.kind == FileKind::RecordsOnly;
    if records_required || !spec.records.is_empty() {
        let f = if records_required { DIR_REQUIRED } else { 0 };
        sections.push(table(RECS, 80, recs, f));
        sections.push(table(RNOD, 16, rnod, f));
    }
    if !meta.is_empty() {
        sections.push(table(META, 16, meta, 0));
    }
    if !occr.is_empty() {
        let mut rows = Vec::with_capacity(occr.len() * 24);
        for (g, r, n) in occr {
            put64(&mut rows, g);
            put64(&mut rows, r);
            put64(&mut rows, n);
        }
        sections.push(table(OCCR, 24, rows, DIR_DERIVED));
    }
    if let Some(r) = raws_section {
        sections.push(r);
    }
    for o in &spg.opaque {
        sections.push(Section { tag: o.tag, flags: o.flags, bytes: o.bytes.clone() });
    }
    sections.push(csum_section(&sections));
    assemble(spec, sections)
}

/// CSUM (§11.2) over the sections longer than one block.
fn csum_section(sections: &[Section]) -> Section {
    let mut table_rows = Vec::new();
    let mut lower: Vec<u64> = Vec::new();
    let mut n = 0u64;
    for s in sections.iter().filter(|s| s.bytes.len() > BLOCK && s.tag != CSUM && s.tag != BLK3) {
        table_rows.extend_from_slice(&s.tag);
        put32(&mut table_rows, 0);
        put64(&mut table_rows, lower.len() as u64);
        put64(&mut table_rows, blocks(s.bytes.len()) as u64);
        lower.extend(s.bytes.chunks(BLOCK).map(xxh3));
        n += 1;
    }
    let lower_bytes: Vec<u8> = lower.iter().flat_map(|h| h.to_le_bytes()).collect();
    let upper: Vec<u8> = lower_bytes.chunks(BLOCK).flat_map(|c| xxh3(c).to_le_bytes()).collect();
    let mut bytes = prelude(n, 24, &[BLOCK_LOG2]);
    bytes.extend_from_slice(&table_rows);
    bytes.extend_from_slice(&lower_bytes);
    bytes.extend_from_slice(&upper);
    Section { tag: CSUM, flags: DIR_REQUIRED | DIR_DERIVED, bytes }
}

/// Directory hash of a section (§7.6).
pub(crate) fn directory_hash(tag: &Tag, bytes: &[u8]) -> u64 {
    if *tag == CSUM {
        // Lengths come from the file and may be damaged: clamp everything to the section.
        let max_targets = (bytes.len().saturating_sub(PRELUDE_LEN) / 24) as u64;
        let n = u64_at(bytes, 0).unwrap_or(0).min(max_targets) as usize;
        let table_end = PRELUDE_LEN + n * 24;
        let lower_len = (0..n).fold(0u64, |a, i| a.saturating_add(u64_at(bytes, PRELUDE_LEN + i * 24 + 16).unwrap_or(0)));
        let upper_at = lower_len.checked_mul(8).and_then(|l| usize::try_from(l).ok()).and_then(|l| table_end.checked_add(l)).unwrap_or(usize::MAX);
        let mut v = bytes[..table_end.min(bytes.len())].to_vec();
        v.extend_from_slice(bytes.get(upper_at..).unwrap_or(&[]));
        xxh3(&v)
    } else if *tag == BLK3 || bytes.len() > BLOCK {
        0
    } else {
        xxh3(bytes)
    }
}

fn header_bytes(spec: &FileSpec, sections: usize, dir_offset: u64, file_len: u64, dir_hash: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(&MAGIC);
    put16(&mut h, MAJOR);
    put16(&mut h, MINOR);
    put32(&mut h, spec.kind as u32);
    put32(&mut h, sections as u32);
    put32(&mut h, spec.shard);
    put64(&mut h, dir_offset);
    put64(&mut h, file_len);
    put64(&mut h, dir_hash);
    put64(&mut h, spec.first_global);
    put64(&mut h, spec.build_id);
    h
}

fn assemble(spec: &FileSpec, mut sections: Vec<Section>) -> Result<Vec<u8>> {
    if spec.blk3 {
        let leaves = 1 + sections.iter().map(|s| blocks(s.bytes.len())).sum::<usize>();
        sections.push(Section { tag: BLK3, flags: DIR_DERIVED, bytes: prelude(leaves as u64, 32, &[]) });
        if let Some(s) = sections.last_mut() {
            s.bytes.resize(PRELUDE_LEN + leaves * 32, 0);
        }
    }
    let mut offsets = Vec::with_capacity(sections.len());
    let mut at = HEADER_LEN;
    for s in &sections {
        at = align64(at);
        offsets.push(at);
        at += s.bytes.len();
    }
    let dir_offset = align64(at);
    let dir_len = sections.len() * DIR_ENTRY_LEN;
    let copy_offset = dir_offset + dir_len;
    let header_copy = align64(copy_offset + dir_len);
    let file_len = header_copy + HEADER_LEN;
    let mut dir = Vec::with_capacity(dir_len);
    for (s, &off) in sections.iter().zip(&offsets) {
        dir.extend_from_slice(&s.tag);
        put32(&mut dir, s.flags);
        put64(&mut dir, off as u64);
        put64(&mut dir, s.bytes.len() as u64);
        put64(&mut dir, directory_hash(&s.tag, &s.bytes));
    }
    let dir_hash = xxh3(&dir);
    let header = header_bytes(spec, sections.len(), dir_offset as u64, file_len as u64, dir_hash);
    if spec.blk3 {
        let mut leaves: Vec<[u8; 32]> = vec![blake3_leaf(&[&header, &dir])];
        for s in sections.iter().filter(|s| s.tag != BLK3) {
            leaves.extend(s.bytes.chunks(BLOCK).map(|b| blake3_leaf(&[b])));
        }
        if let Some(s) = sections.iter_mut().find(|s| s.tag == BLK3) {
            for (i, l) in leaves.iter().enumerate() {
                s.bytes[PRELUDE_LEN + i * 32..PRELUDE_LEN + (i + 1) * 32].copy_from_slice(l);
            }
        }
    }
    let mut out = vec![0u8; file_len];
    out[..HEADER_LEN].copy_from_slice(&header);
    for (s, &off) in sections.iter().zip(&offsets) {
        out[off..off + s.bytes.len()].copy_from_slice(&s.bytes);
    }
    out[dir_offset..dir_offset + dir_len].copy_from_slice(&dir);
    out[copy_offset..copy_offset + dir_len].copy_from_slice(&dir);
    let tail = header_bytes(spec, sections.len(), copy_offset as u64, file_len as u64, dir_hash);
    out[header_copy..].copy_from_slice(&tail);
    Ok(out)
}

/// Convenience: the canonical position order and a position's global index for `spg`.
pub fn global_index(spg: &Spg, p: &Position) -> Option<u64> {
    let e = p.encode();
    validate::canonical_order(spg).iter().position(|(x, _)| *x == e).map(|i| i as u64)
}
