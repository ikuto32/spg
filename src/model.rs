//! The logical data of an SPG file set (§5): the part that `.spg` and `.spgt` both carry
//! (§9.1). Annotations and analyses are kept with the item they describe, so the order
//! within one target is simply the order of the vectors.

use crate::eval::Unit;
use crate::moves::Move;
use crate::position::Position;

/// Annotation value (§7.19).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Int(i64),
    /// Finite IEEE 754 binary64.
    Real(f64),
    Str(String),
    Moves(Vec<Move>),
    Bool(bool),
    /// A value type reserved in v1.0 (6–255), kept verbatim for rewriting (§7.19).
    Reserved { ty: u8, raw: u64 },
}

/// An annotation (§7.19, §8.2). `rights` are the `rights` annotations that target this
/// annotation entry (target kind 7).
#[derive(Clone, Debug, PartialEq)]
pub struct Anno {
    pub key: String,
    pub value: Value,
    pub rights: Vec<u64>,
}

impl Anno {
    pub fn new(key: impl Into<String>, value: Value) -> Self {
        Anno { key: key.into(), value, rights: Vec::new() }
    }

    pub fn str(key: impl Into<String>, value: impl Into<String>) -> Self {
        Anno::new(key, Value::Str(value.into()))
    }

    pub fn int(key: impl Into<String>, value: i64) -> Self {
        Anno::new(key, Value::Int(value))
    }
}

/// Role of a rights entry (§7.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Author,
    Editor,
    Source,
    Unknown(u8),
}

impl Role {
    pub fn code(self) -> u8 {
        match self {
            Role::Author => 1,
            Role::Editor => 2,
            Role::Source => 3,
            Role::Unknown(c) => c,
        }
    }

    pub fn from_code(c: u8) -> Role {
        match c {
            1 => Role::Author,
            2 => Role::Editor,
            3 => Role::Source,
            c => Role::Unknown(c),
        }
    }

    pub fn name(self) -> Option<&'static str> {
        match self {
            Role::Author => Some("author"),
            Role::Editor => Some("editor"),
            Role::Source => Some("source"),
            Role::Unknown(_) => None,
        }
    }

    pub fn from_name(s: &str) -> Option<Role> {
        match s {
            "author" => Some(Role::Author),
            "editor" => Some(Role::Editor),
            "source" => Some(Role::Source),
            _ => None,
        }
    }
}

/// A rights entry (§7.13).
#[derive(Clone, Debug, PartialEq)]
pub struct Rights {
    pub role: Role,
    pub name: String,
    pub copyright: Option<String>,
    /// SPDX license expression; `NOASSERTION` when unknown.
    pub license: String,
    pub license_text: Option<String>,
    pub url: Option<String>,
    /// RFC 3339 full-date.
    pub date: Option<String>,
}

impl Rights {
    pub fn author(name: impl Into<String>) -> Self {
        Rights {
            role: Role::Author,
            name: name.into(),
            copyright: None,
            license: "NOASSERTION".into(),
            license_text: None,
            url: None,
            date: None,
        }
    }
}

/// A source of merged data (§7.14).
#[derive(Clone, Debug, PartialEq)]
pub struct Source {
    pub name: String,
    pub uri: Option<String>,
    pub annos: Vec<Anno>,
}

/// An engine (§7.12).
#[derive(Clone, Debug, PartialEq)]
pub struct Engine {
    /// Empty when unknown.
    pub name: String,
    /// Empty when unknown.
    pub version: String,
    pub unit: Unit,
    /// Value of one pawn for units 1 and 3; 0 when unknown.
    pub pawn: u16,
    pub annos: Vec<Anno>,
}

/// Evaluation of an edge (§7.17): value from the mover's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdgeEval {
    pub value: i32,
    pub engine: u16,
    /// 0–65534.
    pub depth: Option<u16>,
}

/// Game statistics of an edge (§7.17, §7.26): wins and draws of the side that moved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub games: u64,
    pub wins: u64,
    pub draws: u64,
}

/// A contribution of one source (§7.22). For positions every field is empty.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Prov {
    pub source: u32,
    pub disabled: bool,
    pub weight: Option<u32>,
    pub eval: Option<EdgeEval>,
    pub stats: Option<Stats>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// 0: thinking during a game.
    Game,
    /// 1: analysis.
    Analysis,
    /// 2: book generation.
    Book,
    Unknown(u8),
}

impl Context {
    pub fn code(self) -> u8 {
        match self {
            Context::Game => 0,
            Context::Analysis => 1,
            Context::Book => 2,
            Context::Unknown(c) => c,
        }
    }

    pub fn from_code(c: u8) -> Context {
        match c {
            0 => Context::Game,
            1 => Context::Analysis,
            2 => Context::Book,
            c => Context::Unknown(c),
        }
    }

    pub fn name(self) -> Option<&'static str> {
        match self {
            Context::Game => Some("game"),
            Context::Analysis => Some("analysis"),
            Context::Book => Some("book"),
            Context::Unknown(_) => None,
        }
    }

    pub fn from_name(s: &str) -> Option<Context> {
        match s {
            "game" => Some(Context::Game),
            "analysis" => Some(Context::Analysis),
            "book" => Some(Context::Book),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Exact,
    Lower,
    Upper,
    Unknown(u8),
}

impl Bound {
    pub fn code(self) -> u8 {
        match self {
            Bound::Exact => 0,
            Bound::Lower => 1,
            Bound::Upper => 2,
            Bound::Unknown(c) => c,
        }
    }

    pub fn from_code(c: u8) -> Bound {
        match c {
            0 => Bound::Exact,
            1 => Bound::Lower,
            2 => Bound::Upper,
            c => Bound::Unknown(c),
        }
    }

    pub fn name(self) -> Option<&'static str> {
        match self {
            Bound::Exact => Some("exact"),
            Bound::Lower => Some("lower"),
            Bound::Upper => Some("upper"),
            Bound::Unknown(_) => None,
        }
    }

    pub fn from_name(s: &str) -> Option<Bound> {
        match s {
            "exact" => Some(Bound::Exact),
            "lower" => Some(Bound::Lower),
            "upper" => Some(Bound::Upper),
            _ => None,
        }
    }
}

/// One search or analysis result (§7.20). The value is from the side to move in the
/// target position (for edges: the mover), unless `viewpoint_unknown`.
#[derive(Clone, Debug, PartialEq)]
pub struct Analysis {
    pub context: Context,
    /// MultiPV rank from 1; 0 = none.
    pub rank: u16,
    pub engine: u16,
    pub bound: Bound,
    pub eval: Option<i32>,
    pub depth: Option<u16>,
    pub seldepth: Option<u16>,
    pub nodes: Option<u64>,
    pub time_ms: Option<u32>,
    /// 0–10000.
    pub winrate: Option<u16>,
    /// From the target position (for edges: the position after the move).
    pub pv: Option<Vec<Move>>,
    /// Search identifier; 0 = a standalone result.
    pub group: u64,
    pub viewpoint_unknown: bool,
    pub annos: Vec<Anno>,
}

impl Analysis {
    pub fn new(context: Context, engine: u16) -> Self {
        Analysis {
            context,
            rank: 0,
            engine,
            bound: Bound::Exact,
            eval: None,
            depth: None,
            seldepth: None,
            nodes: None,
            time_ms: None,
            winrate: None,
            pv: None,
            group: 0,
            viewpoint_unknown: false,
            annos: Vec::new(),
        }
    }
}

/// A move edge (§7.17).
#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    pub mv: Move,
    /// Negative book entry: do not choose this move.
    pub disabled: bool,
    pub weight: Option<u32>,
    pub eval: Option<EdgeEval>,
    pub stats: Option<Stats>,
    pub annos: Vec<Anno>,
    pub analyses: Vec<Analysis>,
    pub prov: Vec<Prov>,
}

impl Edge {
    pub fn new(mv: Move) -> Self {
        Edge { mv, disabled: false, weight: None, eval: None, stats: None, annos: Vec::new(), analyses: Vec::new(), prov: Vec::new() }
    }
}

/// A position of the position graph (§7.16).
#[derive(Clone, Debug, PartialEq)]
pub struct PositionEntry {
    pub position: Position,
    pub annos: Vec<Anno>,
    pub analyses: Vec<Analysis>,
    pub prov: Vec<Prov>,
    pub edges: Vec<Edge>,
}

impl PositionEntry {
    pub fn new(position: Position) -> Self {
        PositionEntry { position, annos: Vec::new(), analyses: Vec::new(), prov: Vec::new(), edges: Vec::new() }
    }
}

/// End-of-game event codes (§8.5).
pub mod event {
    pub const RESIGN: u8 = 1;
    pub const INTERRUPT: u8 = 2;
    pub const SENNICHITE: u8 = 3;
    pub const JISHOGI: u8 = 4;
    pub const TIMEOUT: u8 = 5;
    pub const ILLEGAL_LOSS: u8 = 6;
    pub const ILLEGAL_WIN: u8 = 7;
    pub const DECLARE_WIN: u8 = 8;
    pub const MATE: u8 = 9;
    pub const NOMATE: u8 = 10;
    pub const DRAW: u8 = 11;
    pub const MAX_MOVES: u8 = 12;
    pub const MATTA: u8 = 13;
    /// 不戦勝: the side to move at the start position wins by default (§8.5).
    pub const DEFAULT_WIN: u8 = 14;
    /// 不戦敗: the side to move at the start position loses by default.
    pub const DEFAULT_LOSS: u8 = 15;
    pub const OTHER: u8 = 255;

    const NAMES: [(u8, &str); 16] = [
        (RESIGN, "resign"),
        (INTERRUPT, "interrupt"),
        (SENNICHITE, "sennichite"),
        (JISHOGI, "jishogi"),
        (TIMEOUT, "timeout"),
        (ILLEGAL_LOSS, "illegal_loss"),
        (ILLEGAL_WIN, "illegal_win"),
        (DECLARE_WIN, "declare_win"),
        (MATE, "mate"),
        (NOMATE, "nomate"),
        (DRAW, "draw"),
        (MAX_MOVES, "max_moves"),
        (MATTA, "matta"),
        (DEFAULT_WIN, "default_win"),
        (DEFAULT_LOSS, "default_loss"),
        (OTHER, "other"),
    ];

    pub fn name(code: u8) -> Option<&'static str> {
        NAMES.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
    }

    pub fn from_name(s: &str) -> Option<u8> {
        NAMES.iter().find(|(_, n)| *n == s).map(|(c, _)| *c)
    }

    pub fn is_defined(code: u8) -> bool {
        name(code).is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Root,
    Move(Move),
    /// An end-of-game event (§8.5).
    Event(u8),
}

/// A node of a record tree (§7.24). Nodes are in pre-order; `parent` is the index of the
/// parent within the same record (ignored for the root).
#[derive(Clone, Debug, PartialEq)]
pub struct RecordNode {
    pub parent: u32,
    pub kind: NodeKind,
    /// Time spent on the move, in milliseconds (0 – 4 294 967 294).
    pub time_ms: Option<u32>,
    pub annos: Vec<Anno>,
    pub analyses: Vec<Analysis>,
}

impl RecordNode {
    pub fn new(parent: u32, kind: NodeKind) -> Self {
        RecordNode { parent, kind, time_ms: None, annos: Vec::new(), analyses: Vec::new() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameResult {
    Unknown,
    BlackWin,
    WhiteWin,
    Draw,
    Reserved(u8),
}

impl GameResult {
    pub fn code(self) -> u8 {
        match self {
            GameResult::Unknown => 0,
            GameResult::BlackWin => 1,
            GameResult::WhiteWin => 2,
            GameResult::Draw => 3,
            GameResult::Reserved(c) => c,
        }
    }

    pub fn from_code(c: u8) -> GameResult {
        match c {
            0 => GameResult::Unknown,
            1 => GameResult::BlackWin,
            2 => GameResult::WhiteWin,
            3 => GameResult::Draw,
            c => GameResult::Reserved(c),
        }
    }

    pub fn name(self) -> Option<&'static str> {
        match self {
            GameResult::Unknown => Some("unknown"),
            GameResult::BlackWin => Some("black"),
            GameResult::WhiteWin => Some("white"),
            GameResult::Draw => Some("draw"),
            GameResult::Reserved(_) => None,
        }
    }

    pub fn from_name(s: &str) -> Option<GameResult> {
        match s {
            "unknown" => Some(GameResult::Unknown),
            "black" => Some(GameResult::BlackWin),
            "white" => Some(GameResult::WhiteWin),
            "draw" => Some(GameResult::Draw),
            _ => None,
        }
    }
}

/// A game record (§7.23).
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub start: Position,
    /// Move number of the start position (SFEN field 4); 0 when unknown.
    pub start_ply: u32,
    pub result: GameResult,
    /// Not the record of a game (a study, a problem, a book line…).
    pub nongame: bool,
    /// Header items in their original order.
    pub meta: Vec<(String, String)>,
    pub annos: Vec<Anno>,
    pub nodes: Vec<RecordNode>,
    /// Index into [`Spg::raws`].
    pub raw: Option<u64>,
}

impl Record {
    pub fn new(start: Position) -> Self {
        Record {
            start,
            start_ply: 0,
            result: GameResult::Unknown,
            nongame: false,
            meta: Vec::new(),
            annos: Vec::new(),
            nodes: vec![RecordNode::new(0, NodeKind::Root)],
            raw: None,
        }
    }

    /// Children of each node, in order.
    pub fn children(&self) -> Vec<Vec<usize>> {
        let mut ch = vec![Vec::new(); self.nodes.len()];
        for (i, n) in self.nodes.iter().enumerate().skip(1) {
            if let Some(c) = ch.get_mut(n.parent as usize) {
                c.push(i);
            }
        }
        ch
    }

    /// Add a node under `parent` keeping pre-order: it goes after the parent's subtree.
    pub fn push_child(&mut self, parent: usize, node: RecordNode) -> usize {
        let end = self.subtree_end(parent);
        let mut node = node;
        node.parent = parent as u32;
        self.nodes.insert(end, node);
        for n in self.nodes.iter_mut().skip(end + 1) {
            if n.parent as usize >= end {
                n.parent += 1;
            }
        }
        end
    }

    /// One past the last node of `node`'s subtree.
    pub fn subtree_end(&self, node: usize) -> usize {
        let mut end = node + 1;
        while end < self.nodes.len() && self.is_descendant(end, node) {
            end += 1;
        }
        end
    }

    fn is_descendant(&self, mut n: usize, ancestor: usize) -> bool {
        while n > ancestor {
            n = self.nodes[n].parent as usize;
        }
        n == ancestor
    }
}

/// An original file kept for byte-exact recovery (§7.27, lossless level L3).
#[derive(Clone, Debug, PartialEq)]
pub struct Raw {
    pub format: String,
    pub filename: Option<String>,
    pub compression: Compression,
    /// Stored bytes (compressed when `compression` says so).
    pub stored: Vec<u8>,
    pub original_len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Zstd,
    Reserved(u8),
}

impl Compression {
    pub fn code(self) -> u8 {
        match self {
            Compression::None => 0,
            Compression::Zstd => 1,
            Compression::Reserved(c) => c,
        }
    }

    pub fn from_code(c: u8) -> Compression {
        match c {
            0 => Compression::None,
            1 => Compression::Zstd,
            c => Compression::Reserved(c),
        }
    }
}

impl Raw {
    /// The original bytes.
    pub fn original(&self) -> crate::Result<Vec<u8>> {
        let out = match self.compression {
            Compression::None => self.stored.clone(),
            Compression::Zstd => {
                use std::io::Read;
                let mut d = ruzstd::decoding::StreamingDecoder::new(self.stored.as_slice()).map_err(|e| crate::Error::corrupt(format!("zstd: {e}")))?;
                let mut out = Vec::new();
                let limit = self.original_len.saturating_add(1);
                (&mut d).take(limit).read_to_end(&mut out).map_err(|e| crate::Error::corrupt(format!("zstd: {e}")))?;
                out
            }
            Compression::Reserved(c) => return Err(crate::Error::Unsupported(format!("compression method {c}"))),
        };
        if out.len() as u64 != self.original_len {
            return Err(crate::Error::corrupt("original length does not match the RAWS entry"));
        }
        Ok(out)
    }
}

/// A section this implementation does not know, kept for rewriting (§7.6). Only sections
/// that are neither required nor derived are kept.
#[derive(Clone, Debug, PartialEq)]
pub struct OpaqueSection {
    pub tag: [u8; 4],
    pub flags: u32,
    /// The whole section, prelude included.
    pub bytes: Vec<u8>,
}

/// A whole SPG data set.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Spg {
    pub file_annos: Vec<Anno>,
    pub rights: Vec<Rights>,
    pub sources: Vec<Source>,
    pub engines: Vec<Engine>,
    /// Positions; writers put them into the order of §7.16.
    pub positions: Vec<PositionEntry>,
    pub records: Vec<Record>,
    pub raws: Vec<Raw>,
    pub opaque: Vec<OpaqueSection>,
}

impl Spg {
    /// Index of an engine, adding it when missing.
    pub fn engine_index(&mut self, name: &str, version: &str, unit: Unit, pawn: u16) -> u16 {
        if let Some(i) = self.engines.iter().position(|e| e.name == name && e.version == version && e.unit == unit && e.pawn == pawn) {
            return i as u16;
        }
        self.engines.push(Engine { name: name.into(), version: version.into(), unit, pawn, annos: Vec::new() });
        (self.engines.len() - 1) as u16
    }

    /// The "unknown engine" entry for data imported from `source` (§7.12).
    pub fn unknown_engine(&mut self, source: &str, unit: Unit, pawn: u16) -> u16 {
        if let Some(i) = self.engines.iter().position(|e| {
            e.name.is_empty() && e.unit == unit && e.pawn == pawn && e.annos.iter().any(|a| a.key == "src.engine" && a.value == Value::Str(source.into()))
        }) {
            return i as u16;
        }
        self.engines.push(Engine { name: String::new(), version: String::new(), unit, pawn, annos: vec![Anno::str("src.engine", source)] });
        (self.engines.len() - 1) as u16
    }

    pub fn rights_index(&mut self, r: Rights) -> u64 {
        if let Some(i) = self.rights.iter().position(|x| *x == r) {
            return i as u64;
        }
        self.rights.push(r);
        (self.rights.len() - 1) as u64
    }

    /// Add `src.partial` describing entries a partial import or a lossy conversion left out.
    pub fn note_partial(&mut self, text: impl Into<String>) {
        self.file_annos.push(Anno::str("src.partial", text));
    }
}
