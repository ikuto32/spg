//! The text form `.spgt` (§9): reading with the lexical rules of §9.2 and the grammar of
//! §9.4, and writing in the canonical form of §9.7.

use std::collections::HashSet;
use std::fmt::Write as _;

use crate::error::{Error, Result};
use crate::eval::{self, Unit};
use crate::model::*;
use crate::moves::Move;
use crate::position::{Position, STARTPOS};
use crate::validate::{self, Checks, SchemaType};

pub const HEADER: &str = "SPG-TEXT 1.0";
/// Longest accepted line, in bytes.
pub const MAX_LINE: usize = 64 << 20;

// ---------------------------------------------------------------- lexing (§9.2)

#[derive(Clone, Debug, PartialEq)]
enum Seg {
    Bare(String),
    Quoted(String),
    Moves(Vec<String>),
}

type Word = Vec<Seg>;

fn lex(line: &str, no: usize) -> Result<Vec<Word>> {
    let mut words: Vec<Word> = Vec::new();
    let mut cur: Word = Vec::new();
    let mut bare = String::new();
    let mut chars = line.chars().peekable();
    let flush_bare = |cur: &mut Word, bare: &mut String| {
        if !bare.is_empty() {
            cur.push(Seg::Bare(std::mem::take(bare)));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            ' ' => {
                flush_bare(&mut cur, &mut bare);
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            '"' => {
                flush_bare(&mut cur, &mut bare);
                let mut s = String::new();
                loop {
                    let Some(c) = chars.next() else { return Err(Error::syntax(no, "unterminated string")) };
                    match c {
                        '"' => break,
                        '\\' => {
                            let e = chars.next().ok_or_else(|| Error::syntax(no, "unterminated escape"))?;
                            match e {
                                '"' => s.push('"'),
                                '\\' => s.push('\\'),
                                '/' => s.push('/'),
                                'b' => s.push('\u{8}'),
                                'f' => s.push('\u{c}'),
                                'n' => s.push('\n'),
                                'r' => s.push('\r'),
                                't' => s.push('\t'),
                                'u' => {
                                    let hex = |chars: &mut std::iter::Peekable<std::str::Chars>| -> Result<u32> {
                                        let h: String = (0..4).filter_map(|_| chars.next()).collect();
                                        if h.len() != 4 {
                                            return Err(Error::syntax(no, "bad \\u escape"));
                                        }
                                        u32::from_str_radix(&h, 16).map_err(|_| Error::syntax(no, "bad \\u escape"))
                                    };
                                    let hi = hex(&mut chars)?;
                                    let cp = if (0xD800..0xDC00).contains(&hi) {
                                        if chars.next() != Some('\\') || chars.next() != Some('u') {
                                            return Err(Error::syntax(no, "unpaired surrogate"));
                                        }
                                        let lo = hex(&mut chars)?;
                                        if !(0xDC00..0xE000).contains(&lo) {
                                            return Err(Error::syntax(no, "unpaired surrogate"));
                                        }
                                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                    } else {
                                        hi
                                    };
                                    s.push(char::from_u32(cp).ok_or_else(|| Error::syntax(no, "unpaired surrogate"))?);
                                }
                                _ => return Err(Error::syntax(no, format!("escape \\{e} is not allowed"))),
                            }
                        }
                        c if (c as u32) < 0x20 => return Err(Error::syntax(no, "unescaped control character in a string")),
                        c => s.push(c),
                    }
                }
                cur.push(Seg::Quoted(s));
            }
            '[' => {
                flush_bare(&mut cur, &mut bare);
                let mut moves = Vec::new();
                let mut tok = String::new();
                loop {
                    let Some(c) = chars.next() else { return Err(Error::syntax(no, "unterminated move list")) };
                    match c {
                        ']' => break,
                        ' ' => {
                            if !tok.is_empty() {
                                moves.push(std::mem::take(&mut tok));
                            }
                        }
                        '"' | '[' => return Err(Error::syntax(no, "'\"' or '[' inside a move list")),
                        c => tok.push(c),
                    }
                }
                if !tok.is_empty() {
                    moves.push(tok);
                }
                cur.push(Seg::Moves(moves));
            }
            c if (c as u32) < 0x20 || c == '\u{7f}' => return Err(Error::syntax(no, "control character outside a string")),
            c => bare.push(c),
        }
    }
    flush_bare(&mut cur, &mut bare);
    if !cur.is_empty() {
        words.push(cur);
    }
    Ok(words)
}

#[derive(Clone, Debug, PartialEq)]
enum Raw {
    Bare(String),
    Quoted(String),
    Moves(Vec<String>),
}

/// Split `key=value` at the first `=` of the normal state.
fn split_attr(word: &Word, no: usize, meta: bool) -> Result<(String, Raw)> {
    let err = |m: &str| Error::syntax(no, m.to_owned());
    let mut key_segs: Vec<Seg> = Vec::new();
    let mut rest: Vec<Seg> = Vec::new();
    let mut found = false;
    for s in word {
        if found {
            rest.push(s.clone());
            continue;
        }
        match s {
            Seg::Bare(b) if b.contains('=') => {
                let (k, v) = b.split_once('=').unwrap_or((b, ""));
                if !k.is_empty() {
                    key_segs.push(Seg::Bare(k.to_owned()));
                }
                if !v.is_empty() {
                    rest.push(Seg::Bare(v.to_owned()));
                }
                found = true;
            }
            other => key_segs.push(other.clone()),
        }
    }
    if !found {
        return Err(err("expected key=value"));
    }
    let key = match key_segs.as_slice() {
        [Seg::Bare(k)] if !meta && validate::valid_key(k) => k.clone(),
        [Seg::Bare(k)] if meta && !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-') => k.clone(),
        [Seg::Quoted(k)] if meta => k.clone(),
        _ => return Err(err("bad attribute key")),
    };
    let value = match rest.as_slice() {
        [Seg::Bare(v)] => Raw::Bare(v.clone()),
        [Seg::Quoted(v)] => Raw::Quoted(v.clone()),
        [Seg::Moves(m)] => Raw::Moves(m.clone()),
        _ => return Err(err(&format!("bad value for {key}"))),
    };
    Ok((key, value))
}

// ---------------------------------------------------------------- values (§9.3)

fn is_real(s: &str) -> bool {
    let b = s.strip_prefix('-').unwrap_or(s);
    let (mant, exp) = match b.find(['e', 'E']) {
        Some(i) => (&b[..i], Some(&b[i + 1..])),
        None => (b, None),
    };
    let (int, frac) = match mant.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (mant, None),
    };
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit());
    if !digits(int) || frac.is_some_and(|f| !digits(f)) || (frac.is_none() && exp.is_none()) {
        return false;
    }
    match exp {
        None => true,
        Some(e) => digits(e.strip_prefix(['+', '-']).unwrap_or(e)),
    }
}

fn parse_moves(m: &[String], no: usize) -> Result<Vec<Move>> {
    if m.len() > validate::MAX_MOVE_LIST {
        return Err(Error::syntax(no, "move list longer than 65535"));
    }
    m.iter().map(|s| Move::from_usi(s).map_err(|_| Error::syntax(no, format!("bad move {s:?}")))).collect()
}

/// An annotation value: typed by the key's schema, else by its notation.
fn anno_value(key: &str, raw: &Raw, no: usize) -> Result<Value> {
    let err = |m: String| Error::syntax(no, m);
    match (validate::schema_type(key), raw) {
        (Some(SchemaType::Str), Raw::Bare(s) | Raw::Quoted(s)) => Ok(Value::Str(s.clone())),
        (Some(SchemaType::Int), Raw::Bare(s)) => eval::parse_int(s).map(Value::Int).ok_or_else(|| err(format!("{key} needs an integer"))),
        (Some(_), _) => Err(err(format!("bad value type for {key}"))),
        (None, Raw::Quoted(s)) => Ok(Value::Str(s.clone())),
        (None, Raw::Moves(m)) => Ok(Value::Moves(parse_moves(m, no)?)),
        (None, Raw::Bare(s)) => {
            if s == "true" || s == "false" {
                Ok(Value::Bool(s == "true"))
            } else if let Some(i) = eval::parse_int(s) {
                Ok(Value::Int(i))
            } else if is_real(s) {
                let f: f64 = s.parse().map_err(|_| err(format!("bad number {s:?}")))?;
                if !f.is_finite() {
                    return Err(err("non-finite real".into()));
                }
                Ok(Value::Real(f))
            } else {
                Err(err(format!("{key}: strings of keys without a schema type must be quoted")))
            }
        }
    }
}

fn str_of(raw: &Raw, key: &str, no: usize) -> Result<String> {
    match raw {
        Raw::Bare(s) | Raw::Quoted(s) => Ok(s.clone()),
        Raw::Moves(_) => Err(Error::syntax(no, format!("{key} needs a string"))),
    }
}

fn uint<T: TryFrom<u64>>(raw: &Raw, key: &str, no: usize) -> Result<T> {
    match raw {
        Raw::Bare(s) => eval::parse_uint(s).and_then(|v| T::try_from(v).ok()).ok_or_else(|| Error::syntax(no, format!("{key}: value out of range"))),
        _ => Err(Error::syntax(no, format!("{key} needs a number"))),
    }
}

fn boolean(raw: &Raw, key: &str, no: usize) -> Result<bool> {
    match raw {
        Raw::Bare(s) if s == "true" => Ok(true),
        Raw::Bare(s) if s == "false" => Ok(false),
        _ => Err(Error::syntax(no, format!("{key} needs true or false"))),
    }
}

fn eval_of(raw: &Raw, no: usize) -> Result<i32> {
    match raw {
        Raw::Bare(s) => eval::from_text(s).ok_or_else(|| Error::syntax(no, format!("bad evaluation {s:?}"))),
        _ => Err(Error::syntax(no, "bad evaluation")),
    }
}

// ---------------------------------------------------------------- parsing (§9.4)

struct Line {
    no: usize,
    words: Vec<Word>,
}

impl Line {
    fn head(&self) -> Option<&str> {
        match self.words.first()?.as_slice() {
            [Seg::Bare(s)] => Some(s.as_str()),
            _ => None,
        }
    }
}

/// Attributes of one line: schema fields (unique) and annotations (in order).
struct Attrs {
    no: usize,
    schema: Vec<(String, Raw)>,
    annos: Vec<Anno>,
}

impl Attrs {
    fn take(&mut self, key: &str) -> Option<Raw> {
        let i = self.schema.iter().position(|(k, _)| k == key)?;
        Some(self.schema.remove(i).1)
    }
}

fn attrs(line: &Line, from: usize, schema: &[&str], annos_allowed: bool) -> Result<Attrs> {
    let mut out = Attrs { no: line.no, schema: Vec::new(), annos: Vec::new() };
    for w in &line.words[from..] {
        let (k, v) = split_attr(w, line.no, false)?;
        if schema.contains(&k.as_str()) {
            if out.schema.iter().any(|(x, _)| *x == k) {
                return Err(Error::syntax(line.no, format!("attribute {k} given twice")));
            }
            out.schema.push((k, v));
        } else if annos_allowed {
            let value = anno_value(&k, &v, line.no)?;
            out.annos.push(Anno::new(k, value));
        } else {
            return Err(Error::syntax(line.no, format!("unknown attribute {k}")));
        }
    }
    Ok(out)
}

/// (disabled, weight, evaluation, statistics) of an `edge` or `prov` line.
type EdgeFields = (bool, Option<u32>, Option<EdgeEval>, Option<Stats>);

struct Parser {
    lines: Vec<Line>,
    at: usize,
    spg: Spg,
}

/// A node of a record while parsing (document order differs from pre-order).
struct TempNode {
    kind: NodeKind,
    time_ms: Option<u32>,
    annos: Vec<Anno>,
    analyses: Vec<Analysis>,
    children: Vec<usize>,
    ply: u32,
}

impl Parser {
    fn peek(&self) -> Option<&Line> {
        self.lines.get(self.at)
    }

    fn peek_head(&self) -> Option<&str> {
        self.peek().and_then(Line::head)
    }

    fn next(&mut self) -> Option<&Line> {
        let l = self.lines.get(self.at);
        self.at += 1;
        l
    }

    fn line_no(&self) -> usize {
        self.peek().map_or(self.lines.last().map_or(1, |l| l.no + 1), |l| l.no)
    }

    fn id(&self, line: &Line, expected: usize, what: &str) -> Result<()> {
        let (k, v) = split_attr(line.words.get(1).ok_or_else(|| Error::syntax(line.no, "missing id="))?, line.no, false)?;
        if k != "id" {
            return Err(Error::syntax(line.no, "the first attribute must be id="));
        }
        let id: usize = uint(&v, "id", line.no)?;
        if id != expected {
            return Err(Error::syntax(line.no, format!("{what} ids must count up from 0 (expected {expected})")));
        }
        Ok(())
    }

    /// `anno` lines after a target; the first attribute is the annotation, `rights=` after
    /// it are rights of that annotation (kind 7, allowed after every line, §9.4).
    /// `rights_allowed`: the target itself may carry `rights` (not an engine).
    fn annos(&mut self, out: &mut Vec<Anno>, rights_allowed: bool) -> Result<()> {
        while self.peek_head() == Some("anno") {
            let Some(line) = self.next() else { break };
            let no = line.no;
            let first = line.words.get(1).ok_or_else(|| Error::syntax(no, "anno needs key=value"))?;
            let (k, v) = split_attr(first, no, false)?;
            if k == "rights" && !rights_allowed {
                return Err(Error::syntax(no, "rights cannot be attached here"));
            }
            let mut a = Anno::new(k.clone(), anno_value(&k, &v, no)?);
            for w in &line.words[2..] {
                let (rk, rv) = split_attr(w, no, false)?;
                if rk != "rights" {
                    return Err(Error::syntax(no, "only rights= may follow the annotation"));
                }
                a.rights.push(uint(&rv, "rights", no)?);
            }
            out.push(a);
        }
        Ok(())
    }

    fn engine_ref(&self, raw: &Raw, no: usize) -> Result<u16> {
        let e: u16 = uint(raw, "engine", no)?;
        if usize::from(e) >= self.spg.engines.len() {
            return Err(Error::syntax(no, format!("engine {e} is not defined above")));
        }
        Ok(e)
    }

    fn rights_check(&self, annos: &[Anno], no: usize) -> Result<()> {
        for a in annos {
            let refs = a.rights.iter().copied().chain(if a.key == "rights" { if let Value::Int(i) = a.value { Some(i as u64) } else { None } } else { None });
            for r in refs {
                if r as usize >= self.spg.rights.len() {
                    return Err(Error::syntax(no, format!("rights {r} is not defined above")));
                }
            }
        }
        Ok(())
    }

    /// Edge-like fields shared by `edge` and `prov`.
    fn edge_fields(&self, a: &mut Attrs) -> Result<EdgeFields> {
        let no = a.no;
        let disabled = match a.take("disabled") {
            Some(v) => boolean(&v, "disabled", no)?,
            None => false,
        };
        let weight = a.take("weight").map(|v| uint::<u32>(&v, "weight", no)).transpose()?;
        let value = a.take("eval").map(|v| eval_of(&v, no)).transpose()?;
        let engine = a.take("engine").map(|v| self.engine_ref(&v, no)).transpose()?;
        let depth = a.take("depth").map(|v| uint::<u16>(&v, "depth", no)).transpose()?;
        let ev = match (value, engine) {
            (Some(value), Some(engine)) => {
                if depth == Some(u16::MAX) {
                    return Err(Error::syntax(no, "depth: value out of range"));
                }
                let unit = self.spg.engines[usize::from(engine)].unit;
                if !eval::is_valid(value, unit) {
                    return Err(Error::syntax(no, "eval: value out of range for the engine's unit"));
                }
                Some(EdgeEval { value, engine, depth })
            }
            (None, None) if depth.is_none() => None,
            _ => return Err(Error::syntax(no, "eval and engine go together (depth needs both)")),
        };
        let g = a.take("games").map(|v| uint::<u64>(&v, "games", no)).transpose()?;
        let w = a.take("win").map(|v| uint::<u64>(&v, "win", no)).transpose()?;
        let d = a.take("draw").map(|v| uint::<u64>(&v, "draw", no)).transpose()?;
        let stats = match (g, w, d) {
            (Some(games), Some(wins), Some(draws)) => {
                if wins.checked_add(draws).is_none_or(|n| n > games) {
                    return Err(Error::syntax(no, "win + draw exceed games"));
                }
                Some(Stats { games, wins, draws })
            }
            (None, None, None) => None,
            _ => return Err(Error::syntax(no, "games, win and draw go together")),
        };
        Ok((disabled, weight, ev, stats))
    }

    fn analysis(&mut self) -> Result<Analysis> {
        let Some(line) = self.next() else { return Err(Error::syntax(0, "missing anls")) };
        let no = line.no;
        const SCHEMA: [&str; 13] = ["engine", "ctx", "rank", "eval", "bound", "depth", "seldepth", "nodes", "ms", "winrate", "pv", "group", "viewpoint"];
        let line_words = Line { no, words: line.words.clone() };
        let mut a = attrs(&line_words, 1, &SCHEMA, true)?;
        let engine = self.engine_ref(&a.take("engine").ok_or_else(|| Error::syntax(no, "anls needs engine="))?, no)?;
        let ctx = match a.take("ctx") {
            Some(v) => Context::from_name(&str_of(&v, "ctx", no)?).ok_or_else(|| Error::syntax(no, "bad ctx"))?,
            None => Context::Game,
        };
        let mut an = Analysis::new(ctx, engine);
        if let Some(v) = a.take("rank") {
            an.rank = uint(&v, "rank", no)?;
            if an.rank == 0 {
                return Err(Error::syntax(no, "rank starts at 1 (omit it for none)"));
            }
        }
        if let Some(v) = a.take("viewpoint") {
            if str_of(&v, "viewpoint", no)? != "unknown" {
                return Err(Error::syntax(no, "viewpoint can only be unknown"));
            }
            an.viewpoint_unknown = true;
        }
        if let Some(v) = a.take("eval") {
            let v = eval_of(&v, no)?;
            if !eval::is_valid(v, self.spg.engines[usize::from(engine)].unit) {
                return Err(Error::syntax(no, "eval: value out of range for the engine's unit"));
            }
            an.eval = Some(v);
        }
        if let Some(v) = a.take("bound") {
            an.bound = Bound::from_name(&str_of(&v, "bound", no)?).ok_or_else(|| Error::syntax(no, "bad bound"))?;
        }
        an.depth = a.take("depth").map(|v| uint(&v, "depth", no)).transpose()?;
        an.seldepth = a.take("seldepth").map(|v| uint(&v, "seldepth", no)).transpose()?;
        an.nodes = a.take("nodes").map(|v| uint(&v, "nodes", no)).transpose()?;
        an.time_ms = a.take("ms").map(|v| uint(&v, "ms", no)).transpose()?;
        an.winrate = a.take("winrate").map(|v| uint::<u16>(&v, "winrate", no)).transpose()?;
        if an.winrate.is_some_and(|w| w > 10_000) {
            return Err(Error::syntax(no, "winrate: value out of range"));
        }
        if let Some(v) = a.take("pv") {
            let Raw::Moves(m) = v else { return Err(Error::syntax(no, "pv needs [moves]")) };
            an.pv = Some(parse_moves(&m, no)?);
        }
        if let Some(v) = a.take("group") {
            an.group = uint(&v, "group", no)?;
            if an.group == 0 {
                return Err(Error::syntax(no, "group 0 means none: omit it"));
            }
        }
        an.annos = a.annos;
        self.annos(&mut an.annos, true)?;
        self.rights_check(&an.annos, no)?;
        Ok(an)
    }

    fn analyses(&mut self, out: &mut Vec<Analysis>) -> Result<()> {
        while self.peek_head() == Some("anls") {
            out.push(self.analysis()?);
        }
        Ok(())
    }

    fn prov(&mut self, out: &mut Vec<Prov>, edge: bool) -> Result<()> {
        while self.peek_head() == Some("prov") {
            let Some(line) = self.next() else { break };
            let line = Line { no: line.no, words: line.words.clone() };
            let no = line.no;
            let first = line.words.get(1).map(|w| split_attr(w, no, false)).transpose()?;
            if first.as_ref().map(|(k, _)| k.as_str()) != Some("source") {
                return Err(Error::syntax(no, "prov starts with source="));
            }
            let mut a = attrs(&line, 1, &["source", "weight", "eval", "engine", "depth", "games", "win", "draw", "disabled"], false)?;
            let source: u32 = uint(&a.take("source").ok_or_else(|| Error::syntax(no, "missing source"))?, "source", no)?;
            if source as usize >= self.spg.sources.len() {
                return Err(Error::syntax(no, format!("source {source} is not defined above")));
            }
            let (disabled, weight, eval, stats) = self.edge_fields(&mut a)?;
            if !edge && (disabled || weight.is_some() || eval.is_some() || stats.is_some()) {
                return Err(Error::syntax(no, "prov of a position carries only source="));
            }
            out.push(Prov { source, disabled, weight, eval, stats });
        }
        Ok(())
    }

    fn position_of(&self, line: &Line, from: usize) -> Result<(Position, usize)> {
        let word = |i: usize| -> Option<&str> {
            match line.words.get(i)?.as_slice() {
                [Seg::Bare(s)] => Some(s.as_str()),
                _ => None,
            }
        };
        if word(from) == Some("startpos") {
            return Ok((Position::startpos(), from + 1));
        }
        let (Some(a), Some(b), Some(c)) = (word(from), word(from + 1), word(from + 2)) else {
            return Err(Error::syntax(line.no, "expected a canonical SFEN"));
        };
        let p = Position::from_sfen(&format!("{a} {b} {c}")).map_err(|e| Error::syntax(line.no, e.to_string()))?;
        Ok((p, from + 3))
    }

    fn time(&self, a: &mut Attrs) -> Result<Option<u32>> {
        let t = a.take("t").map(|v| uint::<u32>(&v, "t", a.no)).transpose()?;
        if t == Some(u32::MAX) {
            return Err(Error::syntax(a.no, "t: value out of range"));
        }
        Ok(t)
    }

    /// `seq` (§9.4) under `parent`.
    fn seq(&mut self, nodes: &mut Vec<TempNode>, parent: usize, nested: bool) -> Result<usize> {
        let mut prev: Option<usize> = None;
        let mut count = 0;
        while let Some(head) = self.peek_head().map(str::to_owned) {
            match head.as_str() {
                "var" => {
                    let no = self.line_no();
                    let Some(sibling) = prev else { return Err(Error::syntax(no, "var needs a preceding move or event")) };
                    if self.next().is_some_and(|l| l.words.len() != 1) {
                        return Err(Error::syntax(no, "var takes no attributes"));
                    }
                    let sib_parent = nodes.iter().position(|n| n.children.contains(&sibling)).unwrap_or(parent);
                    if self.seq(nodes, sib_parent, true)? == 0 {
                        return Err(Error::syntax(no, "a variation cannot be empty"));
                    }
                    let end_no = self.line_no();
                    match self.next() {
                        Some(l) if l.head() == Some("end") && l.words.len() == 1 => {}
                        _ => return Err(Error::syntax(end_no, "expected end")),
                    }
                }
                "end" => {
                    if !nested {
                        return Err(Error::syntax(self.line_no(), "end without var"));
                    }
                    break;
                }
                "event" => {
                    let at = prev.unwrap_or(parent);
                    if matches!(nodes[at].kind, NodeKind::Event(_)) {
                        return Err(Error::syntax(self.line_no(), "events have no children"));
                    }
                    let Some(line) = self.next() else { break };
                    let line = Line { no: line.no, words: line.words.clone() };
                    let name = match line.words.get(1).map(Vec::as_slice) {
                        Some([Seg::Bare(n)]) => n.clone(),
                        _ => return Err(Error::syntax(line.no, "event needs a name")),
                    };
                    let code = event::from_name(&name).ok_or_else(|| Error::syntax(line.no, format!("unknown event {name:?}")))?;
                    let mut a = attrs(&line, 2, &["t"], true)?;
                    let time_ms = self.time(&mut a)?;
                    let mut annos = a.annos;
                    self.annos(&mut annos, true)?;
                    self.rights_check(&annos, line.no)?;
                    let mut analyses = Vec::new();
                    self.analyses(&mut analyses)?;
                    let ply = nodes[at].ply + 1;
                    nodes.push(TempNode { kind: NodeKind::Event(code), time_ms, annos, analyses, children: Vec::new(), ply });
                    let id = nodes.len() - 1;
                    nodes[at].children.push(id);
                    prev = Some(id);
                    count += 1;
                }
                h if h.bytes().all(|b| b.is_ascii_digit()) => {
                    let at = prev.unwrap_or(parent);
                    let Some(line) = self.next() else { break };
                    let line = Line { no: line.no, words: line.words.clone() };
                    if matches!(nodes[at].kind, NodeKind::Event(_)) {
                        return Err(Error::syntax(line.no, "events have no children"));
                    }
                    let ply = eval::parse_uint(h).and_then(|p| u32::try_from(p).ok()).ok_or_else(|| Error::syntax(line.no, "bad ply"))?;
                    if ply != nodes[at].ply + 1 {
                        return Err(Error::syntax(line.no, format!("ply must be {}", nodes[at].ply + 1)));
                    }
                    let mv = match line.words.get(1).map(Vec::as_slice) {
                        Some([Seg::Bare(m)]) => Move::from_usi(m).map_err(|_| Error::syntax(line.no, format!("bad move {m:?}")))?,
                        _ => return Err(Error::syntax(line.no, "expected a move")),
                    };
                    let mut a = attrs(&line, 2, &["t"], true)?;
                    let time_ms = self.time(&mut a)?;
                    let mut annos = a.annos;
                    self.annos(&mut annos, true)?;
                    self.rights_check(&annos, line.no)?;
                    let mut analyses = Vec::new();
                    self.analyses(&mut analyses)?;
                    nodes.push(TempNode { kind: NodeKind::Move(mv), time_ms, annos, analyses, children: Vec::new(), ply });
                    let id = nodes.len() - 1;
                    nodes[at].children.push(id);
                    prev = Some(id);
                    count += 1;
                }
                _ => break,
            }
        }
        Ok(count)
    }

    fn record(&mut self) -> Result<()> {
        let Some(line) = self.next() else { return Ok(()) };
        let line = Line { no: line.no, words: line.words.clone() };
        let no = line.no;
        let mut a = attrs(&line, 1, &["result", "start_ply", "nongame"], true)?;
        let result = match a.take("result") {
            Some(v) => GameResult::from_name(&str_of(&v, "result", no)?).ok_or_else(|| Error::syntax(no, "bad result"))?,
            None => GameResult::Unknown,
        };
        let start_ply: u32 = a.take("start_ply").map(|v| uint(&v, "start_ply", no)).transpose()?.unwrap_or(0);
        let nongame = a.take("nongame").map(|v| boolean(&v, "nongame", no)).transpose()?.unwrap_or(false);
        let mut annos = a.annos;
        self.annos(&mut annos, true)?;
        self.rights_check(&annos, no)?;
        let mut meta = Vec::new();
        while self.peek_head() == Some("meta") {
            let Some(l) = self.next() else { break };
            if l.words.len() != 2 {
                return Err(Error::syntax(l.no, "meta takes one key=value"));
            }
            let (k, v) = split_attr(&l.words[1], l.no, true)?;
            meta.push((k, str_of(&v, "meta", l.no)?));
        }
        let root_no = self.line_no();
        let root = match self.next() {
            Some(l) if l.head() == Some("root") => Line { no: l.no, words: l.words.clone() },
            _ => return Err(Error::syntax(root_no, "expected root")),
        };
        let (start, at) = self.position_of(&root, 1)?;
        let mut ra = attrs(&root, at, &["t"], true)?;
        let time_ms = self.time(&mut ra)?;
        let mut root_annos = ra.annos;
        self.annos(&mut root_annos, true)?;
        self.rights_check(&root_annos, root.no)?;
        let mut root_anls = Vec::new();
        self.analyses(&mut root_anls)?;
        let mut nodes = vec![TempNode { kind: NodeKind::Root, time_ms, annos: root_annos, analyses: root_anls, children: Vec::new(), ply: 0 }];
        self.seq(&mut nodes, 0, false)?;
        // Pre-order: first child first (§7.24).
        let mut rec = Record::new(start);
        rec.start_ply = start_ply;
        rec.result = result;
        rec.nongame = nongame;
        rec.meta = meta;
        rec.annos = annos;
        rec.nodes.clear();
        let mut stack = vec![(0usize, 0u32)];
        let mut taken: Vec<Option<TempNode>> = nodes.into_iter().map(Some).collect();
        while let Some((t, parent)) = stack.pop() {
            let Some(n) = taken[t].take() else { continue };
            let me = rec.nodes.len() as u32;
            rec.nodes.push(RecordNode { parent: if me == 0 { 0 } else { parent }, kind: n.kind, time_ms: n.time_ms, annos: n.annos, analyses: n.analyses });
            for &c in n.children.iter().rev() {
                stack.push((c, me));
            }
        }
        self.spg.records.push(rec);
        Ok(())
    }
}

/// Parse `.spgt` text.
pub fn parse(text: &str) -> Result<Spg> {
    let mut lines = Vec::new();
    let mut first = true;
    for (i, raw) in text.split('\n').enumerate() {
        let no = i + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.len() > MAX_LINE {
            return Err(Error::Limit(format!("line {no} is longer than {MAX_LINE} bytes")));
        }
        if first {
            if line != HEADER {
                return Err(Error::syntax(no, format!("the first line must be {HEADER:?}")));
            }
            first = false;
            continue;
        }
        let trimmed = line.trim_start_matches(' ');
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let words = lex(line, no)?;
        if !words.is_empty() {
            lines.push(Line { no, words });
        }
    }
    if first {
        return Err(Error::syntax(1, "empty file"));
    }
    let mut p = Parser { lines, at: 0, spg: Spg::default() };
    while p.peek_head() == Some("rights") {
        let Some(line) = p.next() else { break };
        let line = Line { no: line.no, words: line.words.clone() };
        let no = line.no;
        p.id(&line, p.spg.rights.len(), "rights")?;
        let mut a = attrs(&line, 2, &["role", "name", "copyright", "license", "license_text", "url", "date"], false)?;
        let mut req = |k: &str| -> Result<String> { str_of(&a.take(k).ok_or_else(|| Error::syntax(no, format!("rights needs {k}=")))?, k, no) };
        let role = Role::from_name(&req("role")?).ok_or_else(|| Error::syntax(no, "bad role"))?;
        let name = req("name")?;
        let license = req("license")?;
        let mut opt = |k: &str| a.take(k).map(|v| str_of(&v, k, no)).transpose();
        let r = Rights { role, name, copyright: opt("copyright")?, license, license_text: opt("license_text")?, url: opt("url")?, date: opt("date")? };
        p.spg.rights.push(r);
    }
    if p.peek_head() == Some("file") {
        let Some(line) = p.next() else { return Err(Error::syntax(0, "file")) };
        let line = Line { no: line.no, words: line.words.clone() };
        let a = attrs(&line, 1, &[], true)?;
        let mut annos = a.annos;
        p.annos(&mut annos, true)?;
        p.rights_check(&annos, line.no)?;
        p.spg.file_annos = annos;
    }
    while p.peek_head() == Some("source") {
        let Some(line) = p.next() else { break };
        let line = Line { no: line.no, words: line.words.clone() };
        let no = line.no;
        p.id(&line, p.spg.sources.len(), "source")?;
        let mut a = attrs(&line, 2, &["name", "uri"], true)?;
        let name = str_of(&a.take("name").ok_or_else(|| Error::syntax(no, "source needs name="))?, "name", no)?;
        let uri = a.take("uri").map(|v| str_of(&v, "uri", no)).transpose()?;
        let mut annos = a.annos;
        p.annos(&mut annos, true)?;
        p.rights_check(&annos, no)?;
        p.spg.sources.push(Source { name, uri, annos });
    }
    while p.peek_head() == Some("engine") {
        let Some(line) = p.next() else { break };
        let line = Line { no: line.no, words: line.words.clone() };
        let no = line.no;
        p.id(&line, p.spg.engines.len(), "engine")?;
        let mut a = attrs(&line, 2, &["name", "version", "unit", "pawn"], true)?;
        let name = a.take("name").map(|v| str_of(&v, "name", no)).transpose()?.unwrap_or_default();
        let version = a.take("version").map(|v| str_of(&v, "version", no)).transpose()?.unwrap_or_default();
        let unit = Unit::from_name(&str_of(&a.take("unit").ok_or_else(|| Error::syntax(no, "engine needs unit="))?, "unit", no)?).ok_or_else(|| Error::syntax(no, "bad unit"))?;
        let pawn: u16 = a.take("pawn").map(|v| uint(&v, "pawn", no)).transpose()?.unwrap_or(0);
        let mut annos = a.annos;
        if annos.iter().any(|x| x.key == "rights") {
            return Err(Error::syntax(no, "rights cannot be attached to an engine"));
        }
        p.annos(&mut annos, false)?;
        p.rights_check(&annos, no)?;
        p.spg.engines.push(Engine { name, version, unit, pawn, annos });
    }
    while p.peek_head() == Some("pos") {
        let Some(line) = p.next() else { break };
        let line = Line { no: line.no, words: line.words.clone() };
        let (position, at) = p.position_of(&line, 1)?;
        let a = attrs(&line, at, &[], true)?;
        let mut e = PositionEntry::new(position);
        e.annos = a.annos;
        p.annos(&mut e.annos, true)?;
        p.rights_check(&e.annos, line.no)?;
        p.analyses(&mut e.analyses)?;
        p.prov(&mut e.prov, false)?;
        while p.peek_head() == Some("edge") {
            let Some(line) = p.next() else { break };
            let line = Line { no: line.no, words: line.words.clone() };
            let no = line.no;
            let mv = match line.words.get(1).map(Vec::as_slice) {
                Some([Seg::Bare(m)]) => Move::from_usi(m).map_err(|_| Error::syntax(no, format!("bad move {m:?}")))?,
                _ => return Err(Error::syntax(no, "edge needs a move")),
            };
            let mut a = attrs(&line, 2, &["weight", "eval", "engine", "depth", "games", "win", "draw", "disabled"], true)?;
            let (disabled, weight, eval, stats) = p.edge_fields(&mut a)?;
            let mut edge = Edge { mv, disabled, weight, eval, stats, annos: a.annos, analyses: Vec::new(), prov: Vec::new() };
            p.annos(&mut edge.annos, true)?;
            p.rights_check(&edge.annos, no)?;
            p.analyses(&mut edge.analyses)?;
            p.prov(&mut edge.prov, true)?;
            e.edges.push(edge);
        }
        p.spg.positions.push(e);
    }
    while p.peek_head() == Some("record") {
        p.record()?;
    }
    if p.peek().is_some() {
        return Err(Error::syntax(p.line_no(), "unexpected line"));
    }
    Ok(p.spg)
}

// ---------------------------------------------------------------- writing (§9.7)

fn bare_ok(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| matches!(c, ' ' | '"' | '=' | '[' | ']') || (c as u32) < 0x20 || c == '\u{7f}')
}

pub fn json_string(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn schema_str(s: &str) -> String {
    if bare_ok(s) { s.to_owned() } else { json_string(s) }
}

fn moves_text(m: &[Move]) -> String {
    format!("[{}]", m.iter().map(|m| m.to_usi()).collect::<Vec<_>>().join(" "))
}

fn real_text(f: f64) -> String {
    // Debug gives the shortest round-trip digits and always a '.' or an exponent.
    format!("{f:?}")
}

fn value_text(key: &str, v: &Value) -> Result<String> {
    Ok(match (validate::schema_type(key), v) {
        (Some(SchemaType::Str), Value::Str(s)) => schema_str(s),
        (_, Value::Str(s)) => json_string(s),
        (_, Value::Int(i)) => i.to_string(),
        (_, Value::Real(f)) => real_text(*f),
        (_, Value::Bool(b)) => b.to_string(),
        (_, Value::Moves(m)) => moves_text(m),
        (_, Value::Reserved { ty, .. }) => return Err(Error::Unsupported(format!("annotation value type {ty} is reserved in v1.0 and has no text form (§9.1)"))),
    })
}

struct Writer {
    out: String,
}

impl Writer {
    /// Write a line with schema attributes, then the annotations: as attributes until one
    /// needs an `anno` line (it has rights or its key collides with a schema attribute);
    /// from there on as `anno` lines, keeping the recorded order (§9.7 rule 2).
    fn line(&mut self, head: &str, schema: &[(&str, String)], schema_keys: &[&str], annos: &[Anno]) -> Result<()> {
        self.out.push_str(head);
        for (k, v) in schema {
            let _ = write!(self.out, " {k}={v}");
        }
        let split = annos.iter().position(|a| !a.rights.is_empty() || schema_keys.contains(&a.key.as_str())).unwrap_or(annos.len());
        for a in &annos[..split] {
            let _ = write!(self.out, " {}={}", a.key, value_text(&a.key, &a.value)?);
        }
        self.out.push('\n');
        for a in &annos[split..] {
            let _ = write!(self.out, "anno {}={}", a.key, value_text(&a.key, &a.value)?);
            for r in &a.rights {
                let _ = write!(self.out, " rights={r}");
            }
            self.out.push('\n');
        }
        Ok(())
    }

    fn edge_fields(f: &mut Vec<(&'static str, String)>, disabled: bool, weight: Option<u32>, ev: Option<EdgeEval>, stats: Option<Stats>) {
        if let Some(w) = weight {
            f.push(("weight", w.to_string()));
        }
        if let Some(e) = ev {
            f.push(("eval", eval::to_text(e.value)));
            f.push(("engine", e.engine.to_string()));
            if let Some(d) = e.depth {
                f.push(("depth", d.to_string()));
            }
        }
        if let Some(s) = stats {
            f.push(("games", s.games.to_string()));
            f.push(("win", s.wins.to_string()));
            f.push(("draw", s.draws.to_string()));
        }
        if disabled {
            f.push(("disabled", "true".into()));
        }
    }

    fn analysis(&mut self, a: &Analysis) -> Result<()> {
        const KEYS: [&str; 13] = ["engine", "ctx", "rank", "eval", "bound", "depth", "seldepth", "nodes", "ms", "winrate", "pv", "group", "viewpoint"];
        let mut f: Vec<(&str, String)> = vec![("engine", a.engine.to_string())];
        f.push(("ctx", a.context.name().ok_or_else(|| Error::Unsupported("reserved analysis context".into()))?.into()));
        if a.rank != 0 {
            f.push(("rank", a.rank.to_string()));
        }
        if let Some(v) = a.eval {
            f.push(("eval", eval::to_text(v)));
        }
        if a.bound != Bound::Exact {
            f.push(("bound", a.bound.name().ok_or_else(|| Error::Unsupported("reserved bound".into()))?.into()));
        }
        for (k, v) in [("depth", a.depth.map(u64::from)), ("seldepth", a.seldepth.map(u64::from)), ("nodes", a.nodes), ("ms", a.time_ms.map(u64::from)), ("winrate", a.winrate.map(u64::from))] {
            if let Some(v) = v {
                f.push((k, v.to_string()));
            }
        }
        if let Some(pv) = &a.pv {
            f.push(("pv", moves_text(pv)));
        }
        if a.group != 0 {
            f.push(("group", a.group.to_string()));
        }
        if a.viewpoint_unknown {
            f.push(("viewpoint", "unknown".into()));
        }
        self.line("anls", &f, &KEYS, &a.annos)
    }

    fn prov(&mut self, p: &Prov) -> Result<()> {
        let mut f: Vec<(&str, String)> = vec![("source", p.source.to_string())];
        Writer::edge_fields(&mut f, p.disabled, p.weight, p.eval, p.stats);
        self.line("prov", &f, &[], &[])
    }
}

/// Write `spg` as canonical `.spgt` text (§9.7).
pub fn write(spg: &Spg) -> Result<String> {
    if !spg.raws.is_empty() || !spg.opaque.is_empty() {
        // Outside the round trip (§9.1): dropped without being an error.
    }
    validate::validate(spg, &Checks { allow_unknown: true, legality: false })?;
    let mut w = Writer { out: String::new() };
    w.out.push_str(HEADER);
    w.out.push('\n');
    for (i, r) in spg.rights.iter().enumerate() {
        let mut f: Vec<(&str, String)> = vec![("id", i.to_string()), ("role", r.role.name().ok_or_else(|| Error::Unsupported("reserved role".into()))?.into()), ("name", schema_str(&r.name))];
        if let Some(c) = &r.copyright {
            f.push(("copyright", schema_str(c)));
        }
        f.push(("license", schema_str(&r.license)));
        for (k, v) in [("license_text", &r.license_text), ("url", &r.url), ("date", &r.date)] {
            if let Some(v) = v {
                f.push((k, schema_str(v)));
            }
        }
        w.line("rights", &f, &[], &[])?;
    }
    if !spg.file_annos.is_empty() {
        w.line("file", &[], &[], &spg.file_annos)?;
    }
    for (i, s) in spg.sources.iter().enumerate() {
        let mut f: Vec<(&str, String)> = vec![("id", i.to_string()), ("name", schema_str(&s.name))];
        if let Some(u) = &s.uri {
            f.push(("uri", schema_str(u)));
        }
        w.line("source", &f, &["id", "name", "uri"], &s.annos)?;
    }
    for (i, e) in spg.engines.iter().enumerate() {
        let mut f: Vec<(&str, String)> = vec![("id", i.to_string())];
        if !e.name.is_empty() {
            f.push(("name", schema_str(&e.name)));
        }
        if !e.version.is_empty() {
            f.push(("version", schema_str(&e.version)));
        }
        f.push(("unit", e.unit.name().ok_or_else(|| Error::Unsupported("reserved unit".into()))?.into()));
        if e.pawn != 0 {
            f.push(("pawn", e.pawn.to_string()));
        }
        w.line("engine", &f, &["id", "name", "version", "unit", "pawn"], &e.annos)?;
    }
    let (sorted, _) = crate::write::prepare_edges(spg, crate::write::EdgeForm::Full);
    for (_, i) in validate::canonical_order(&sorted) {
        let p = &sorted.positions[i];
        w.line(&format!("pos {}", p.position.to_sfen()), &[], &[], &p.annos)?;
        for a in &p.analyses {
            w.analysis(a)?;
        }
        for pr in &p.prov {
            w.prov(pr)?;
        }
        for e in &p.edges {
            let mut f = Vec::new();
            Writer::edge_fields(&mut f, e.disabled, e.weight, e.eval, e.stats);
            w.line(&format!("edge {}", e.mv.to_usi()), &f, &["weight", "eval", "engine", "depth", "games", "win", "draw", "disabled"], &e.annos)?;
            for a in &e.analyses {
                w.analysis(a)?;
            }
            for pr in &e.prov {
                w.prov(pr)?;
            }
        }
    }
    for r in &spg.records {
        let mut f: Vec<(&str, String)> = Vec::new();
        if r.result != GameResult::Unknown {
            f.push(("result", r.result.name().ok_or_else(|| Error::Unsupported("reserved result".into()))?.into()));
        }
        if r.start_ply != 0 {
            f.push(("start_ply", r.start_ply.to_string()));
        }
        if r.nongame {
            f.push(("nongame", "true".into()));
        }
        w.line("record", &f, &["result", "start_ply", "nongame"], &r.annos)?;
        for (k, v) in &r.meta {
            let key = if !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-') { k.clone() } else { json_string(k) };
            let _ = writeln!(w.out, "meta {key}={}", schema_str(v));
        }
        let start = r.start.to_sfen();
        let start = if start == STARTPOS { "startpos".to_owned() } else { start };
        let children = r.children();
        let node_line = |w: &mut Writer, n: &RecordNode, head: String| -> Result<()> {
            let mut f: Vec<(&str, String)> = Vec::new();
            if let Some(t) = n.time_ms {
                f.push(("t", t.to_string()));
            }
            w.line(&head, &f, &["t"], &n.annos)?;
            for a in &n.analyses {
                w.analysis(a)?;
            }
            Ok(())
        };
        node_line(&mut w, &r.nodes[0], format!("root {start}"))?;
        // seq: first child continues, other children become var blocks (§9.4).
        fn seq(w: &mut Writer, r: &Record, children: &[Vec<usize>], first: usize, siblings: &[usize], ply: u32, node_line: &dyn Fn(&mut Writer, &RecordNode, String) -> Result<()>) -> Result<()> {
            let (mut node, mut sibs, mut ply) = (first, siblings.to_vec(), ply);
            loop {
                let n = &r.nodes[node];
                let head = match n.kind {
                    NodeKind::Move(m) => format!("{ply} {}", m.to_usi()),
                    NodeKind::Event(c) => format!("event {}", event::name(c).ok_or_else(|| Error::Unsupported(format!("event code {c} is reserved")))?),
                    NodeKind::Root => return Err(Error::invalid("root inside a record")),
                };
                node_line(w, n, head)?;
                for &s in &sibs {
                    w.out.push_str("var\n");
                    seq(w, r, children, s, &[], ply, node_line)?;
                    w.out.push_str("end\n");
                }
                if matches!(n.kind, NodeKind::Event(_)) || children[node].is_empty() {
                    return Ok(());
                }
                sibs = children[node][1..].to_vec();
                node = children[node][0];
                ply += 1;
            }
        }
        if let Some((&first, rest)) = children[0].split_first() {
            seq(&mut w, r, &children, first, rest, 1, &node_line)?;
        }
    }
    Ok(w.out)
}

/// Names of the keys that a line's schema uses, for tests and tools.
pub fn schema_keys() -> HashSet<&'static str> {
    ["weight", "eval", "engine", "depth", "games", "win", "draw", "disabled", "t", "result", "start_ply", "nongame"].into_iter().collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// §9.6, accepted as is and written back identically.
    pub const EXAMPLE: &str = "SPG-TEXT 1.0
engine id=0 name=YaneuraOu version=9.00 unit=cp pawn=100
pos lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b -
edge 2g2f weight=60 eval=48 engine=0 depth=34 games=1200 win=560 draw=40
anls engine=0 ctx=book eval=48 depth=34 pv=[8c8d 7g7f]
edge 7g7f weight=40 eval=41 engine=0 depth=34 games=800 win=360 draw=30
edge 1g1f disabled=true
record result=white start_ply=1
meta \"先手\"=PlayerA
meta \"後手\"=PlayerB
root startpos
1 7g7f t=12000
2 3c3d t=6000 comment=\"角道を開ける\"
3 2g2f t=3000
anls engine=0 ctx=game rank=1 eval=52 depth=20 pv=[8c8d 2f2e]
anls engine=0 ctx=game rank=2 eval=40 depth=20 pv=[4a3b 2f2e]
var
3 6g6f t=4000
4 8c8d
end
4 8c8d t=5000
event resign
";

    #[test]
    fn example_round_trips() {
        let spg = parse(EXAMPLE).unwrap();
        assert_eq!(spg.records[0].nodes.len(), 8);
        let r = &spg.records[0];
        // Pre-order: 7g7f 3c3d 2g2f 8c8d resign 6g6f 8c8d
        let kinds: Vec<String> = r.nodes.iter().map(|n| match n.kind {
            NodeKind::Root => "root".into(),
            NodeKind::Move(m) => m.to_usi(),
            NodeKind::Event(c) => event::name(c).unwrap().into(),
        }).collect();
        assert_eq!(kinds, ["root", "7g7f", "3c3d", "2g2f", "8c8d", "resign", "6g6f", "8c8d"]);
        let out = write(&spg).unwrap();
        // Canonical form writes comment bare when it can.
        let expected = EXAMPLE.replace("comment=\"角道を開ける\"", "comment=角道を開ける");
        assert_eq!(out, expected);
        assert_eq!(parse(&out).unwrap(), spg);
    }

    #[test]
    fn lexical_errors() {
        for (bad, why) in [
            ("SPG-TEXT 1.0\nfile x.a.b=\"open", "unterminated"),
            ("SPG-TEXT 1.0\nfile x.a.b=[7g7f", "unterminated"),
            ("SPG-TEXT 1.0\nfile x.a.b=\"\\q\"", "escape"),
            ("SPG-TEXT 1.0\nfile x.a.b=nan", "quoted"),
            ("SPG-TEXT 1.0\nfile x.a.b=inf", "quoted"),
            ("SPG-TEXT 1.0\nfile x.a.b=bare", "quoted"),
            ("SPG-TEXT 1.1\n", "first line"),
            ("\u{feff}SPG-TEXT 1.0\n", "first line"),
        ] {
            let e = parse(bad).unwrap_err().to_string();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        let e = parse("SPG-TEXT 1.0\nengine id=0 unit=cp\npos lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b -\nedge 7g7f weight=10 weight=20\n").unwrap_err();
        assert!(e.to_string().contains("twice"));
        let ok = parse("SPG-TEXT 1.0\nfile x.a.b=\"a b = [ ] #\" x.a.c=1.5e3 x.a.d=-0.25 x.a.e=true x.a.f=[7g7f 3c3d] comment=one comment=two\n").unwrap();
        assert_eq!(ok.file_annos.len(), 7);
        assert_eq!(ok.file_annos[1].value, Value::Real(1500.0));
        assert_eq!(ok.file_annos[5].value, Value::Str("one".into()));
        assert_eq!(parse(&write(&ok).unwrap()).unwrap(), ok);
    }

    #[test]
    fn ids_and_rights() {
        assert!(parse("SPG-TEXT 1.0\nengine id=1 unit=cp\n").is_err());
        let t = "SPG-TEXT 1.0\nrights id=0 role=author name=Alice license=CC-BY-4.0 date=2026-11-06\nengine id=0 unit=cp\nanno x.a.b=1\npos lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b - comment=hi rights=0\nanno comment=\"by alice\" rights=0\nedge 7g7f eval=30 engine=0\nanls engine=0 ctx=book depth=12 x.a.note=\"n\"\nanno rights=0\n";
        let spg = parse(t).unwrap();
        assert_eq!(spg.positions[0].annos.len(), 3);
        assert_eq!(spg.positions[0].annos[2].rights, vec![0]);
        assert_eq!(spg.positions[0].edges[0].analyses[0].annos.len(), 2);
        let out = write(&spg).unwrap();
        assert_eq!(parse(&out).unwrap(), spg);
        assert!(parse("SPG-TEXT 1.0\nengine id=0 unit=cp rights=0\n").is_err());
    }

    /// The final v1.0 grammar: rights lines come before the file line, so file-level rights
    /// refer backwards; rights of engine annotations (kind 7) are written on anno lines.
    #[test]
    fn file_rights_and_engine_annotation_rights_round_trip() {
        let t = "SPG-TEXT 1.0\nrights id=0 role=author name=Alice license=MIT\nfile rights=0 comment=c\nengine id=0 unit=cp\nanno x.a.b=1 rights=0\n";
        let spg = parse(t).unwrap();
        assert_eq!(spg.file_annos[0].value, Value::Int(0));
        assert_eq!(spg.engines[0].annos[0].rights, vec![0]);
        assert_eq!(write(&spg).unwrap(), t);
        // The file line before the rights lines is out of order; references point backwards.
        assert!(parse("SPG-TEXT 1.0\nfile rights=0\nrights id=0 role=author name=Alice license=MIT\n").is_err());
        assert!(parse("SPG-TEXT 1.0\nfile x.a.b=1\nanno x.a.c=1 rights=0\n").is_err());
        // An engine itself takes no rights.
        assert!(parse("SPG-TEXT 1.0\nrights id=0 role=author name=Alice license=MIT\nengine id=0 unit=cp\nanno rights=0\n").is_err());
    }

    /// §9.2: blank lines, memo lines and leading spaces are accepted anywhere after line 1;
    /// §9.4: eval/engine/depth and games/win/draw go together.
    #[test]
    fn lexical_leniency_and_field_groups() {
        let t = "SPG-TEXT 1.0\n\n  # memo\nengine id=0 unit=cp\n   pos lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b -\n\n  edge 7g7f  eval=30 engine=0\n";
        let spg = parse(t).unwrap();
        assert_eq!(spg.positions[0].edges[0].eval.unwrap().value, 30);
        let base = "SPG-TEXT 1.0\nengine id=0 unit=cp\npos lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b -\n";
        for bad in ["edge 7g7f eval=30", "edge 7g7f engine=0", "edge 7g7f depth=3", "edge 7g7f games=3 win=1", "edge 7g7f depth=65535 eval=1 engine=0"] {
            assert!(parse(&format!("{base}{bad}\n")).is_err(), "{bad}");
        }
    }
}
