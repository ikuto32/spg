//! Conformance tests along appendix C of the specification.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use spg::eval::{self, Unit};
use spg::layout::*;
use spg::lookup::Book;
use spg::manifest::{self, SetOptions};
use spg::model::*;
use spg::validate::Checks;
use spg::{EdgeForm, Error, Move, Position, ReadOptions, WriteOptions};

fn mv(s: &str) -> Move {
    Move::from_usi(s).unwrap()
}

fn opts() -> WriteOptions {
    WriteOptions { build_id: Some(0x1234_5678_9abc_def0), ..Default::default() }
}

/// A data set touching every section.
fn sample() -> Spg {
    let mut s = Spg::default();
    let author = s.rights_index(Rights { date: Some("2026-11-06".into()), ..Rights::author("Alice") });
    s.file_annos.push(Anno::str("comment", "sample book"));
    let e0 = s.engine_index("YaneuraOu", "9.00", Unit::Cp, 100);
    let unknown = s.unknown_engine("yaneuraou-db2016", Unit::Cp, 100);
    let start = Position::startpos();
    let mut p = PositionEntry::new(start.clone());
    p.annos.push(Anno::str("comment", "初期局面"));
    let mut e = Edge::new(mv("2g2f"));
    e.weight = Some(60);
    e.eval = Some(EdgeEval { value: 48, engine: e0, depth: Some(34) });
    e.stats = Some(Stats { games: 1200, wins: 560, draws: 40 });
    let mut a = Analysis::new(Context::Book, e0);
    a.eval = Some(48);
    a.depth = Some(34);
    a.pv = Some(vec![mv("8c8d"), mv("7g7f")]);
    a.annos.push(Anno { key: "x.test.note".into(), value: Value::Real(0.5), rights: vec![author] });
    e.analyses.push(a);
    p.edges.push(e);
    let mut e2 = Edge::new(mv("7g7f"));
    e2.weight = Some(40);
    e2.eval = Some(EdgeEval { value: eval::mate(true, Some(7)), engine: unknown, depth: None });
    e2.annos.push(Anno::int("src.yane.count", 3));
    p.edges.push(e2);
    let mut e3 = Edge::new(mv("1g1f"));
    e3.disabled = true;
    p.edges.push(e3);
    s.positions.push(p);
    let after = start.play(mv("7g7f")).unwrap();
    let mut p2 = PositionEntry::new(after.clone());
    p2.edges.push(Edge::new(mv("3c3d")));
    p2.analyses.push(Analysis { winrate: Some(5100), nodes: Some(123_456), time_ms: Some(1500), seldepth: Some(30), group: 7, ..Analysis::new(Context::Analysis, e0) });
    s.positions.push(p2);
    // An extended position (19 pawns).
    let ext = Position::from_sfen("lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b P").unwrap();
    let mut p3 = PositionEntry::new(ext);
    p3.annos.push(Anno::new("x.test.flag", Value::Bool(true)));
    s.positions.push(p3);
    // A record with a variation, a matta-shaped branch and an event.
    let mut r = Record::new(start.clone());
    r.start_ply = 1;
    r.result = GameResult::WhiteWin;
    r.meta = vec![("先手".into(), "PlayerA".into()), ("後手".into(), "PlayerB".into())];
    r.annos.push(Anno::int("rights", author as i64));
    let n1 = r.push_child(0, RecordNode { time_ms: Some(12_000), ..RecordNode::new(0, NodeKind::Move(mv("7g7f"))) });
    let n2 = r.push_child(n1, RecordNode::new(0, NodeKind::Move(mv("3c3d"))));
    r.nodes[n2].annos.push(Anno::str("comment", "角道を開ける"));
    r.nodes[n2].annos.push(Anno::str("bookmark", "基本図"));
    let mut think = Analysis::new(Context::Game, e0);
    think.rank = 1;
    think.eval = Some(52);
    think.pv = Some(vec![mv("2g2f")]);
    r.nodes[n2].analyses.push(think);
    let n3 = r.push_child(n2, RecordNode::new(0, NodeKind::Move(mv("2g2f"))));
    let alt = r.push_child(n2, RecordNode::new(0, NodeKind::Move(mv("6g6f"))));
    r.push_child(alt, RecordNode::new(0, NodeKind::Event(event::MATTA)));
    let ev = r.push_child(n3, RecordNode::new(0, NodeKind::Event(event::OTHER)));
    r.nodes[ev].annos.push(Anno::str("event.raw", "封じ手"));
    s.records.push(r);
    s.raws.push(Raw { format: "kif".into(), filename: Some("game.kif".into()), compression: Compression::None, stored: b"raw bytes".to_vec(), original_len: 9 });
    s.records[0].raw = Some(0);
    s.sources.push(Source { name: "book A".into(), uri: None, annos: vec![] });
    s
}

fn round_trip(s: &Spg) -> (Vec<u8>, Spg) {
    let (bytes, _) = spg::write(s, &opts()).unwrap();
    let (back, _) = spg::read(&bytes, &ReadOptions::default()).unwrap();
    (bytes, back)
}

#[test]
fn binary_and_text_round_trips() {
    let s = sample();
    let (bytes, back) = round_trip(&s);
    let (again, _) = spg::write(&back, &opts()).unwrap();
    assert_eq!(bytes, again, "write(read(write(x))) == write(x)");
    let text = spg::text::write(&s).unwrap();
    assert_eq!(spg::text::write(&back).unwrap(), text, "same logical data");
    let parsed = spg::text::parse(&text).unwrap();
    assert_eq!(spg::text::write(&parsed).unwrap(), text, "canonical text is a fixed point");
    // .spgt → .spg → .spgt (raws are outside the text round trip).
    let mut no_raw = back.clone();
    no_raw.raws.clear();
    no_raw.records[0].raw = None;
    let (b2, _) = spg::write(&parsed, &opts()).unwrap();
    let (back2, _) = spg::read(&b2, &ReadOptions::default()).unwrap();
    assert_eq!(back2, no_raw);
    assert_eq!(back.raws[0].original().unwrap(), b"raw bytes");
}

#[test]
fn compact_edges() {
    let mut s = Spg::default();
    let e = s.engine_index("e", "", Unit::Cp, 100);
    let mut p = PositionEntry::new(Position::startpos());
    for (m, v) in [("7g7f", Some(30)), ("2g2f", Some(50)), ("5g5f", None)] {
        let mut x = Edge::new(mv(m));
        x.eval = v.map(|value| EdgeEval { value, engine: e, depth: None });
        p.edges.push(x);
    }
    s.positions.push(p);
    let (bytes, rep) = spg::write(&s, &opts()).unwrap();
    assert!(rep.compact);
    let c = spg::container::Container::open(&bytes).unwrap();
    assert!(c.index(EDGC).is_some() && c.index(EDGE).is_none());
    let (back, info) = spg::read(&bytes, &ReadOptions::default()).unwrap();
    assert!(info.edge_form_compact);
    let order: Vec<String> = back.positions[0].edges.iter().map(|e| e.mv.to_usi()).collect();
    assert_eq!(order, ["2g2f", "7g7f", "5g5f"], "EDGC order: value desc, then no value");
    // Forcing the compact form records what it drops.
    let mut lossy = sample();
    lossy.positions.retain(|p| !p.position.encode().is_extended());
    let (b, rep) = spg::write(&lossy, &WriteOptions { edges: EdgeForm::Compact, ..opts() }).unwrap();
    assert!(rep.dropped_weights >= 2 && rep.dropped_stats == 1);
    let (back, _) = spg::read(&b, &ReadOptions::default()).unwrap();
    assert!(back.file_annos.iter().any(|a| a.key == "src.partial"));
    let first = back.positions.iter().find(|p| p.position == Position::startpos()).unwrap();
    assert!(first.edges.iter().any(|e| e.analyses.iter().any(|a| a.depth == Some(34))), "depth moved to ANLS");
}

#[test]
fn records_only_file_is_small() {
    let mut s = sample();
    s.positions.clear();
    let (bytes, _) = spg::write(&s, &opts()).unwrap();
    let c = spg::container::Container::open(&bytes).unwrap();
    assert_eq!(c.header.kind, FileKind::RecordsOnly);
    assert!(bytes.len() < 8192, "{} bytes", bytes.len());
    assert!(c.index(KBKT).is_none());
    let (back, _) = spg::read(&bytes, &ReadOptions::default()).unwrap();
    assert_eq!(back.records, s.records);
}

#[test]
fn every_bit_flip_is_caught_or_harmless() {
    let mut s = sample();
    s.positions.truncate(2);
    let (bytes, _) = spg::write(&s, &opts()).unwrap();
    let (good, _) = spg::read(&bytes, &ReadOptions::default()).unwrap();
    // Sections are small, so the directory hashes cover everything; flipping any bit must
    // either be rejected or (in the duplicated header/directory) be repaired.
    let mut repaired = 0;
    let step = (bytes.len() / 3000).max(1);
    for i in (0..128).chain((0..bytes.len()).step_by(step)).chain(bytes.len() - 1200..bytes.len()) {
        {
            let bit = (i % 8) as u8;
            let mut b = bytes.clone();
            b[i] ^= 1 << bit;
            match spg::read(&b, &ReadOptions { legality: false, ..Default::default() }) {
                Err(_) => {}
                Ok((x, info)) => {
                    assert_eq!(x, good, "byte {i} bit {bit} changed the data silently");
                    assert!(info.used_tail_copy, "byte {i} bit {bit} was ignored");
                    repaired += 1;
                }
            }
        }
    }
    assert!(repaired > 0, "header damage is repaired from the tail copy");
}

/// §11.6 / appendix C "配置と末尾の複製": a valid head with a differing tail copy is reported
/// as corruption, by the full reader and by the engine-side lookup alike; §7.1 placement.
#[test]
fn tail_copy_mismatch_is_corruption() {
    let s = sample();
    let (bytes, _) = spg::write(&s, &opts()).unwrap();
    let c = spg::container::Container::open(&bytes).unwrap();
    let dir_end = c.header.dir_offset as usize + c.entries.len() * 32;
    let tail = bytes.len() - 64;
    assert_eq!(u64::from_le_bytes(bytes[tail + 24..tail + 32].try_into().unwrap()) as usize, dir_end, "the directory copy follows the directory");
    for at in [tail + 56, dir_end + 5] {
        let mut b = bytes.clone();
        b[at] ^= 0x10;
        assert!(matches!(spg::read(&b, &ReadOptions::default()), Err(Error::Corrupt { .. })), "byte {at}");
        assert!(matches!(Book::open(&b), Err(Error::Corrupt { .. })), "byte {at}");
    }
}

#[test]
fn large_sections_use_csum_blocks() {
    let mut s = Spg::default();
    let e = s.engine_index("e", "", Unit::Cp, 100);
    // Enough positions for sections over 64 KiB.
    let mut frontier = vec![Position::startpos()];
    let mut seen = std::collections::HashSet::new();
    while s.positions.len() < 3000 {
        let p = frontier.remove(0);
        if !seen.insert(p.clone()) {
            continue;
        }
        let mut entry = PositionEntry::new(p.clone());
        for m in p.legal_moves().into_iter().take(4) {
            let mut x = Edge::new(m);
            x.weight = Some(1);
            x.eval = Some(EdgeEval { value: 10, engine: e, depth: Some(5) });
            entry.edges.push(x);
            frontier.push(p.play_unchecked(m));
        }
        s.positions.push(entry);
    }
    let (bytes, _) = spg::write(&s, &WriteOptions { blk3: true, ..opts() }).unwrap();
    let c = spg::container::Container::open(&bytes).unwrap();
    let posn = c.index(POSN).unwrap();
    assert!(c.entries[posn].len > BLOCK && c.entries[posn].hash == 0);
    let (back, info) = spg::read(&bytes, &ReadOptions::default()).unwrap();
    assert_eq!(back.positions.len(), 3000);
    assert!(info.blk3_root.is_some());
    // Damage one block of POSN: reported as corrupt in POSN.
    let mut b = bytes.clone();
    b[c.entries[posn].offset + BLOCK + 100] ^= 0x10;
    match spg::read(&b, &ReadOptions::default()) {
        Err(Error::Corrupt { section: Some(t), .. }) => assert_eq!(&t, b"POSN"),
        other => panic!("{other:?}"),
    }
    // Lookup: find positions and edges without decoding.
    let book = Book::open(&bytes).unwrap();
    for p in back.positions.iter().step_by(97) {
        let k = book.find(&p.position).unwrap().expect("found");
        let edges = book.edges(k).unwrap();
        assert_eq!(edges.len(), p.edges.len());
        if let Some(e) = p.edges.first() {
            assert!(book.verify_for_play(&p.position, e.mv).unwrap());
        }
    }
    let missing = Position::from_sfen("4k4/9/9/9/9/9/9/9/4K4 b -").unwrap();
    assert_eq!(book.find(&missing).unwrap(), None);
    // The engine path detects the damaged block when it touches it.
    let damaged = Book::open(&b).unwrap();
    let hits: Vec<_> = back.positions.iter().map(|p| damaged.find(&p.position)).collect();
    assert!(hits.iter().any(|r| r.is_err()));
}

#[test]
fn unknown_sections_and_versions() {
    let s = sample();
    let mut opaque = prelude(0, 0, &[]);
    opaque.extend_from_slice(b"private data");
    let mut with = s.clone();
    with.opaque.push(OpaqueSection { tag: *b"xsak", flags: 0, bytes: opaque });
    let (bytes, back) = round_trip(&with);
    assert_eq!(back.opaque.len(), 1, "unknown sections are kept");
    // A required unknown section is rejected.
    let c = spg::container::Container::open(&bytes).unwrap();
    let i = c.entries.iter().position(|e| &e.tag == b"xsak").unwrap();
    let mut b = bytes.clone();
    let dir = c.header.dir_offset as usize;
    b[dir + i * 32 + 4] |= 1;
    let h = xxhash_dir(&b, dir, c.entries.len());
    b[40..48].copy_from_slice(&h.to_le_bytes());
    assert!(matches!(spg::read(&b, &ReadOptions::default()), Err(Error::Rejected(_))));
    // A newer major version is rejected.
    let mut b = bytes.clone();
    b[8] = 2;
    let tail = b.len() - 64;
    b[tail + 8] = 2;
    assert!(matches!(spg::read(&b, &ReadOptions::default()), Err(Error::Rejected(_))));
}

fn xxhash_dir(b: &[u8], at: usize, n: usize) -> u64 {
    xxhash_rust::xxh3::xxh3_64(&b[at..at + n * 32])
}

#[test]
fn writer_refuses_invalid_data() {
    let mut s = sample();
    s.positions[0].edges[0].mv = mv("5a5b");
    assert!(matches!(spg::write(&s, &opts()), Err(Error::Invalid(_))));
    let mut s = sample();
    s.file_annos.push(Anno::str("note", "undefined key"));
    assert!(matches!(spg::write(&s, &opts()), Err(Error::Invalid(_))));
    let mut s = sample();
    s.positions[0].edges[0].stats = Some(Stats { games: 1, wins: 1, draws: 1 });
    assert!(spg::write(&s, &opts()).is_err());
    let mut s = sample();
    s.positions.push(s.positions[0].clone());
    assert!(spg::write(&s, &opts()).is_err());
    let mut s = sample();
    s.positions[0].edges[0].eval = Some(EdgeEval { value: 1 << 25, engine: 0, depth: None });
    assert!(spg::write(&s, &opts()).is_err());
    let mut s = sample();
    s.positions[0].prov.push(Prov { source: 0, ..Default::default() });
    assert!(spg::write(&s, &opts()).is_err(), "PROV needs merge.rule");
    s.file_annos.push(Anno::str("merge.rule", "sum"));
    spg::write(&s, &opts()).unwrap();
    // Unknown keys are kept when rewriting newer files.
    let mut s = sample();
    s.file_annos.push(Anno::str("future.key", "v"));
    spg::write(&s, &WriteOptions { checks: Checks { allow_unknown: true, legality: true }, ..opts() }).unwrap();
}

#[test]
fn file_sets() {
    let dir = std::env::temp_dir().join(format!("spg-set-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let s = sample();
    for (split, sign) in [(false, false), (true, true)] {
        let o = SetOptions { split, signing_key: sign.then_some([7u8; 32]), build_id: Some(if split { 2 } else { 1 }), ..Default::default() };
        let rep = manifest::write_set(&dir, "book", &s, &o).unwrap();
        assert_eq!(rep.files.len(), if split { 257 } else { 2 });
        let (back, info) = manifest::read_set(&dir.join("book.spgm"), &ReadOptions::default(), 1 << 30).unwrap();
        assert_eq!(back.positions.len(), s.positions.len());
        assert_eq!(back.records.len(), 1);
        assert_eq!(info.signed_by.is_some(), sign);
        assert!(!info.used_backup);
    }
    // A damaged .spgm falls back to .spgm.bak.
    let mut m = std::fs::read(dir.join("book.spgm")).unwrap();
    m[30] ^= 1;
    std::fs::write(dir.join("book.spgm"), &m).unwrap();
    let (_, info) = manifest::read_set(&dir.join("book.spgm"), &ReadOptions::default(), 1 << 30).unwrap();
    assert!(info.used_backup);
    // A tampered shard is rejected.
    let shard = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).find(|p| p.to_string_lossy().contains(".0000000000000002.") && p.to_string_lossy().ends_with(".rec.spg")).unwrap();
    let mut b = std::fs::read(&shard).unwrap();
    b[200] ^= 1;
    std::fs::write(&shard, &b).unwrap();
    std::fs::copy(dir.join("book.spgm.bak"), dir.join("book.spgm")).unwrap();
    assert!(manifest::read_set(&dir.join("book.spgm"), &ReadOptions::default(), 1 << 30).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn key_ranges() {
    assert_eq!(manifest::key_range(0, 0), (0, u64::MAX));
    assert_eq!(manifest::key_range(255, 8), (0xFF00_0000_0000_0000, u64::MAX));
    assert_eq!(bucket(u64::MAX, 16, 0), 0xFFFF);
    assert_eq!(bucket(0x00FF_FF00_0000_0000, 16, 8), 0xFFFF);
    assert_eq!(shard_of(u64::MAX, 0), 0);
}

#[test]
fn hostile_inputs_never_panic() {
    let s = sample();
    let (bytes, _) = spg::write(&s, &opts()).unwrap();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let rounds: usize = std::env::var("SAKIYOMI_FUZZ_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
    for _ in 0..rounds {
        let mut b = bytes.clone();
        for _ in 0..1 + rnd() % 8 {
            let i = (rnd() as usize) % b.len();
            b[i] = rnd() as u8;
        }
        if rnd() % 4 == 0 {
            b.truncate((rnd() as usize) % b.len());
        }
        let _ = spg::read(&b, &ReadOptions::default());
        if let Ok(book) = Book::open(&b) {
            let _ = book.find(&Position::startpos()).map(|k| k.map(|k| book.edges(k)));
        }
        let text = String::from_utf8_lossy(&b).into_owned();
        let _ = spg::text::parse(&text);
    }
    let t = spg::text::write(&s).unwrap();
    for _ in 0..rounds {
        let mut c: Vec<char> = t.chars().collect();
        for _ in 0..1 + rnd() % 4 {
            let i = (rnd() as usize) % c.len();
            c[i] = ['"', '[', ']', ' ', '=', '\n', 'x', '0', '\\'][(rnd() % 9) as usize];
        }
        let _ = spg::text::parse(&c.into_iter().collect::<String>());
    }
}

