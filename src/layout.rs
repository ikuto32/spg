//! Byte layout constants of the binary container (§7) and little-endian helpers.

pub const MAGIC: [u8; 8] = *b"SPG\0\r\n\x1A\n";
pub const MANIFEST_MAGIC: [u8; 8] = *b"SPGM\r\n\x1A\n";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;

/// Whether a file's minor version is one this implementation knows: reserved fields must
/// then be zero (§2.4); in newer files they are ignored.
#[allow(clippy::absurd_extreme_comparisons)] // MINOR is 0 today; the check is for later versions.
pub fn known_minor(minor: u16) -> bool {
    minor <= MINOR
}
pub const HEADER_LEN: usize = 64;
pub const PRELUDE_LEN: usize = 64;
pub const DIR_ENTRY_LEN: usize = 32;
pub const BLOCK: usize = 1 << 16;
pub const BLOCK_LOG2: u8 = 16;
/// Bucket bits every v1.0 writer uses (§7.15).
pub const BUCKET_BITS: u8 = 16;
pub const NONE64: u64 = u64::MAX;
pub const NONE32: u32 = u32::MAX;
pub const NONE16: u16 = u16::MAX;

/// File kinds (§7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Single = 0,
    PositionShard = 1,
    RecordsOnly = 2,
}

impl FileKind {
    pub fn from_bits(b: u32) -> Option<FileKind> {
        match b & 3 {
            0 => Some(FileKind::Single),
            1 => Some(FileKind::PositionShard),
            2 => Some(FileKind::RecordsOnly),
            _ => None,
        }
    }
}

pub type Tag = [u8; 4];

pub const STRS: Tag = *b"STRS";
pub const AKEY: Tag = *b"AKEY";
pub const ENGN: Tag = *b"ENGN";
pub const RGHT: Tag = *b"RGHT";
pub const SRCS: Tag = *b"SRCS";
pub const KBKT: Tag = *b"KBKT";
pub const KFLT: Tag = *b"KFLT";
pub const PKEY: Tag = *b"PKEY";
pub const POSN: Tag = *b"POSN";
pub const EDGE: Tag = *b"EDGE";
pub const EDGC: Tag = *b"EDGC";
pub const ANNO: Tag = *b"ANNO";
pub const ANLS: Tag = *b"ANLS";
pub const MVLS: Tag = *b"MVLS";
pub const PROV: Tag = *b"PROV";
pub const RECS: Tag = *b"RECS";
pub const RNOD: Tag = *b"RNOD";
pub const META: Tag = *b"META";
pub const OCCR: Tag = *b"OCCR";
pub const RAWS: Tag = *b"RAWS";
pub const CSUM: Tag = *b"CSUM";
pub const BLK3: Tag = *b"BLK3";

/// Known sections in the recommended order (§7.7), with their record length (0 for
/// variable-length sections) and whether they are derived.
pub const KNOWN: [(Tag, u32, bool); 21] = [
    (STRS, 0, false),
    (AKEY, 8, false),
    (ENGN, 24, false),
    (RGHT, 64, false),
    (SRCS, 24, false),
    (KBKT, 8, true),
    (PKEY, 8, true),
    (POSN, 48, false),
    (EDGE, 48, false),
    (EDGC, 16, false),
    (ANNO, 24, false),
    (ANLS, 56, false),
    (MVLS, 2, false),
    (PROV, 64, false),
    (RECS, 80, false),
    (RNOD, 16, false),
    (META, 16, false),
    (OCCR, 24, true),
    (RAWS, 48, false),
    (CSUM, 24, true),
    (BLK3, 32, true),
];

pub fn known(tag: &Tag) -> Option<(u32, bool)> {
    KNOWN.iter().find(|(t, _, _)| t == tag).map(|&(_, r, d)| (r, d))
}

/// Directory flags (§7.6).
pub const DIR_REQUIRED: u32 = 1;
pub const DIR_DERIVED: u32 = 2;

pub fn align64(n: usize) -> usize {
    n.div_ceil(64) * 64
}

pub fn blocks(len: usize) -> usize {
    len.div_ceil(BLOCK)
}

/// Bucket number i(K) (§7.15).
pub fn bucket(key: u64, b: u8, s: u8) -> u64 {
    let shifted = if s == 0 { key } else { key << s };
    shifted >> (64 - u32::from(b))
}

/// Shard number of a key: its top `s` bits (§7.28). `s = 0` has a single shard.
pub fn shard_of(key: u64, s: u8) -> u32 {
    if s == 0 { 0 } else { (key >> (64 - u32::from(s))) as u32 }
}

// ---------------------------------------------------------------- byte helpers

pub fn put16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
pub fn put32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
pub fn put64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}

/// Bounds-checked little-endian reads (§11.8: every offset is range-checked).
pub fn get<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}
pub fn u8_at(b: &[u8], at: usize) -> Option<u8> {
    b.get(at).copied()
}
pub fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    get::<2>(b, at).map(u16::from_le_bytes)
}
pub fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    get::<4>(b, at).map(u32::from_le_bytes)
}
pub fn i32_at(b: &[u8], at: usize) -> Option<i32> {
    get::<4>(b, at).map(i32::from_le_bytes)
}
pub fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    get::<8>(b, at).map(u64::from_le_bytes)
}

/// A 64-byte section prelude (§7.8).
pub fn prelude(count: u64, record_len: u32, specific: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(PRELUDE_LEN);
    put64(&mut p, count);
    put32(&mut p, record_len);
    put32(&mut p, 0);
    p.extend_from_slice(specific);
    p.resize(PRELUDE_LEN, 0);
    p
}
