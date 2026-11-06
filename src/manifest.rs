//! File sets: position shards, the records-only file and the `.spgm` manifest with its
//! `.spgm.bak` twin (§7.28, §11.6, §11.7), BLK3 roots and Ed25519 signatures (§11.8).

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::container::Container;
use crate::error::{Error, Result};
use crate::hash::xxh3;
use crate::layout::*;
use crate::model::Spg;
use crate::position::Encoded;
use crate::read::{self, ReadInfo, ReadOptions};
use crate::validate;
use crate::write::{self, EdgeForm, FileSpec, random_build_id};

pub const ENTRY_LEN: usize = 80;
pub const SIGNATURE_LEN: usize = 100;
/// Shard bits every v1.0 writer uses when it splits a set (§7.28).
pub const SHARD_BITS: u8 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    /// All ones for the records-only file.
    pub shard: u32,
    pub first_global: u64,
    pub positions: u64,
    pub key_lo: u64,
    pub key_hi: u64,
    pub file_hash: u64,
    /// Zero when the file has no BLK3.
    pub blk3_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub minor: u16,
    pub s: u8,
    pub build_id: u64,
    pub total_positions: u64,
    pub entries: Vec<ManifestEntry>,
    pub signature: Option<Signature>,
}

impl Manifest {
    fn body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&MANIFEST_MAGIC);
        put16(&mut b, MAJOR);
        put16(&mut b, MINOR);
        b.push(self.s);
        let records = self.entries.iter().any(|e| e.shard == NONE32);
        b.push(u8::from(self.signature.is_some()) | (u8::from(records) << 1));
        put16(&mut b, 0);
        put32(&mut b, self.entries.len() as u32);
        put32(&mut b, 0);
        put64(&mut b, self.build_id);
        put64(&mut b, self.total_positions);
        for e in &self.entries {
            put32(&mut b, e.shard);
            put32(&mut b, 0);
            put64(&mut b, e.first_global);
            put64(&mut b, e.positions);
            put64(&mut b, e.key_lo);
            put64(&mut b, e.key_hi);
            put64(&mut b, e.file_hash);
            b.extend_from_slice(&e.blk3_root);
        }
        b
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        if let Some(s) = &self.signature {
            b.push(1);
            b.extend_from_slice(&[0; 3]);
            b.extend_from_slice(&s.public_key);
            b.extend_from_slice(&s.signature);
        }
        let h = xxh3(&b);
        put64(&mut b, h);
        b
    }

    /// Sign with an Ed25519 key (32-byte seed). Every file must have BLK3 (§11.8).
    pub fn sign(&mut self, seed: &[u8; 32]) -> Result<()> {
        use ed25519_dalek::Signer;
        if self.entries.iter().any(|e| e.blk3_root == [0; 32]) {
            return Err(Error::invalid("a signed manifest needs BLK3 in every file"));
        }
        let key = ed25519_dalek::SigningKey::from_bytes(seed);
        self.signature = Some(Signature { public_key: [0; 32], signature: [0; 64] });
        let msg = self.body();
        // The signed bytes run up to the signature field (§11.8), with the flag bit set.
        let sig = key.sign(&msg);
        self.signature = Some(Signature { public_key: key.verifying_key().to_bytes(), signature: sig.to_bytes() });
        Ok(())
    }

    /// Check the signature; `Ok(None)` when unsigned.
    pub fn verify_signature(&self) -> Result<Option<[u8; 32]>> {
        let Some(s) = &self.signature else { return Ok(None) };
        let key = ed25519_dalek::VerifyingKey::from_bytes(&s.public_key).map_err(|_| Error::rejected("bad public key in the manifest"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&s.signature);
        key.verify_strict(&self.body(), &sig).map_err(|_| Error::rejected("manifest signature does not verify"))?;
        Ok(Some(s.public_key))
    }

    pub fn parse(b: &[u8]) -> Result<Manifest> {
        let bad = |m: &str| Error::rejected(format!("manifest: {m}"));
        if !b.starts_with(&MANIFEST_MAGIC) {
            return Err(bad("magic mismatch"));
        }
        if b.len() < 48 {
            return Err(bad("truncated"));
        }
        let (body, tail) = b.split_at(b.len() - 8);
        if u64_at(tail, 0) != Some(xxh3(body)) {
            return Err(bad("hash mismatch"));
        }
        let major = u16_at(b, 8).unwrap_or(0);
        let minor = u16_at(b, 10).unwrap_or(0);
        if major != MAJOR {
            return Err(bad("unsupported major version"));
        }
        let strict = known_minor(minor);
        let s = b[12];
        let flags = b[13];
        if s > 16 {
            return Err(bad("s out of range"));
        }
        if strict && (flags & !3 != 0 || u16_at(b, 14) != Some(0) || u32_at(b, 20) != Some(0)) {
            return Err(bad("reserved fields are not zero"));
        }
        let n = u32_at(b, 16).unwrap_or(0) as usize;
        let signed = flags & 1 != 0;
        let expect = 40usize.checked_add(n.checked_mul(ENTRY_LEN).ok_or_else(|| bad("too many files"))?).ok_or_else(|| bad("too many files"))? + if signed { SIGNATURE_LEN } else { 0 };
        if body.len() != expect {
            return Err(bad("length does not match the file count"));
        }
        let mut entries = Vec::with_capacity(n);
        for k in 0..n {
            let at = 40 + k * ENTRY_LEN;
            if strict && u32_at(b, at + 4) != Some(0) {
                return Err(bad("reserved entry field is not zero"));
            }
            entries.push(ManifestEntry {
                shard: u32_at(b, at).unwrap_or(0),
                first_global: u64_at(b, at + 8).unwrap_or(0),
                positions: u64_at(b, at + 16).unwrap_or(0),
                key_lo: u64_at(b, at + 24).unwrap_or(0),
                key_hi: u64_at(b, at + 32).unwrap_or(0),
                file_hash: u64_at(b, at + 40).unwrap_or(0),
                blk3_root: get::<32>(b, at + 48).unwrap_or([0; 32]),
            });
        }
        let signature = if signed {
            let at = 40 + n * ENTRY_LEN;
            if b[at] != 1 {
                return Err(bad("unknown signature method"));
            }
            if strict && b[at + 1..at + 4] != [0, 0, 0] {
                return Err(bad("reserved signature bytes are not zero"));
            }
            Some(Signature { public_key: get::<32>(b, at + 4).unwrap_or([0; 32]), signature: get::<64>(b, at + 36).unwrap_or([0; 64]) })
        } else {
            None
        };
        let m = Manifest { minor, s, build_id: u64_at(b, 24).unwrap_or(0), total_positions: u64_at(b, 32).unwrap_or(0), entries, signature };
        m.check_layout()?;
        if (flags & 2 != 0) != m.entries.iter().any(|e| e.shard == NONE32) {
            return Err(bad("records-only flag does not match the entries"));
        }
        Ok(m)
    }

    /// Entry order, shard numbers, key ranges and index continuity (§7.28).
    fn check_layout(&self) -> Result<()> {
        let bad = |m: &str| Error::rejected(format!("manifest: {m}"));
        let shards = 1usize << self.s;
        let pos: Vec<&ManifestEntry> = self.entries.iter().filter(|e| e.shard != NONE32).collect();
        let recs = self.entries.len() - pos.len();
        if pos.len() != shards || recs > 1 || self.entries.iter().take(shards).any(|e| e.shard == NONE32) {
            return Err(bad("expected 2^s position shards followed by at most one records-only file"));
        }
        let mut next = 0u64;
        for (i, e) in pos.iter().enumerate() {
            let (lo, hi) = key_range(i as u32, self.s);
            if e.shard != i as u32 || e.first_global != next || e.key_lo != lo || e.key_hi != hi {
                return Err(bad("shard entry out of order or with wrong bounds"));
            }
            next = next.checked_add(e.positions).ok_or_else(|| bad("position count overflow"))?;
        }
        if next != self.total_positions {
            return Err(bad("total position count does not add up"));
        }
        for e in self.entries.iter().filter(|e| e.shard == NONE32) {
            if e.first_global != 0 || e.positions != 0 || e.key_lo != 0 || e.key_hi != 0 {
                return Err(bad("records-only entry fields must be zero"));
            }
        }
        Ok(())
    }
}

/// Key range a shard covers (§7.28).
pub fn key_range(shard: u32, s: u8) -> (u64, u64) {
    if s == 0 {
        return (0, u64::MAX);
    }
    let w = 64 - u32::from(s);
    let lo = u64::from(shard) << w;
    (lo, lo | ((1u64 << w) - 1))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn shard_file_name(name: &str, build: u64, shard: u32) -> String {
    format!("{name}.{build:016x}.{shard:04x}.spg")
}

pub fn records_file_name(name: &str, build: u64) -> String {
    format!("{name}.{build:016x}.rec.spg")
}

#[derive(Clone, Debug, Default)]
pub struct SetOptions {
    /// Split into 2^8 shards (§7.28); otherwise one shard (s = 0).
    pub split: bool,
    pub edges: EdgeForm,
    /// Write BLK3 in every file (implied by `signing_key`).
    pub blk3: bool,
    /// Ed25519 seed to sign the manifest with.
    pub signing_key: Option<[u8; 32]>,
    pub build_id: Option<u64>,
    pub checks: validate::Checks,
    /// Delete the previous build's files after the manifests are replaced. Off by default:
    /// readers that still use them cannot be detected (§11.7 step 3).
    pub remove_old: bool,
}

#[derive(Clone, Debug, Default)]
pub struct SetReport {
    pub build_id: u64,
    pub files: Vec<PathBuf>,
    /// Files of the previous build, kept (or removed with `remove_old`).
    pub old_files: Vec<PathBuf>,
    pub removed_old: bool,
    pub write: write::WriteReport,
}

fn write_durably(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::File::create(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Replace `path` atomically: write a temporary file, persist it, rename it into place.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    write_durably(&tmp, bytes)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    Ok(())
}

/// Write a file set `<dir>/<name>.spgm` following the update procedure of §11.7.
pub fn write_set(dir: &Path, name: &str, spg: &Spg, opts: &SetOptions) -> Result<SetReport> {
    if !valid_name(name) {
        return Err(Error::invalid("set names use only letters, digits, '-' and '_'"));
    }
    validate::validate(spg, &opts.checks)?;
    let (spg, wreport) = write::prepare_edges(spg, opts.edges);
    let s = if opts.split { SHARD_BITS } else { 0 };
    let build = opts.build_id.unwrap_or_else(random_build_id);
    let blk3 = opts.blk3 || opts.signing_key.is_some();
    let order = validate::canonical_order(&spg);
    let global: HashMap<Encoded, u64> = order.iter().enumerate().map(|(g, (e, _))| (e.clone(), g as u64)).collect();
    let mut shards: Vec<Vec<(&crate::model::PositionEntry, Encoded)>> = vec![Vec::new(); 1 << s];
    for (e, i) in &order {
        shards[shard_of(e.key(), s) as usize].push((&spg.positions[*i], e.clone()));
    }
    let manifest_path = dir.join(format!("{name}.spgm"));
    let previous = read_manifest_file(&manifest_path).ok();
    let mut entries = Vec::new();
    let mut files = Vec::new();
    let mut first = 0u64;
    for (i, positions) in shards.iter().enumerate() {
        let spec = FileSpec {
            kind: FileKind::PositionShard,
            shard: i as u32,
            s,
            first_global: first,
            build_id: build,
            compact: wreport.compact,
            blk3,
            positions,
            global: &global,
            records: &[],
            spg: &spg,
        };
        let bytes = write::write_file(&spec)?;
        let path = dir.join(shard_file_name(name, build, i as u32));
        write_durably(&path, &bytes)?;
        let (lo, hi) = key_range(i as u32, s);
        entries.push(ManifestEntry { shard: i as u32, first_global: first, positions: positions.len() as u64, key_lo: lo, key_hi: hi, file_hash: xxh3(&bytes), blk3_root: blk3_root(&bytes)? });
        files.push(path);
        first += positions.len() as u64;
    }
    if !spg.records.is_empty() || !spg.raws.is_empty() {
        let spec = FileSpec {
            kind: FileKind::RecordsOnly,
            shard: NONE32,
            s: 0,
            first_global: 0,
            build_id: build,
            compact: wreport.compact,
            blk3,
            positions: &[],
            global: &global,
            records: &spg.records,
            spg: &spg,
        };
        let bytes = write::write_file(&spec)?;
        let path = dir.join(records_file_name(name, build));
        write_durably(&path, &bytes)?;
        entries.push(ManifestEntry { shard: NONE32, first_global: 0, positions: 0, key_lo: 0, key_hi: 0, file_hash: xxh3(&bytes), blk3_root: blk3_root(&bytes)? });
        files.push(path);
    }
    let mut m = Manifest { minor: MINOR, s, build_id: build, total_positions: first, entries, signature: None };
    if let Some(seed) = &opts.signing_key {
        m.sign(seed)?;
    }
    let bytes = m.to_bytes();
    replace(&manifest_path, &bytes)?;
    replace(&dir.join(format!("{name}.spgm.bak")), &bytes)?;
    let mut report = SetReport { build_id: build, files, write: wreport, ..Default::default() };
    if let Some(old) = previous
        && old.build_id != build
    {
        report.old_files = set_files(dir, name, &old);
        if opts.remove_old {
            for f in &report.old_files {
                let _ = fs::remove_file(f);
            }
            report.removed_old = true;
        }
    }
    Ok(report)
}

fn blk3_root(bytes: &[u8]) -> Result<[u8; 32]> {
    Ok(Container::open(bytes)?.verify_blk3()?.unwrap_or([0; 32]))
}

fn set_files(dir: &Path, name: &str, m: &Manifest) -> Vec<PathBuf> {
    m.entries
        .iter()
        .map(|e| dir.join(if e.shard == NONE32 { records_file_name(name, m.build_id) } else { shard_file_name(name, m.build_id, e.shard) }))
        .collect()
}

fn read_manifest_file(path: &Path) -> Result<Manifest> {
    let b = fs::read(path)?;
    Manifest::parse(&b)
}

#[derive(Clone, Debug, Default)]
pub struct SetInfo {
    pub manifest: Option<Manifest>,
    /// The `.spgm.bak` was used because `.spgm` was damaged or stale (§11.6).
    pub used_backup: bool,
    /// The public key that signed the manifest, when the signature and every BLK3 root
    /// verified. Whether the key is trusted is for the caller to decide (§11.8).
    pub signed_by: Option<[u8; 32]>,
    pub files: Vec<ReadInfo>,
}

/// Read a file set through `<name>.spgm` (or its `.bak`, §11.6). `limit` caps the bytes
/// read per file.
pub fn read_set(manifest_path: &Path, opts: &ReadOptions, limit: u64) -> Result<(Spg, SetInfo)> {
    let dir = manifest_path.parent().unwrap_or(Path::new("."));
    let file_name = manifest_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let name = file_name.strip_suffix(".spgm.bak").or_else(|| file_name.strip_suffix(".spgm")).ok_or_else(|| Error::invalid("a manifest is named <name>.spgm"))?;
    let candidates = [dir.join(format!("{name}.spgm")), dir.join(format!("{name}.spgm.bak"))];
    let mut last_err = Error::rejected("no usable manifest");
    for (k, path) in candidates.iter().enumerate() {
        let attempt = (|| -> Result<(Manifest, Vec<Vec<u8>>)> {
            let m = read_manifest_file(path)?;
            let mut bytes = Vec::new();
            for f in set_files(dir, name, &m) {
                let len = fs::metadata(&f).map_err(|_| Error::rejected(format!("missing file {}", f.display())))?.len();
                if len > limit {
                    return Err(Error::Limit(format!("{} is larger than {limit} bytes", f.display())));
                }
                let b = fs::read(&f)?;
                if Container::open(&b).map(|c| c.header.build_id) != Ok(m.build_id) {
                    return Err(Error::rejected(format!("{} belongs to another build", f.display())));
                }
                bytes.push(b);
            }
            Ok((m, bytes))
        })();
        match attempt {
            Ok((m, bytes)) => return read_files(m, bytes, k == 1, opts),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn read_files(m: Manifest, bytes: Vec<Vec<u8>>, used_backup: bool, opts: &ReadOptions) -> Result<(Spg, SetInfo)> {
    let signer = m.verify_signature()?;
    let mut parts = Vec::new();
    let mut roots_ok = true;
    for (e, b) in m.entries.iter().zip(&bytes) {
        if xxh3(b) != e.file_hash {
            return Err(Error::rejected("a file's hash does not match the manifest"));
        }
        let c = Container::open(b)?;
        let h = &c.header;
        let want_kind = if e.shard == NONE32 { FileKind::RecordsOnly } else { FileKind::PositionShard };
        // A single file may also carry a manifest (§7.28): one entry, shard 0, s = 0.
        let single_ok = h.kind == FileKind::Single && m.s == 0 && m.entries.len() == 1;
        if (h.kind != want_kind && !single_ok) || h.shard != e.shard || h.first_global != e.first_global {
            return Err(Error::rejected("a file's header does not match its manifest entry"));
        }
        let part = read::decode(&c, opts)?;
        if part.spg.positions.len() as u64 != e.positions {
            return Err(Error::rejected("a shard's position count does not match the manifest"));
        }
        if want_kind == FileKind::PositionShard && !single_ok {
            if part.info.buckets.map(|b| b.1) != Some(m.s) {
                return Err(Error::rejected("a shard's KBKT s does not match the manifest"));
            }
            if part.keys.iter().any(|&k| k < e.key_lo || k > e.key_hi) {
                return Err(Error::corrupt("a position lies outside its shard's key range"));
            }
        }
        match part.info.blk3_root {
            Some(r) if r == e.blk3_root => {}
            None if e.blk3_root == [0; 32] => roots_ok = false,
            _ => return Err(Error::rejected("BLK3 root does not match the manifest")),
        }
        parts.push(part);
    }
    let (spg, files) = read::link(parts, m.total_positions, opts)?;
    let signed_by = if roots_ok { signer } else { None };
    if signer.is_some() && !roots_ok {
        return Err(Error::rejected("a signed manifest needs BLK3 in every file"));
    }
    Ok((spg, SetInfo { manifest: Some(m), used_backup, signed_by, files }))
}
