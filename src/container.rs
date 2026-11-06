//! Opening a `.spg` file: the open-time checks of §13.1 (magic, version, length, kind,
//! required sections, preludes, directory hash with fallback to the tail copies, CSUM
//! entry) and access-time block verification (§11.2).

use std::ops::Range;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::error::{Error, Result};
use crate::hash::{blake3_leaf, merkle_root, xxh3};
use crate::layout::*;
use crate::write::directory_hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub major: u16,
    pub minor: u16,
    pub flags: u32,
    pub kind: FileKind,
    pub section_count: u32,
    pub shard: u32,
    pub dir_offset: u64,
    pub file_len: u64,
    pub dir_hash: u64,
    pub first_global: u64,
    pub build_id: u64,
}

impl Header {
    fn parse(b: &[u8]) -> Result<Header> {
        let bad = || Error::rejected("truncated header");
        if b.get(..8) != Some(&MAGIC[..]) {
            return Err(Error::rejected("not an SPG file (magic mismatch)"));
        }
        let flags = u32_at(b, 12).ok_or_else(bad)?;
        Ok(Header {
            major: u16_at(b, 8).ok_or_else(bad)?,
            minor: u16_at(b, 10).ok_or_else(bad)?,
            flags,
            kind: FileKind::from_bits(flags).ok_or_else(|| Error::rejected("reserved file kind 3"))?,
            section_count: u32_at(b, 16).ok_or_else(bad)?,
            shard: u32_at(b, 20).ok_or_else(bad)?,
            dir_offset: u64_at(b, 24).ok_or_else(bad)?,
            file_len: u64_at(b, 32).ok_or_else(bad)?,
            dir_hash: u64_at(b, 40).ok_or_else(bad)?,
            first_global: u64_at(b, 48).ok_or_else(bad)?,
            build_id: u64_at(b, 56).ok_or_else(bad)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub tag: Tag,
    pub flags: u32,
    pub offset: usize,
    pub len: usize,
    pub hash: u64,
}

/// The CSUM structure: per target section, where its block hashes start in the lower array.
#[derive(Debug)]
struct Csum {
    /// (section index, first lower entry, block count)
    targets: Vec<(usize, usize, usize)>,
    lower_at: usize,
    upper_at: usize,
    lower_len: usize,
    section: usize,
}

const UNCHECKED: u8 = 0;
const GOOD: u8 = 1;
const BAD: u8 = 2;

/// An opened file. Block checks are remembered, so a block is hashed once (§11.2).
pub struct Container<'a> {
    pub bytes: &'a [u8],
    pub header: Header,
    pub entries: Vec<Entry>,
    /// The first header or directory was damaged and the tail copies were used (§11.6).
    pub used_tail_copy: bool,
    csum: Option<Csum>,
    /// Per section: per block (or one state for sections checked as a whole).
    state: Vec<Vec<AtomicU8>>,
    lower_state: Vec<AtomicU8>,
}

impl std::fmt::Debug for Container<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Container").field("header", &self.header).field("entries", &self.entries).finish()
    }
}

fn parse_directory(bytes: &[u8], h: &Header) -> Result<Vec<Entry>> {
    let n = h.section_count as usize;
    let len = n.checked_mul(DIR_ENTRY_LEN).ok_or_else(|| Error::rejected("section count overflow"))?;
    let start = usize::try_from(h.dir_offset).map_err(|_| Error::rejected("directory offset out of range"))?;
    let dir = bytes.get(start..start.checked_add(len).ok_or_else(|| Error::rejected("directory out of range"))?).ok_or_else(|| Error::rejected("directory out of range"))?;
    if xxh3(dir) != h.dir_hash {
        return Err(Error::rejected("directory hash mismatch"));
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let at = i * DIR_ENTRY_LEN;
        let e = (|| {
            Some(Entry {
                tag: get::<4>(dir, at)?,
                flags: u32_at(dir, at + 4)?,
                offset: usize::try_from(u64_at(dir, at + 8)?).ok()?,
                len: usize::try_from(u64_at(dir, at + 16)?).ok()?,
                hash: u64_at(dir, at + 24)?,
            })
        })()
        .ok_or_else(|| Error::rejected("bad directory entry"))?;
        entries.push(e);
    }
    Ok(entries)
}

impl<'a> Container<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Container<'a>> {
        if bytes.len() < 2 * HEADER_LEN {
            return Err(Error::rejected("file too short"));
        }
        let primary = Header::parse(bytes)?;
        let tail_at = bytes.len() - HEADER_LEN;
        let attempt = |h: Header| -> Result<(Header, Vec<Entry>)> {
            if h.major != MAJOR {
                return Err(Error::rejected(format!("major version {} is not supported", h.major)));
            }
            if h.file_len != bytes.len() as u64 {
                return Err(Error::rejected("file length field does not match the file"));
            }
            if known_minor(h.minor) && h.flags & !3 != 0 {
                return Err(Error::rejected("reserved header flag bits are set"));
            }
            match h.kind {
                FileKind::Single if h.shard != 0 || h.first_global != 0 => {
                    return Err(Error::rejected("a single file has shard number 0 and first index 0"));
                }
                FileKind::RecordsOnly if h.shard != NONE32 || h.first_global != 0 => {
                    return Err(Error::rejected("a records-only file has shard number all ones and first index 0"));
                }
                _ => {}
            }
            let entries = parse_directory(bytes, &h)?;
            Ok((h, entries))
        };
        let (header, entries, used_tail_copy) = match attempt(primary) {
            Ok((h, e)) => (h, e, false),
            Err(first) => {
                // §11.6: verify the tail copies before using them.
                let tail = Header::parse(&bytes[tail_at..]).map_err(|_| first.clone())?;
                if primary.major != MAJOR && tail.major != MAJOR {
                    return Err(first);
                }
                match attempt(tail) {
                    Ok((h, e)) => (h, e, true),
                    Err(_) => return Err(first),
                }
            }
        };
        let strict = known_minor(header.minor);
        // Sections: sorted by offset, 64-aligned, within the file before the directory,
        // not overlapping, unique tags.
        let mut end = HEADER_LEN;
        for (i, e) in entries.iter().enumerate() {
            if !e.tag.iter().all(|c| c.is_ascii_graphic()) {
                return Err(Error::rejected("section tag is not 4 ASCII characters"));
            }
            if entries[..i].iter().any(|x| x.tag == e.tag) {
                return Err(Error::rejected(format!("section {} appears twice", tag_str(&e.tag))));
            }
            if e.offset % 64 != 0 || e.offset < end {
                return Err(Error::rejected(format!("section {} is misplaced", tag_str(&e.tag))));
            }
            end = e.offset.checked_add(e.len).ok_or_else(|| Error::rejected("section length overflow"))?;
            if end as u64 > header.dir_offset {
                return Err(Error::rejected(format!("section {} runs into the directory", tag_str(&e.tag))));
            }
            if strict && e.flags & !3 != 0 {
                return Err(Error::rejected("reserved directory flag bits are set"));
            }
            if e.len < PRELUDE_LEN {
                return Err(Error::rejected(format!("section {} is shorter than its prelude", tag_str(&e.tag))));
            }
            if known(&e.tag).is_none() || e.tag == KFLT {
                if e.flags & DIR_REQUIRED != 0 {
                    return Err(Error::rejected(format!("unknown required section {}", tag_str(&e.tag))));
                }
                if e.tag.first().is_some_and(u8::is_ascii_lowercase) && e.flags & DIR_REQUIRED != 0 {
                    return Err(Error::rejected("private sections cannot be required"));
                }
            }
        }
        let has = |t: Tag| entries.iter().any(|e| e.tag == t);
        let required: &[Tag] = match header.kind {
            FileKind::Single | FileKind::PositionShard => &[KBKT, PKEY, POSN, CSUM],
            FileKind::RecordsOnly => &[RECS, RNOD, CSUM],
        };
        for t in required {
            if !has(*t) {
                return Err(Error::rejected(format!("required section {} is missing", tag_str(t))));
            }
        }
        if header.kind != FileKind::RecordsOnly && has(EDGE) == has(EDGC) {
            return Err(Error::rejected("exactly one of EDGE and EDGC is required"));
        }
        let mut c = Container {
            bytes,
            header,
            entries,
            used_tail_copy,
            csum: None,
            state: Vec::new(),
            lower_state: Vec::new(),
        };
        for i in 0..c.entries.len() {
            c.check_prelude(i, strict)?;
        }
        c.state = c
            .entries
            .iter()
            .map(|e| {
                let n = if e.len > BLOCK && e.tag != CSUM && e.tag != BLK3 { blocks(e.len) } else { 1 };
                (0..n).map(|_| AtomicU8::new(UNCHECKED)).collect()
            })
            .collect();
        c.open_csum()?;
        Ok(c)
    }

    pub fn strict(&self) -> bool {
        known_minor(self.header.minor)
    }

    pub fn index(&self, tag: Tag) -> Option<usize> {
        self.entries.iter().position(|e| e.tag == tag)
    }

    /// The bytes of a section (unverified; call [`Container::verify`] before use).
    pub fn raw(&self, i: usize) -> &'a [u8] {
        let e = &self.entries[i];
        &self.bytes[e.offset..e.offset + e.len]
    }

    /// (count, record length, specific bytes) of a section's prelude.
    pub fn prelude(&self, i: usize) -> (u64, u32, &'a [u8]) {
        let b = self.raw(i);
        (u64_at(b, 0).unwrap_or(0), u32_at(b, 8).unwrap_or(0), &b[16..PRELUDE_LEN])
    }

    fn check_prelude(&self, i: usize, strict: bool) -> Result<()> {
        let e = self.entries[i];
        let (count, rec, spec) = self.prelude(i);
        let b = self.raw(i);
        let corrupt = |m: &str| Error::corrupt_in(e.tag, m.to_owned());
        let Some((want_rec, _)) = known(&e.tag) else { return Ok(()) };
        if e.tag == KFLT {
            return Ok(());
        }
        if rec != want_rec {
            return Err(Error::rejected(format!("section {} has record length {rec}, expected {want_rec}", tag_str(&e.tag))));
        }
        if strict && u32_at(b, 12) != Some(0) {
            return Err(corrupt("reserved prelude field is not zero"));
        }
        let used_specific = match e.tag {
            KBKT => 2,
            EDGC => 2,
            CSUM => 1,
            _ => 0,
        };
        if strict && spec[used_specific..].iter().any(|&x| x != 0) {
            return Err(corrupt("reserved prelude bytes are not zero"));
        }
        let body = (e.len - PRELUDE_LEN) as u64;
        let fixed = count.checked_mul(u64::from(rec)).ok_or_else(|| corrupt("count overflow"))?;
        let ok = match e.tag {
            STRS => true,
            RAWS | CSUM => fixed <= body,
            _ => fixed == body,
        };
        if !ok {
            return Err(corrupt("count, record length and section length disagree"));
        }
        if e.tag == KBKT {
            let (b, s) = (spec[0], spec[1]);
            if !(1..=32).contains(&b) || s > 16 || u32::from(b) + u32::from(s) > 64 {
                return Err(corrupt("bucket parameters out of range"));
            }
            if count != (1u64 << b) + 1 {
                return Err(corrupt("bucket count is not 2^b + 1"));
            }
        }
        Ok(())
    }

    fn open_csum(&mut self) -> Result<()> {
        let Some(ci) = self.index(CSUM) else { return Ok(()) };
        let e = self.entries[ci];
        let b = self.raw(ci);
        if directory_hash(&CSUM, b) != e.hash {
            return Err(Error::corrupt_in(CSUM, "CSUM hash mismatch"));
        }
        let (n, _, spec) = self.prelude(ci);
        if spec[0] != BLOCK_LOG2 {
            return Err(Error::corrupt_in(CSUM, "block size must be 2^16"));
        }
        let expected: Vec<usize> = (0..self.entries.len()).filter(|&i| self.entries[i].len > BLOCK && self.entries[i].tag != CSUM && self.entries[i].tag != BLK3).collect();
        if n as usize != expected.len() {
            return Err(Error::corrupt_in(CSUM, "target count does not match the sections longer than 64 KiB"));
        }
        let mut targets = Vec::with_capacity(expected.len());
        let mut next = 0usize;
        for (k, &si) in expected.iter().enumerate() {
            let at = PRELUDE_LEN + k * 24;
            let tag = get::<4>(b, at);
            let first = u64_at(b, at + 8).map(|v| v as usize);
            let count = u64_at(b, at + 16).map(|v| v as usize);
            if tag != Some(self.entries[si].tag) || first != Some(next) || count != Some(blocks(self.entries[si].len)) || (self.strict() && u32_at(b, at + 4) != Some(0)) {
                return Err(Error::corrupt_in(CSUM, "target table does not match the directory"));
            }
            targets.push((si, next, blocks(self.entries[si].len)));
            next += blocks(self.entries[si].len);
        }
        let lower_at = PRELUDE_LEN + expected.len() * 24;
        let upper_at = lower_at + next * 8;
        let upper_len = (next * 8).div_ceil(BLOCK) * 8;
        if b.len() != upper_at + upper_len {
            return Err(Error::corrupt_in(CSUM, "length does not match its tables"));
        }
        self.lower_state = (0..(next * 8).div_ceil(BLOCK)).map(|_| AtomicU8::new(UNCHECKED)).collect();
        self.csum = Some(Csum { targets, lower_at, upper_at, lower_len: next, section: ci });
        Ok(())
    }

    fn lower_chunk_ok(&self, chunk: usize, fresh: bool) -> bool {
        let Some(c) = &self.csum else { return false };
        let st = &self.lower_state[chunk];
        match if fresh { UNCHECKED } else { st.load(Ordering::Relaxed) } {
            GOOD => return true,
            BAD => return false,
            _ => {}
        }
        let b = self.raw(c.section);
        let start = c.lower_at + chunk * BLOCK;
        let end = (start + BLOCK).min(c.lower_at + c.lower_len * 8);
        let ok = u64_at(b, c.upper_at + chunk * 8) == Some(xxh3(&b[start..end]));
        st.store(if ok { GOOD } else { BAD }, Ordering::Relaxed);
        ok
    }

    /// Verify the blocks of section `i` that cover `range` (bytes within the section).
    /// Sections up to 64 KiB are checked as a whole against the directory (§11.2).
    pub fn verify(&self, i: usize, range: Range<usize>) -> Result<()> {
        self.verify_with(i, range, false)
    }

    /// Like [`Container::verify`] but hashing again even blocks already checked: the
    /// re-verification right before a book move is played (§11.4).
    pub fn verify_fresh(&self, i: usize, range: Range<usize>) -> Result<()> {
        self.verify_with(i, range, true)
    }

    fn verify_with(&self, i: usize, range: Range<usize>, fresh: bool) -> Result<()> {
        let e = self.entries[i];
        if e.tag == CSUM || e.tag == BLK3 {
            return Ok(()); // CSUM was checked at open; BLK3 is checked by verify_blk3.
        }
        if e.len <= BLOCK {
            let st = &self.state[i][0];
            match if fresh { UNCHECKED } else { st.load(Ordering::Relaxed) } {
                GOOD => return Ok(()),
                BAD => return Err(Error::corrupt_in(e.tag, "section hash mismatch")),
                _ => {}
            }
            let ok = xxh3(self.raw(i)) == e.hash;
            st.store(if ok { GOOD } else { BAD }, Ordering::Relaxed);
            return if ok { Ok(()) } else { Err(Error::corrupt_in(e.tag, "section hash mismatch")) };
        }
        let Some(c) = &self.csum else { return Err(Error::corrupt_in(e.tag, "no CSUM entry for a section over 64 KiB")) };
        let Some(&(_, first, n)) = c.targets.iter().find(|t| t.0 == i) else {
            return Err(Error::corrupt_in(e.tag, "no CSUM entry for a section over 64 KiB"));
        };
        let csum = self.raw(c.section);
        let last = range.end.max(range.start + 1).min(e.len).div_ceil(BLOCK).min(n);
        for blk in range.start / BLOCK..last {
            let st = &self.state[i][blk];
            match if fresh { UNCHECKED } else { st.load(Ordering::Relaxed) } {
                GOOD => continue,
                BAD => return Err(Error::corrupt_in(e.tag, format!("block {blk} failed its checksum"))),
                _ => {}
            }
            let li = first + blk;
            let ok = self.lower_chunk_ok(li * 8 / BLOCK, fresh) && {
                let data = &self.raw(i)[blk * BLOCK..((blk + 1) * BLOCK).min(e.len)];
                u64_at(csum, c.lower_at + li * 8) == Some(xxh3(data))
            };
            st.store(if ok { GOOD } else { BAD }, Ordering::Relaxed);
            if !ok {
                let derived = e.flags & DIR_DERIVED != 0;
                return Err(Error::corrupt_in(e.tag, format!("block {blk} failed its checksum{}", if derived { " (derived data: can be rebuilt)" } else { "" })));
            }
        }
        Ok(())
    }

    /// Verify every section.
    pub fn verify_all(&self) -> Result<()> {
        for i in 0..self.entries.len() {
            self.verify(i, 0..self.entries[i].len)?;
        }
        Ok(())
    }

    /// Full-check items of §13.2.12 and .16: zero padding and identical tail copies.
    /// §11.6: when the header and directory at the start are valid, the copies at the end
    /// must equal them; a difference cannot be resolved and is reported as corruption.
    /// Cheap (one header and one directory), so readers run it when opening a file.
    pub fn verify_tail(&self) -> Result<()> {
        if self.used_tail_copy {
            return Ok(());
        }
        let b = self.bytes;
        let dir_len = self.entries.len() * DIR_ENTRY_LEN;
        let dir_at = self.header.dir_offset as usize;
        let tail_at = b.len() - HEADER_LEN;
        let copy_at = u64_at(b, tail_at + 24).unwrap_or(0) as usize;
        let mut expect = b[..HEADER_LEN].to_vec();
        expect[24..32].copy_from_slice(&(copy_at as u64).to_le_bytes());
        if b[tail_at..] != expect[..] {
            return Err(Error::corrupt("the tail header copy differs from the header"));
        }
        // §7.1: the directory copy follows the directory directly.
        if copy_at != dir_at + dir_len || b.get(copy_at..copy_at + dir_len) != b.get(dir_at..dir_at + dir_len) {
            return Err(Error::corrupt("the directory copy differs from the directory"));
        }
        Ok(())
    }

    pub fn verify_layout(&self) -> Result<()> {
        let b = self.bytes;
        let h = &self.header;
        let dir_len = self.entries.len() * DIR_ENTRY_LEN;
        let dir_at = h.dir_offset as usize;
        let tail_at = b.len() - HEADER_LEN;
        let copy_at = u64_at(b, tail_at + 24).unwrap_or(0) as usize;
        let mut regions: Vec<Range<usize>> = vec![0..HEADER_LEN, dir_at..dir_at + dir_len, tail_at..b.len()];
        regions.extend(self.entries.iter().map(|e| e.offset..e.offset + e.len));
        self.verify_tail()?;
        if !self.used_tail_copy {
            regions.push(copy_at..copy_at + dir_len);
        }
        if self.used_tail_copy {
            // Degraded mode: the damaged primary header cannot locate its directory.
            return Ok(());
        }
        regions.sort_by_key(|r| r.start);
        let mut at = 0;
        for r in regions {
            if r.start > at && b[at..r.start].iter().any(|&x| x != 0) {
                return Err(Error::corrupt("padding bytes are not zero"));
            }
            at = at.max(r.end);
        }
        Ok(())
    }

    /// BLK3 (§11.8): recompute the leaves and return the Merkle root, or `None` when the
    /// file has no BLK3.
    pub fn verify_blk3(&self) -> Result<Option<[u8; 32]>> {
        let Some(bi) = self.index(BLK3) else { return Ok(None) };
        let b = self.raw(bi);
        let (n, _, _) = self.prelude(bi);
        let dir_at = self.header.dir_offset as usize;
        let dir = &self.bytes[dir_at..dir_at + self.entries.len() * DIR_ENTRY_LEN];
        let mut leaves = vec![blake3_leaf(&[&self.bytes[..HEADER_LEN], dir])];
        for (i, e) in self.entries.iter().enumerate() {
            if e.tag == BLK3 {
                continue;
            }
            leaves.extend(self.raw(i).chunks(BLOCK).map(|c| blake3_leaf(&[c])));
        }
        if leaves.len() as u64 != n {
            return Err(Error::corrupt_in(BLK3, "leaf count does not match the file"));
        }
        for (k, l) in leaves.iter().enumerate() {
            if b.get(PRELUDE_LEN + k * 32..PRELUDE_LEN + (k + 1) * 32) != Some(&l[..]) {
                return Err(Error::corrupt_in(BLK3, format!("leaf {k} does not match")));
            }
        }
        Ok(Some(merkle_root(&leaves)))
    }
}

pub fn tag_str(t: &Tag) -> String {
    String::from_utf8_lossy(t).into_owned()
}
