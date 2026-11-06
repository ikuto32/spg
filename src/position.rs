//! Positions (§2.5, §6.1, §6.3–6.5): squares, pieces, the canonical SFEN, the canonical
//! position encoding (CPE) and the position key.

use std::fmt;

use crate::error::{Error, Result};
use crate::hash::xxh3;

/// Square number `(file − 1) × 9 + (rank − 1)`: １一 = 0, １九 = 8, ２一 = 9, ９九 = 80 (§6.1).
pub type Square = u8;

/// The side to move, or a piece's owner. Black is Sente (upper case in SFEN; 下手 in
/// handicap games), White is Gote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Color {
    Black = 0,
    White = 1,
}

impl Color {
    pub fn opponent(self) -> Color {
        match self {
            Color::Black => Color::White,
            Color::White => Color::Black,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// Piece kinds. The first seven discriminants are the SPG piece-kind codes of §6.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Pawn = 0,
    Lance = 1,
    Knight = 2,
    Silver = 3,
    Gold = 4,
    Bishop = 5,
    Rook = 6,
    King = 7,
}

impl Kind {
    /// The seven kinds that can be in hand, in code order.
    pub const HAND: [Kind; 7] = [Kind::Pawn, Kind::Lance, Kind::Knight, Kind::Silver, Kind::Gold, Kind::Bishop, Kind::Rook];

    /// Count of each kind in the standard set (§6.1), indexed by code.
    pub const STANDARD: [u32; 7] = [18, 4, 4, 4, 4, 2, 2];

    pub fn from_code(code: u8) -> Option<Kind> {
        Kind::HAND.get(usize::from(code)).copied()
    }

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn can_promote(self) -> bool {
        !matches!(self, Kind::Gold | Kind::King)
    }

    fn letter(self) -> char {
        ['P', 'L', 'N', 'S', 'G', 'B', 'R', 'K'][self as usize]
    }

    fn from_letter(c: char) -> Option<Kind> {
        Some(match c.to_ascii_uppercase() {
            'P' => Kind::Pawn,
            'L' => Kind::Lance,
            'N' => Kind::Knight,
            'S' => Kind::Silver,
            'G' => Kind::Gold,
            'B' => Kind::Bishop,
            'R' => Kind::Rook,
            'K' => Kind::King,
            _ => return None,
        })
    }

    /// USI letter (upper case) used for drops.
    pub fn usi_letter(self) -> char {
        self.letter()
    }

    pub fn from_usi_letter(c: char) -> Option<Kind> {
        if c.is_ascii_uppercase() { Kind::from_letter(c) } else { None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Piece {
    pub kind: Kind,
    pub color: Color,
    pub promoted: bool,
}

impl Piece {
    pub fn new(kind: Kind, color: Color, promoted: bool) -> Self {
        Piece { kind, color, promoted }
    }
}

/// A position: pieces on the board, both hands and the side to move. No move number and no
/// history (§2.5). Hands may exceed the standard set: such positions are extended positions.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Position {
    pub board: [Option<Piece>; 81],
    /// `hands[color][code]` for the seven hand kinds.
    pub hands: [[u32; 7]; 2],
    pub side: Color,
}

impl fmt::Debug for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Position({})", self.to_sfen())
    }
}

/// The canonical SFEN of the initial position.
pub const STARTPOS: &str = "lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b -";

/// How a position is stored (§6.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Encoded {
    /// A normal position's 256-bit CPE.
    Cpe([u8; 32]),
    /// An extended position's canonical SFEN.
    Sfen(String),
}

impl Encoded {
    /// Position key K (§6.4).
    pub fn key(&self) -> u64 {
        match self {
            Encoded::Cpe(c) => xxh3(c),
            Encoded::Sfen(s) => xxh3(s.as_bytes()),
        }
    }

    pub fn is_extended(&self) -> bool {
        matches!(self, Encoded::Sfen(_))
    }

    /// The order of §7.16 among positions with the same key: normal positions by CPE, then
    /// extended positions by SFEN bytes.
    pub fn sort_key(&self) -> (u64, u8, &[u8]) {
        match self {
            Encoded::Cpe(c) => (self.key(), 0, c),
            Encoded::Sfen(s) => (self.key(), 1, s.as_bytes()),
        }
    }
}

impl Position {
    pub fn empty(side: Color) -> Self {
        Position { board: [None; 81], hands: [[0; 7]; 2], side }
    }

    pub fn startpos() -> Self {
        #[allow(clippy::expect_used)] // A constant that is covered by the tests.
        Position::from_sfen(STARTPOS).expect("STARTPOS parses")
    }

    pub fn file_of(sq: usize) -> usize {
        sq / 9
    }

    pub fn rank_of(sq: usize) -> usize {
        sq % 9
    }

    /// Parse a SFEN with three fields (canonical or not) or four (the move number is
    /// ignored). Returns the position and the move number, when given.
    pub fn parse_sfen(text: &str) -> Result<(Position, Option<u32>)> {
        let fields: Vec<&str> = text.split(' ').collect();
        if !(fields.len() == 3 || fields.len() == 4) || fields.iter().any(|f| f.is_empty()) {
            return Err(Error::invalid(format!("SFEN needs 3 or 4 fields separated by single spaces: {text:?}")));
        }
        let side = match fields[1] {
            "b" => Color::Black,
            "w" => Color::White,
            other => return Err(Error::invalid(format!("bad side to move {other:?}"))),
        };
        let mut pos = Position::empty(side);
        let rows: Vec<&str> = fields[0].split('/').collect();
        if rows.len() != 9 {
            return Err(Error::invalid("SFEN board needs nine ranks"));
        }
        for (rank, row) in rows.iter().enumerate() {
            let mut file = 9usize; // 9 down to 1
            let mut promoted = false;
            for c in row.chars() {
                if c == '+' {
                    if promoted {
                        return Err(Error::invalid("double '+' in SFEN"));
                    }
                    promoted = true;
                    continue;
                }
                if let Some(d) = c.to_digit(10) {
                    if promoted || d == 0 {
                        return Err(Error::invalid("bad empty-square count in SFEN"));
                    }
                    file = file.checked_sub(d as usize).ok_or_else(|| Error::invalid("SFEN rank too wide"))?;
                    continue;
                }
                let kind = Kind::from_letter(c).ok_or_else(|| Error::invalid(format!("bad piece {c:?} in SFEN")))?;
                if promoted && !kind.can_promote() {
                    return Err(Error::invalid("gold and king cannot be promoted"));
                }
                if file == 0 {
                    return Err(Error::invalid("SFEN rank too wide"));
                }
                let color = if c.is_ascii_uppercase() { Color::Black } else { Color::White };
                pos.board[(file - 1) * 9 + rank] = Some(Piece::new(kind, color, promoted));
                file -= 1;
                promoted = false;
            }
            if file != 0 || promoted {
                return Err(Error::invalid("SFEN rank must cover nine files"));
            }
        }
        if fields[2] != "-" {
            let mut count: Option<u32> = None;
            for c in fields[2].chars() {
                if let Some(d) = c.to_digit(10) {
                    if count.is_none() && d == 0 {
                        return Err(Error::invalid("hand count with a leading zero"));
                    }
                    let n = count.unwrap_or(0).checked_mul(10).and_then(|n| n.checked_add(d));
                    count = Some(n.ok_or_else(|| Error::invalid("hand count too large"))?);
                    continue;
                }
                let kind = Kind::from_letter(c).filter(|k| *k != Kind::King).ok_or_else(|| Error::invalid(format!("bad hand piece {c:?}")))?;
                let color = if c.is_ascii_uppercase() { Color::Black } else { Color::White };
                let slot = &mut pos.hands[color.index()][kind as usize];
                if *slot != 0 {
                    return Err(Error::invalid("a hand piece is listed twice"));
                }
                let n = count.take().unwrap_or(1);
                if n == 0 {
                    return Err(Error::invalid("hand count 0"));
                }
                *slot = n;
            }
            if count.is_some() {
                return Err(Error::invalid("hand count without a piece"));
            }
        }
        let ply = match fields.get(3) {
            None => None,
            Some(n) => Some(n.parse::<u32>().map_err(|_| Error::invalid(format!("bad move number {n:?}")))?),
        };
        Ok((pos, ply))
    }

    /// Parse a canonical SFEN (§6.5): exactly three fields in canonical form.
    pub fn from_sfen(text: &str) -> Result<Position> {
        let (pos, ply) = Position::parse_sfen(text)?;
        if ply.is_some() || pos.to_sfen() != text {
            return Err(Error::invalid(format!("not a canonical SFEN: {text:?}")));
        }
        Ok(pos)
    }

    /// The canonical SFEN (§6.5).
    pub fn to_sfen(&self) -> String {
        let mut s = String::with_capacity(96);
        for rank in 0..9 {
            if rank > 0 {
                s.push('/');
            }
            let mut empty = 0;
            for file in (0..9).rev() {
                match self.board[file * 9 + rank] {
                    None => empty += 1,
                    Some(p) => {
                        if empty > 0 {
                            s.push(char::from(b'0' + empty));
                            empty = 0;
                        }
                        if p.promoted {
                            s.push('+');
                        }
                        let l = p.kind.letter();
                        s.push(if p.color == Color::Black { l } else { l.to_ascii_lowercase() });
                    }
                }
            }
            if empty > 0 {
                s.push(char::from(b'0' + empty));
            }
        }
        s.push_str(if self.side == Color::Black { " b " } else { " w " });
        let mut any = false;
        for color in [Color::Black, Color::White] {
            for kind in [Kind::Rook, Kind::Bishop, Kind::Gold, Kind::Silver, Kind::Knight, Kind::Lance, Kind::Pawn] {
                let n = self.hands[color.index()][kind as usize];
                if n == 0 {
                    continue;
                }
                any = true;
                if n > 1 {
                    s.push_str(&n.to_string());
                }
                let l = kind.letter();
                s.push(if color == Color::Black { l } else { l.to_ascii_lowercase() });
            }
        }
        if !any {
            s.push('-');
        }
        s
    }

    /// Squares of `color`'s kings on the board.
    pub fn kings(&self, color: Color) -> impl Iterator<Item = usize> + '_ {
        (0..81).filter(move |&sq| matches!(self.board[sq], Some(p) if p.kind == Kind::King && p.color == color))
    }

    /// Count of each hand kind on the board and in both hands (promoted pieces counted as
    /// their base kind), and the number of kings per colour.
    fn material(&self) -> ([u64; 7], [u32; 2]) {
        let mut m = [0u64; 7];
        let mut kings = [0u32; 2];
        for p in self.board.iter().flatten() {
            if p.kind == Kind::King {
                kings[p.color.index()] += 1;
            } else {
                m[p.kind as usize] += 1;
            }
        }
        for hand in &self.hands {
            for (k, &n) in hand.iter().enumerate() {
                m[k] += u64::from(n);
            }
        }
        (m, kings)
    }

    /// Encode as CPE when the position is a normal position, else as its canonical SFEN.
    pub fn encode(&self) -> Encoded {
        match cpe_encode(self) {
            Some((c, _)) => Encoded::Cpe(c),
            None => Encoded::Sfen(self.to_sfen()),
        }
    }

    pub fn key(&self) -> u64 {
        self.encode().key()
    }

    pub fn is_normal(&self) -> bool {
        cpe_encode(self).is_some()
    }

    /// Length of the CPE before padding, in bits; `None` for extended positions.
    pub fn cpe_bits(&self) -> Option<usize> {
        cpe_encode(self).map(|(_, n)| n)
    }

    /// Decode a CPE; positions that are not normal and non-zero padding are corrupt (§6.3).
    pub fn from_cpe(cpe: &[u8; 32]) -> Result<Position> {
        cpe_decode(cpe).ok_or_else(|| Error::corrupt("invalid CPE"))
    }
}

// ---------------------------------------------------------------- CPE

struct BitWriter {
    bytes: [u8; 32],
    len: usize,
}

impl BitWriter {
    fn push(&mut self, value: u32, bits: usize) -> Option<()> {
        for i in (0..bits).rev() {
            if self.len >= 256 {
                return None;
            }
            if (value >> i) & 1 == 1 {
                self.bytes[self.len / 8] |= 0x80 >> (self.len % 8);
            }
            self.len += 1;
        }
        Some(())
    }
}

struct BitReader<'a> {
    bytes: &'a [u8; 32],
    pos: usize,
}

impl BitReader<'_> {
    fn bit(&mut self) -> Option<u32> {
        if self.pos >= 256 {
            return None;
        }
        let b = (self.bytes[self.pos / 8] >> (7 - self.pos % 8)) & 1;
        self.pos += 1;
        Some(u32::from(b))
    }

    fn bits(&mut self, n: usize) -> Option<u32> {
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Some(v)
    }
}

/// Huffman code of a board piece kind (§6.3 step 4), as (bits, length).
fn kind_code(kind: Kind) -> (u32, usize) {
    match kind {
        Kind::Pawn => (0b0, 1),
        Kind::Lance => (0b100, 3),
        Kind::Knight => (0b101, 3),
        Kind::Silver => (0b110, 3),
        Kind::Gold => (0b1110, 4),
        Kind::Bishop => (0b11110, 5),
        Kind::Rook => (0b11111, 5),
        Kind::King => (0, 0),
    }
}

const OFF_BOARD_ORDER: [Kind; 7] = [Kind::Rook, Kind::Bishop, Kind::Gold, Kind::Silver, Kind::Knight, Kind::Lance, Kind::Pawn];

fn cpe_encode(pos: &Position) -> Option<([u8; 32], usize)> {
    let (material, kings) = pos.material();
    if material.iter().zip(Kind::STANDARD).any(|(&n, s)| n > u64::from(s)) || kings.iter().any(|&k| k > 1) {
        return None;
    }
    let king_sq = |c: Color| pos.kings(c).next();
    let (bk, wk) = (king_sq(Color::Black), king_sq(Color::White));
    let mut w = BitWriter { bytes: [0; 32], len: 0 };
    w.push(pos.side as u32, 1)?;
    w.push(bk.map_or(127, |s| s as u32), 7)?;
    w.push(wk.map_or(127, |s| s as u32), 7)?;
    let mut on_board = [0u32; 7];
    for sq in 0..81 {
        if Some(sq) == bk || Some(sq) == wk {
            continue;
        }
        match pos.board[sq] {
            None => w.push(0, 1)?,
            Some(p) => {
                on_board[p.kind as usize] += 1;
                let (code, len) = kind_code(p.kind);
                w.push(1, 1)?;
                w.push(code, len)?;
                w.push(p.color as u32, 1)?;
                if p.kind != Kind::Gold {
                    w.push(u32::from(p.promoted), 1)?;
                }
            }
        }
    }
    for kind in OFF_BOARD_ORDER {
        let k = kind as usize;
        let off = Kind::STANDARD[k] - on_board[k];
        let (b, wh) = (pos.hands[0][k], pos.hands[1][k]);
        // material ≤ standard was checked above, so b + wh ≤ off.
        for _ in 0..b {
            w.push(0b0, 1)?;
        }
        for _ in 0..wh {
            w.push(0b10, 2)?;
        }
        for _ in 0..off - b - wh {
            w.push(0b11, 2)?;
        }
    }
    Some((w.bytes, w.len))
}

fn cpe_decode(cpe: &[u8; 32]) -> Option<Position> {
    let mut r = BitReader { bytes: cpe, pos: 0 };
    let side = if r.bit()? == 0 { Color::Black } else { Color::White };
    let mut pos = Position::empty(side);
    let bk = r.bits(7)? as usize;
    let wk = r.bits(7)? as usize;
    for (sq, color) in [(bk, Color::Black), (wk, Color::White)] {
        if sq == 127 {
            continue;
        }
        if sq > 80 || pos.board[sq].is_some() {
            return None;
        }
        pos.board[sq] = Some(Piece::new(Kind::King, color, false));
    }
    let mut on_board = [0u32; 7];
    for sq in 0..81 {
        if sq == bk || sq == wk {
            continue;
        }
        if r.bit()? == 0 {
            continue;
        }
        let kind = if r.bit()? == 0 {
            Kind::Pawn
        } else {
            match r.bits(2)? {
                0b00 => Kind::Lance,
                0b01 => Kind::Knight,
                0b10 => Kind::Silver,
                _ => {
                    if r.bit()? == 0 {
                        Kind::Gold
                    } else if r.bit()? == 0 {
                        Kind::Bishop
                    } else {
                        Kind::Rook
                    }
                }
            }
        };
        let color = if r.bit()? == 0 { Color::Black } else { Color::White };
        let promoted = kind != Kind::Gold && r.bit()? == 1;
        on_board[kind as usize] += 1;
        if on_board[kind as usize] > Kind::STANDARD[kind as usize] {
            return None;
        }
        pos.board[sq] = Some(Piece::new(kind, color, promoted));
    }
    for kind in OFF_BOARD_ORDER {
        let k = kind as usize;
        let mut stage = 0; // 0 black hand, 1 white hand, 2 box: codes must not go back.
        for _ in 0..Kind::STANDARD[k] - on_board[k] {
            let here = if r.bit()? == 0 {
                0
            } else if r.bit()? == 0 {
                1
            } else {
                2
            };
            if here < stage {
                return None;
            }
            stage = here;
            if here < 2 {
                pos.hands[here][k] += 1;
            }
        }
    }
    while r.pos < 256 {
        if r.bit()? != 0 {
            return None;
        }
    }
    // Normal-position conditions 1 and 2 hold by construction; condition 3 (length) too.
    // Re-encoding must reproduce the same bytes (rejects out-of-order location codes).
    (cpe_encode(&pos)?.0 == *cpe).then_some(pos)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect()
    }

    /// §6.6 test vectors.
    #[test]
    fn test_vectors() {
        let cases = [
            (STARTPOS, "2C49928430DBEA847E69D28438F5421E2843D50879D28438DBFA847C69928430", 0x432E1985F9D16B57u64),
            (
                "lnsgkgsnl/1r5b1/ppppppppp/9/9/2P6/PP1PPPPPP/1B5R1/LNSGKGSNL w -",
                "AC49928430DBEA847E69D28438F5421E2843D50879D28838DBFA847C69928430",
                0x7EE23BD9344BE9CC,
            ),
            (
                "lnsgkgsnl/1r5+B1/pppppp1pp/6p2/9/2P6/PP1PPPPPP/7R1/LNSGKGSNL w B",
                "AC49928430DBE6847E69D14438F5421E2843D50879D28838DBFA8434C9421800",
                0xCE452F36A627AC9B,
            ),
            (
                "lnsgkg1nl/1r5s1/pppppp1pp/6p2/9/2P6/PP1PPPPPP/7R1/LNSGKGSNL b Bb",
                "2C49928430DBAA11F9A0A21C7AA10F1421EA843CE9441C6DFD421A64A10C1000",
                0x80AA016EA782DFD8,
            ),
            (
                "lnsgkgsn1/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL w -",
                "AC4850861B7D508FCD3A50871EA843C5087AA10F3A50871B7F508F8D32508618",
                0x82EC8DF27390E37A,
            ),
            (
                "8k/9/8P/9/9/9/9/9/9 b G2r2b3g4s4n4l17p",
                concat!("7F00800000000000000000002A955555", "55555555554000000000000000000000"),
                0xE5C8B0643E0DEE19,
            ),
        ];
        let bits = [256, 256, 250, 245, 253, 171];
        for ((sfen, cpe, key), bits) in cases.into_iter().zip(bits) {
            let pos = Position::from_sfen(sfen).unwrap();
            assert_eq!(pos.cpe_bits(), Some(bits), "{sfen}");
            let enc = pos.encode();
            let Encoded::Cpe(bytes) = &enc else { panic!("{sfen} must be normal") };
            assert_eq!(hex(bytes), cpe, "{sfen}");
            assert_eq!(enc.key(), key, "{sfen}");
            assert_eq!(Position::from_cpe(bytes).unwrap(), pos);
        }
        for ext in [
            "lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSG1GSNL b -",
            "lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b P",
        ] {
            assert!(Position::from_sfen(ext).unwrap().encode().is_extended(), "{ext}");
        }
    }

    #[test]
    fn canonical_sfen() {
        assert!(Position::from_sfen("lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b - 1").is_err());
        assert!(Position::from_sfen("8k/9/8P/9/9/9/9/9/9 b 2rG").is_err());
        assert!(Position::from_sfen("8k/9/8P/9/9/9/9/9/9 b 1G").is_err());
        assert!(Position::from_sfen("8k/9/8P/9/9/9/9/9/9 b G").is_ok());
        assert!(Position::from_sfen("4+G4/9/9/9/9/9/9/9/9 b -").is_err());
        let (p, n) = Position::parse_sfen("lnsgkgsnl/1r5b1/ppppppppp/9/9/9/PPPPPPPPP/1B5R1/LNSGKGSNL b - 7").unwrap();
        assert_eq!((p.to_sfen().as_str(), n), (STARTPOS, Some(7)));
    }

    #[test]
    fn corrupt_cpe_is_rejected() {
        let Encoded::Cpe(mut c) = Position::startpos().encode() else { panic!() };
        c[0] ^= 0x01; // a king square bit
        let _ = Position::from_cpe(&c); // must not panic
        let Encoded::Cpe(mut d) = Position::from_sfen("8k/9/8P/9/9/9/9/9/9 b G2r2b3g4s4n4l17p").unwrap().encode() else { panic!() };
        d[31] = 1; // padding
        assert!(Position::from_cpe(&d).is_err());
        assert!(Position::from_cpe(&[0xFF; 32]).is_err());
    }
}
