//! Moves (§6.2) and move legality (§6.7).

use std::fmt;

use crate::error::{Error, Result};
use crate::position::{Color, Kind, Piece, Position};

/// A Move16 (§6.2): bits 0–6 destination, 7–13 source (81 + kind code for drops),
/// 14 promotion, 15 reserved. `0x0000` means "no move".
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Move(pub u16);

impl fmt::Debug for Move {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_valid() { write!(f, "Move({})", self.to_usi()) } else { write!(f, "Move({:#06x})", self.0) }
    }
}

impl Move {
    pub const NONE: Move = Move(0);

    pub fn board(from: u8, to: u8, promote: bool) -> Move {
        Move(u16::from(to) | (u16::from(from) << 7) | if promote { 1 << 14 } else { 0 })
    }

    pub fn drop(kind: Kind, to: u8) -> Move {
        Move(u16::from(to) | ((81 + u16::from(kind.code())) << 7))
    }

    pub fn to(self) -> usize {
        usize::from(self.0 & 0x7F)
    }

    pub fn from_field(self) -> usize {
        usize::from((self.0 >> 7) & 0x7F)
    }

    /// The source square of a board move.
    pub fn source(self) -> Option<usize> {
        let f = self.from_field();
        (f <= 80).then_some(f)
    }

    /// The kind of a drop.
    pub fn drop_kind(self) -> Option<Kind> {
        let f = self.from_field();
        if f >= 81 { Kind::from_code((f - 81) as u8) } else { None }
    }

    pub fn promotes(self) -> bool {
        self.0 & (1 << 14) != 0
    }

    /// The structural conditions of §6.2 (and not `0x0000`).
    pub fn is_valid(self) -> bool {
        let (to, from) = (self.to(), self.from_field());
        self.0 != 0 && self.0 & 0x8000 == 0 && to <= 80 && from <= 87 && (if from <= 80 { from != to } else { !self.promotes() })
    }

    pub fn to_usi(self) -> String {
        let sq = |s: usize| format!("{}{}", s / 9 + 1, char::from(b'a' + (s % 9) as u8));
        match self.drop_kind() {
            Some(k) => format!("{}*{}", k.usi_letter(), sq(self.to())),
            None => format!("{}{}{}", sq(self.from_field()), sq(self.to()), if self.promotes() { "+" } else { "" }),
        }
    }

    pub fn from_usi(s: &str) -> Result<Move> {
        let b = s.as_bytes();
        let sq = |f: u8, r: u8| -> Option<u8> { ((b'1'..=b'9').contains(&f) && (b'a'..=b'i').contains(&r)).then(|| (f - b'1') * 9 + (r - b'a')) };
        let bad = || Error::invalid(format!("bad USI move {s:?}"));
        let m = if b.len() == 4 && b[1] == b'*' {
            let kind = Kind::from_usi_letter(char::from(b[0])).filter(|k| *k != Kind::King).ok_or_else(bad)?;
            Move::drop(kind, sq(b[2], b[3]).ok_or_else(bad)?)
        } else if b.len() == 4 || (b.len() == 5 && b[4] == b'+') {
            Move::board(sq(b[0], b[1]).ok_or_else(bad)?, sq(b[2], b[3]).ok_or_else(bad)?, b.len() == 5)
        } else {
            return Err(bad());
        };
        if m.is_valid() { Ok(m) } else { Err(bad()) }
    }
}

// ---------------------------------------------------------------- rules (§6.7)

fn forward(c: Color) -> i32 {
    if c == Color::Black { -1 } else { 1 }
}

/// Rank index 0..8 counted from the colour's own far side: 0 is the last rank ahead.
fn rank_ahead(c: Color, rank: usize) -> usize {
    if c == Color::Black { rank } else { 8 - rank }
}

fn in_zone(c: Color, sq: usize) -> bool {
    rank_ahead(c, sq % 9) <= 2
}

/// A piece of this kind could not move again from `to` without promoting.
fn dead_end(kind: Kind, promoted: bool, c: Color, to: usize) -> bool {
    let r = rank_ahead(c, to % 9);
    !promoted && match kind {
        Kind::Pawn | Kind::Lance => r == 0,
        Kind::Knight => r <= 1,
        _ => false,
    }
}

const KING_STEPS: [(i32, i32); 8] = [(-1, -1), (0, -1), (1, -1), (-1, 0), (1, 0), (-1, 1), (0, 1), (1, 1)];
const DIAGONALS: [(i32, i32); 4] = [(-1, -1), (1, -1), (-1, 1), (1, 1)];
const ORTHOGONALS: [(i32, i32); 4] = [(0, -1), (-1, 0), (1, 0), (0, 1)];

type Dirs = &'static [(i32, i32)];

/// (step offsets, slide directions) in (file, rank) deltas, for a piece. Black moves
/// towards rank 1 (decreasing rank index).
fn movement(p: Piece) -> (Dirs, Dirs) {
    const NONE: Dirs = &[];
    let black = p.color == Color::Black;
    let pick = |b: Dirs, w: Dirs| if black { b } else { w };
    match (p.kind, p.promoted) {
        (Kind::Pawn, false) => (pick(&[(0, -1)], &[(0, 1)]), NONE),
        (Kind::Lance, false) => (NONE, pick(&[(0, -1)], &[(0, 1)])),
        (Kind::Knight, false) => (pick(&[(-1, -2), (1, -2)], &[(-1, 2), (1, 2)]), NONE),
        (Kind::Silver, false) => (pick(&[(-1, -1), (0, -1), (1, -1), (-1, 1), (1, 1)], &[(-1, 1), (0, 1), (1, 1), (-1, -1), (1, -1)]), NONE),
        (Kind::Gold, _) | (Kind::Pawn | Kind::Lance | Kind::Knight | Kind::Silver, true) => {
            (pick(&[(-1, -1), (0, -1), (1, -1), (-1, 0), (1, 0), (0, 1)], &[(-1, 1), (0, 1), (1, 1), (-1, 0), (1, 0), (0, -1)]), NONE)
        }
        (Kind::King, _) => (&KING_STEPS, NONE),
        (Kind::Bishop, false) => (NONE, &DIAGONALS),
        (Kind::Rook, false) => (NONE, &ORTHOGONALS),
        (Kind::Bishop, true) => (&ORTHOGONALS, &DIAGONALS),
        (Kind::Rook, true) => (&DIAGONALS, &ORTHOGONALS),
    }
}

fn offset(sq: usize, (df, dr): (i32, i32)) -> Option<usize> {
    let file = (sq / 9) as i32 + df;
    let rank = (sq % 9) as i32 + dr;
    ((0..9).contains(&file) && (0..9).contains(&rank)).then_some((file * 9 + rank) as usize)
}

impl Position {
    /// Squares the piece on `from` attacks (moves to, ignoring what stands on the target).
    fn attacks_from(&self, from: usize, p: Piece) -> Vec<usize> {
        let (steps, slides) = movement(p);
        let mut out: Vec<usize> = steps.iter().filter_map(|&d| offset(from, d)).collect();
        for &d in slides {
            let mut sq = from;
            while let Some(n) = offset(sq, d) {
                out.push(n);
                if self.board[n].is_some() {
                    break;
                }
                sq = n;
            }
        }
        out
    }

    /// Whether `by` attacks `target`: look outwards from the target along the eight lines
    /// and at the two knight squares.
    pub fn attacked(&self, target: usize, by: Color) -> bool {
        for &(df, dr) in &KING_STEPS {
            let mut sq = target;
            let mut dist = 0;
            while let Some(n) = offset(sq, (df, dr)) {
                dist += 1;
                if let Some(p) = self.board[n] {
                    if p.color == by {
                        let back = (-df, -dr);
                        let (steps, slides) = movement(p);
                        if (dist == 1 && steps.contains(&back)) || slides.contains(&back) {
                            return true;
                        }
                    }
                    break;
                }
                sq = n;
            }
        }
        let f = forward(by);
        [(-1, -2 * f), (1, -2 * f)].iter().any(|&d| {
            offset(target, d).and_then(|s| self.board[s]).is_some_and(|p| p.color == by && p.kind == Kind::Knight && !p.promoted)
        })
    }

    /// Whether any king of `color` is attacked.
    pub fn in_check(&self, color: Color) -> bool {
        self.kings(color).any(|k| self.attacked(k, color.opponent()))
    }

    /// Moves satisfying conditions 1 and 2 of §6.7. Capturing a king is excluded: the
    /// resulting position would hold a king in hand, which no position can represent.
    fn pseudo_moves(&self) -> Vec<Move> {
        let me = self.side;
        let mut moves = Vec::with_capacity(128);
        for from in 0..81 {
            let Some(p) = self.board[from] else { continue };
            if p.color != me {
                continue;
            }
            for to in self.attacks_from(from, p) {
                match self.board[to] {
                    Some(q) if q.color == me || q.kind == Kind::King => continue,
                    _ => {}
                }
                if p.kind.can_promote() && !p.promoted && (in_zone(me, from) || in_zone(me, to)) {
                    moves.push(Move::board(from as u8, to as u8, true));
                }
                if !dead_end(p.kind, p.promoted, me, to) {
                    moves.push(Move::board(from as u8, to as u8, false));
                }
            }
        }
        let pawn_files: Vec<bool> = (0..9)
            .map(|file| (0..9).any(|r| matches!(self.board[file * 9 + r], Some(p) if p.color == me && p.kind == Kind::Pawn && !p.promoted)))
            .collect();
        for kind in Kind::HAND {
            if self.hands[me.index()][kind as usize] == 0 {
                continue;
            }
            for to in 0..81 {
                if self.board[to].is_some() || dead_end(kind, false, me, to) || (kind == Kind::Pawn && pawn_files[to / 9]) {
                    continue;
                }
                moves.push(Move::drop(kind, to as u8));
            }
        }
        moves
    }

    /// Apply a move that satisfies conditions 1–2 of §6.7 (no further checks).
    pub fn play_unchecked(&self, m: Move) -> Position {
        let mut next = self.clone();
        let me = self.side;
        let to = m.to();
        if let Some(kind) = m.drop_kind() {
            let n = &mut next.hands[me.index()][kind as usize];
            *n = n.saturating_sub(1);
            next.board[to] = Some(Piece::new(kind, me, false));
        } else if let Some(from) = m.source()
            && let Some(p) = next.board[from].take()
        {
            if let Some(captured) = next.board[to]
                && captured.kind != Kind::King
            {
                let n = &mut next.hands[me.index()][captured.kind as usize];
                *n = n.saturating_add(1);
            }
            next.board[to] = Some(Piece::new(p.kind, p.color, p.promoted || m.promotes()));
        }
        next.side = me.opponent();
        next
    }

    fn legal_moves_with(&self, check_drop_mate: bool) -> Vec<Move> {
        let me = self.side;
        let them = me.opponent();
        self.pseudo_moves()
            .into_iter()
            .filter(|&m| {
                let child = self.play_unchecked(m);
                if child.in_check(me) {
                    return false;
                }
                if check_drop_mate && m.drop_kind() == Some(Kind::Pawn) {
                    let gives_check = child.kings(them).any(|k| child.attacked(k, me));
                    // Drops can never answer a pawn's contact check, so the replies can be
                    // generated without the drop-mate rule (no recursion).
                    if gives_check && child.legal_moves_with(false).is_empty() {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// All legal moves (§6.7). Rules about a king that is not on the board do not apply.
    pub fn legal_moves(&self) -> Vec<Move> {
        self.legal_moves_with(true)
    }

    /// Whether `m` is legal here (§6.7).
    pub fn is_legal(&self, m: Move) -> bool {
        m.is_valid() && self.legal_moves().contains(&m)
    }

    /// Apply a legal move.
    pub fn play(&self, m: Move) -> Result<Position> {
        if !self.is_legal(m) {
            return Err(Error::invalid(format!("illegal move {} in {}", m.to_usi(), self.to_sfen())));
        }
        Ok(self.play_unchecked(m))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn perft(p: &Position, d: u32) -> u64 {
        if d == 0 {
            return 1;
        }
        p.legal_moves().iter().map(|&m| perft(&p.play_unchecked(m), d - 1)).sum()
    }

    #[test]
    fn perft_from_start() {
        let p = Position::startpos();
        assert_eq!(perft(&p, 1), 30);
        assert_eq!(perft(&p, 2), 900);
        assert_eq!(perft(&p, 3), 25470);
    }

    #[test]
    fn usi_round_trip_and_structure() {
        for s in ["7g7f", "8h2b+", "P*5e", "G*1a", "R*9i"] {
            assert_eq!(Move::from_usi(s).unwrap().to_usi(), s);
        }
        assert_eq!(Move::from_usi("G*5e").unwrap().from_field(), 85);
        assert!(Move::from_usi("7g7g").is_err());
        assert!(Move::from_usi("K*5e").is_err());
        assert!(!Move(0).is_valid());
        assert!(!Move(0x8000 | Move::from_usi("7g7f").unwrap().0).is_valid());
        assert!(!Move(Move::from_usi("P*5e").unwrap().0 | 1 << 14).is_valid());
    }

    #[test]
    fn kingless_and_drop_mate() {
        // Tsume without the attacker's king: attacker moves are not checked for self-check.
        let p = Position::from_sfen("8k/9/8P/9/9/9/9/9/9 b G2r2b3g4s4n4l17p").unwrap();
        assert!(p.is_legal(Move::from_usi("G*1b").unwrap()));
        // Drop-pawn mate is illegal; the same drop without mate is legal.
        let mate = Position::from_sfen("kn7/9/1G7/9/9/9/9/9/8K b P").unwrap();
        assert!(!mate.is_legal(Move::from_usi("P*9b").unwrap()));
        let escape = Position::from_sfen("k8/9/1G7/9/9/9/9/9/8K b P").unwrap();
        assert!(escape.is_legal(Move::from_usi("P*9b").unwrap()));
        // No king for the defender: the drop-pawn-mate rule does not apply.
        let none = Position::from_sfen("n8/9/1G7/9/9/9/9/9/8K b P").unwrap();
        assert!(none.legal_moves().iter().any(|m| m.drop_kind() == Some(Kind::Pawn)));
    }
}

#[cfg(test)]
mod perft_more {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn perft(p: &Position, d: u32) -> u64 {
        if d == 0 {
            return 1;
        }
        p.legal_moves().iter().map(|&m| perft(&p.play_unchecked(m), d - 1)).sum()
    }

    /// Known perft counts (matching other generators) for a middlegame position.
    #[test]
    fn perft_middlegame() {
        let p = Position::from_sfen("l6nl/5+P1gk/2np1S3/p1p4Pp/3P2Sp1/1PPb2P1P/P5GS1/R8/LN4bKL w RGgsn5p").unwrap();
        assert_eq!(perft(&p, 1), 207);
        assert_eq!(perft(&p, 2), 28684);
    }
}
