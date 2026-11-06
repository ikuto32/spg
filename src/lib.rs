//! Reference implementation of **SPG (Shogi Position Graph) v1.0**: game records and
//! opening books as one position graph.
//!
//! * [`position`]: positions, canonical SFEN, CPE and position keys (§6.1–6.6)
//! * [`moves`]: Move16 and move legality (§6.2, §6.7)
//! * [`eval`]: EVAL values (§8.1)
//! * [`model`]: the logical data shared by `.spg` and `.spgt` (§5, §9.1)
//! * [`write`] / [`read`]: the binary container (§7, §11)
//! * [`lookup`]: engine-side probing without decoding the file (§7.15, §11.3, §11.4)
//! * [`text`]: the `.spgt` text form (§9)
//! * [`manifest`]: sharded file sets, `.spgm`, BLK3 and signatures (§7.28, §11.6–11.8)
//! * [`validate`]: the writer requirements and invariants (§13.2)
//!
//! The crate has no knowledge of other shogi formats; conversions live elsewhere.

pub mod container;
pub mod error;
pub mod eval;
mod hash;
pub mod layout;
pub mod lookup;
pub mod manifest;
pub mod model;
pub mod moves;
pub mod position;
pub mod read;
pub mod text;
pub mod validate;
pub mod write;

pub use error::{Error, Result};
pub use model::*;
pub use moves::Move;
pub use position::{Color, Encoded, Kind, Piece, Position};
pub use read::{ReadInfo, ReadOptions};
pub use write::{EdgeForm, WriteOptions, WriteReport};

/// Read `.spg` bytes (a single file or a records-only file).
pub fn read(bytes: &[u8], opts: &ReadOptions) -> Result<(Spg, ReadInfo)> {
    read::read(bytes, opts)
}

/// Write one `.spg` file.
pub fn write(spg: &Spg, opts: &WriteOptions) -> Result<(Vec<u8>, WriteReport)> {
    write::write(spg, opts)
}

/// Whether `bytes` start like an `.spg` file, an `.spgm` manifest or `.spgt` text.
pub fn sniff(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&layout::MAGIC) {
        Some("spg")
    } else if bytes.starts_with(&layout::MANIFEST_MAGIC) {
        Some("spgm")
    } else if bytes.starts_with(b"SPG-TEXT ") {
        Some("spgt")
    } else {
        None
    }
}
