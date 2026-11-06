//! Hashes used by the format: XXH3-64 with seed 0 (§6.4, §7.6, §11.2) and BLAKE3 (§11.8).

pub fn xxh3(bytes: &[u8]) -> u64 {
    xxhash_rust::xxh3::xxh3_64(bytes)
}

/// BLAKE3 leaf hash `BLAKE3(0x00 ‖ data)`.
pub fn blake3_leaf(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// BLAKE3 interior node `BLAKE3(0x01 ‖ left ‖ right)`.
pub fn blake3_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Merkle root over the leaves (§11.8): pair left to right, carry an odd last element up.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|c| if c.len() == 2 { blake3_node(&c[0], &c[1]) } else { c[0] }).collect();
    }
    level[0]
}
