# spg — SPG (Shogi Position Graph) v1.0 reference implementation

SPG stores game records and opening books as one **position graph**: positions keyed by a
256-bit canonical encoding (CPE) and an XXH3 key, move edges with evaluations, weights and
statistics, game records as trees over that graph, typed annotations, analyses, rights and
provenance. The specification, frozen on 2026-11-06, is in [spec/SPG-v1.0.md](spec/SPG-v1.0.md)
(Japanese; the typeset PDF sits next to it). This crate implements the whole of v1.0:

| Spec | Module | What |
|---|---|---|
| §6.1–6.6 | `position` | positions, canonical SFEN, CPE encode/decode, position keys, test vectors |
| §6.2, §6.7 | `moves` | Move16, legality (kingless sides, drop-pawn mate, extended positions) |
| §8.1 | `eval` | EVAL values, units, mate values, viewpoint flips |
| §5, §9.1 | `model` | the logical data shared by `.spg` and `.spgt` |
| §7, §11.1–11.3, §11.6 | `write`, `read`, `container` | the binary container: all 21 sections, preludes, directory and tail copies, CSUM blocks, full verification |
| §7.15, §11.4 | `lookup` | engine-side probing (KBKT → PKEY → CPE) with per-block checks and re-verification before a move is played |
| §9 | `text` | `.spgt` lexer, parser and canonical writer |
| §7.28, §11.6–11.8 | `manifest` | `.spgm` file sets (s = 0 or 8), `.spgm.bak` fallback, update procedure, BLK3, Ed25519 signatures |
| §13.2 | `validate` | the writer requirements and invariants |

The crate knows nothing about other shogi formats. Conversions to and from KIF/CSA/JKF,
YaneuraOu `.db`, ShogiGUI `.sbk` and Gikou books live in `sakiyomi-spg`
([crates/spg-convert](https://github.com/ikuto32/sakiyomi/tree/main/crates/spg-convert) of the
[Sakiyomi](https://github.com/ikuto32/sakiyomi) shogi GUI, which uses SPG as its standard format),
following §10.

## Use

```rust
let (data, info) = spg::read(&bytes, &spg::ReadOptions::default())?;   // full verification
let (bytes, _) = spg::write(&data, &spg::WriteOptions::default())?;   // validates first
let text = spg::text::write(&data)?;                                   // canonical .spgt
let book = spg::lookup::Book::open(&bytes)?;                           // engine probing
if let Some(k) = book.find(&position)? { let edges = book.edges(k)?; }
```

Command line (`sakiyomi-tool`, part of [Sakiyomi](https://github.com/ikuto32/sakiyomi)):

```
sakiyomi-tool spg verify book.spg
sakiyomi-tool spg convert book.spg -o book.spgt
sakiyomi-tool spg convert book.spgt -o set/book.spgm --split --sign-key key.bin
sakiyomi-tool spg info book.spg
sakiyomi-tool spg probe book.spg "lnsgkgsnl/1r5b1/ppppppppp/9/9/2P6/PP1PPPPPP/1B5R1/LNSGKGSNL w -"
sakiyomi-tool book convert user_book1.db -o book.spg
sakiyomi-tool kifu convert games/*.kif --to spg --out-dir out
```

## Reading is verification

`spg::read` performs every check a verification tool must (§13.1): magic, version, length,
kind and required sections; preludes; directory hash (falling back to the tail copies,
§11.6); every CSUM block and section hash; reserved fields and flag/field agreement; every
reference range-checked before use (§11.8); CPE decoding and key agreement; position order
and uniqueness; KBKT, PKEY, child links and OCCR against the data they derive from; record
trees; annotation and analysis order; and, unless turned off, the legality of every move.
Malformed input is reported as `Rejected` or `Corrupt`, never a panic; decoding is
bounded by an expansion budget so repeated references cannot exhaust memory.

`lookup::Book` is the engine path: opening is O(1) besides the directory and CSUM tables,
and only the blocks a probe touches are hashed.

## Tests

* `position::tests::test_vectors` — the §6.6 vectors (CPE bytes and keys) and the two
  extended-position cases.
* `moves` — perft from the initial position (30 / 900 / 25 470) and the 207-move position
  (207 / 28 684); `sakiyomi-spg` cross-checks every legal move set against shogi-core's
  independent generator on random games.
* `tests/conformance.rs` (appendix C) — binary and text round trips (`write∘read∘write` is
  the identity; canonical text is a fixed point), the §9.6 example, compact edges and what
  they drop, records-only files, every-bit-flip detection with repair from the tail copy,
  CSUM blocks and BLK3, lookups and damaged blocks, unknown and required unknown sections,
  newer major versions, writer refusals, sharded and signed sets with `.bak` fallback and
  tampering, key ranges, and a fuzz loop (`SAKIYOMI_FUZZ_ROUNDS`, default 2000).

Real data: tanuki's 207 146-position `user_book1.db` converts to `.spg` and back
byte-identically, and `.spg → .spgt → .spg` and `.spg → .spgm (256 shards, signed) →
.spgt` give identical text.

## Implementation notes

[SPEC-NOTES.md](SPEC-NOTES.md) (in Japanese) lists the errata reported against the draft and
resolved in the final text, the rules that became normative there and how this crate follows
them, and the choices made where v1.0 leaves room.

## License

- The reference implementation (everything outside `spec/`): [MIT](LICENSE).
- The specification (`spec/SPG-v1.0.md`, `spec/SPG-v1.0.pdf`): [CC BY 4.0](spec/LICENSE),
  © 2026 @ikuto.
