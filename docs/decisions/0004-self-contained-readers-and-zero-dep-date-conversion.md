# 4. Self-contained bounds-checked readers and zero-dependency FAT date conversion

Date: 2026-07-24
Status: Accepted

## Context

Decoding a shell item needs several byte-level primitives:

- fixed-width little-endian integers (`u16` `cb`, `u32` size/date);
- a **48-bit** little-endian read for the NTFS MFT entry index in the
  `0xbeef0004` file reference;
- NUL-terminated ASCII and UTF-16LE string decoding;
- a **mixed-endian** Microsoft GUID formatter (first three groups LE, last two
  BE);
- FAT (MS-DOS) packed date/time → Unix epoch seconds.

The fleet standard says fixed-width integer field reads should route through the
shared, audited `safe-read` crate and a per-crate `bytes.rs` should not be
hand-rolled. But `safe-read` covers **fixed-width integer fields only** — it does
not provide the 48-bit read, the string decoders, the mixed-endian GUID
formatter, or any date math. And the crate deliberately avoids a date library:
`src/dosdate.rs:12-13` states the rationale — "no `chrono`/`time` dependency,
matching the zero-dep posture of a parser primitive."

## Decision

1. Carry a local `src/reader.rs` module with `le_u16`, `le_u32`, `le_u48`,
   `ascii_z`, `utf16_z`, and `guid` — all bounds-checked (out-of-range returns
   `0` / `None`, `src/reader.rs`).
2. Convert FAT date/time in a local `src/dosdate.rs` (`fat_to_epoch`) with hand
   Gregorian-calendar arithmetic and no external date crate
   (`src/dosdate.rs:24-59`); a `0` value or an out-of-range packed field yields
   `None`, never a bogus timestamp.
3. The crate's only runtime dependency stays `forensicnomicon` (ADR 0002).

## Consequences

- Zero runtime dependencies beyond the KNOWLEDGE leaf — a small, portable,
  low-MSRV primitive.
- The 48-bit read, string decoders, GUID formatter, and date math are
  legitimately outside `safe-read`'s scope, so a local module for *those* is
  warranted.
- **Deviation, honestly flagged:** the fixed-width `le_u16`/`le_u32` helpers
  duplicate what `safe-read` already provides and would ordinarily route through
  it. Rationale reconstructed from structure; original intent not recovered in
  available history — the git log shows no consideration of `safe-read`. Worth
  revisiting: migrate the two fixed-width integer readers onto `safe-read` and
  keep only the genuinely-uncovered helpers local.
