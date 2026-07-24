# 5. Lenient, fail-soft, evidence-preserving parsing

Date: 2026-07-24
Status: Accepted

## Context

Forensic input is truncated, corrupt, and sometimes adversarial. A parser that
aborts the whole list on the first bad byte throws away the recoverable prefix;
one that silently drops an unrecognised item destroys the very evidence an
examiner needs. The fleet robustness rules require degrading at the point of
damage and *showing the unrecognised value* rather than hiding it.

## Decision

1. **Stop cleanly at damage, keep what parsed.** `parse_idlist` returns the
   items decoded so far when it hits the terminator, a `cb < 3` that cannot hold
   a class byte, or a `cb` that would overrun the buffer — it never panics and
   never discards the good prefix (`src/parse.rs:18-36`).
2. **Always retain the raw bytes.** Every `ShellItem` keeps its full raw bytes
   including the 2-byte `cb` prefix (`src/lib.rs:120-121`, `ShellItem::raw`), so
   a consumer can re-inspect or surface the class byte.
3. **Preserve the unrecognised value.** An unknown or not-yet-decoded class maps
   to `ShellItemKind::Unknown` with the raw bytes intact — nothing is silently
   dropped (`src/lib.rs:76-79`, `src/parse.rs:88-95`).
4. **Locate the `0xbeef0004` extension tolerantly.** The block is accepted only
   when its signature validates, and if the computed start is slightly off (name
   padding/alignment drift) it is found by scanning for the signature rather than
   trusting a rigid offset (`src/parse.rs:146-155`, `locate_beef0004`).
5. **A malformed field yields `None`, never a fabricated value.** A FAT date of
   `0` or an out-of-range month/day returns `None` (`src/dosdate.rs:24-41`);
   UTF-16 decodes lossily to U+FFFD rather than dropping code units
   (`src/reader.rs:60-79`).

## Consequences

- Robust against real-world drift and hostile blobs; the recoverable portion of
  a damaged list is always returned.
- Because raw bytes are retained, a consumer can re-examine an `Unknown` item or
  cross-check a decoded field against the original bytes — no information is lost
  in the decode.
- No fabricated timestamps or names enter the evidence chain; absence is
  represented as `None`, distinct from a decoded value.
