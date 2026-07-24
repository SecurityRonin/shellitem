# 1. shellitem is a single-crate decoder primitive, not a reader/analyzer pair

Date: 2026-07-24
Status: Accepted

## Context

A Windows `ITEMIDLIST` (PIDL) is the binary form of a shell-namespace path. The
*same* blob format appears in many artifacts — a `.lnk` file's
`LinkTargetIDList`, registry ShellBags (`BagMRU`) values, jump lists, and the
OpenSave/LastVisited PIDL MRUs (`src/lib.rs:3-16`, `README.md:12`).

The fleet crate-structure standard (`ronin-issen/CLAUDE.md`) defines two shapes:
Pattern A — a single-format container/filesystem repo gets a `<x>-core` reader
plus a `<x>-forensic` analyzer; Pattern B — a multi-crate PARSER suite
decomposes by concern. shellitem fits neither: it is not a container or
filesystem, and it is not an analyzer suite. It is a byte-level **decoding
primitive** shared by several higher-level parsers, exactly like the `lznt1` and
`xpress-huffman` codecs the constitution names as the model for reusable
primitives (`src/lib.rs:12-13` cites that precedent explicitly).

## Decision

1. Ship **one crate**, `shellitem` (`Cargo.toml` `name = "shellitem"`), with a
   **bare, distinctive name** — no `-core`/`-forensic` split. The name is
   self-describing on crates.io and does not collide with a popular third-party
   crate, so the codec-primitive precedent (bare-named single crate) applies
   rather than Pattern A.
2. Emit **no findings**: the public surface is pure typed decode — `ShellItem` /
   `ShellItemKind`, `parse_idlist`, `reconstruct_path` (`src/lib.rs`,
   `src/parse.rs`). The crate deliberately does not depend on
   `forensicnomicon::report` or produce `Finding`s.
3. The forensic interpretation (timeline placement, anomaly grading) lives in
   the consumers — `lnk-core` (LinkTargetIDList) and `winreg-artifacts`
   (ShellBags) — not here (`src/lib.rs:16`, `README.md:52-56`).

## Consequences

- One implementation of the shell-item format, reused everywhere it appears
  (DRY), instead of a copy inside each of `lnk-core` and `winreg-artifacts`.
- The clean split of concerns — *decode* here, *judge* in the analyzer — keeps
  this crate free of severity/category vocabulary and lets it stay a small,
  low-MSRV, dependency-light leaf (ADR 0002, ADR 0007).
- Because it is a library (nothing an examiner runs), it takes the lighter
  library-tier `docs/PRD.md` (Purpose & Scope), not a product PRD.
