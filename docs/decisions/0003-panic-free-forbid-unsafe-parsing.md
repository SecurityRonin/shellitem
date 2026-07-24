# 3. `forbid(unsafe)` and panic-free-by-lint parsing (Paranoid Gatekeeper)

Date: 2026-07-24
Status: Accepted

## Context

Shell-item blobs are **attacker-controllable**: they are lifted verbatim from
`.lnk` `LinkTargetIDList` structures and registry ShellBags values, both of
which an adversary can craft (`Cargo.toml` Paranoid-Gatekeeper comment,
`src/reader.rs:4-7`). The per-item `cb` size field and every internal offset are
untrusted; a naive read (`&data[off..off+4]`, `.unwrap()`) turns a malformed
blob into a panic or an out-of-bounds index.

The fleet security standard for every crate that parses untrusted input is the
Paranoid Gatekeeper posture: never panic, never read out of bounds, never trust
a length field.

## Decision

1. **`unsafe_code = "forbid"`** (`Cargo.toml` `[lints.rust]`) — no `unsafe` is
   permitted anywhere in the crate; this reader needs no `mmap`, so it keeps the
   strongest `forbid` (not the `deny` + bounded-allow downgrade the mmap
   container crates use).
2. **`unwrap_used = "deny"` and `expect_used = "deny"`** (`Cargo.toml`
   `[lints.clippy]`) in production code; tests are exempted via
   `allow-unwrap-in-tests` / `allow-expect-in-tests` in `clippy.toml` plus a
   module-level `#[allow(clippy::unwrap_used, clippy::expect_used)]` on each
   `#[cfg(test)]` block (`src/parse.rs:227-228` and siblings).
3. Every integer read goes through a **bounds-checked helper** that returns `0`
   (or `None`) when the range falls outside the buffer, never a panic
   (`src/reader.rs` — `le_u16`, `le_u32`, `le_u48`, `guid`).
4. The framing loop validates `cb` before slicing: it stops at the terminator,
   at `cb < 3` (cannot hold a class byte), and uses `checked_add` so an
   overrunning `cb` breaks cleanly instead of panicking
   (`src/parse.rs:18-35`).

## Consequences

- Memory safety is compiler-*proved* for the whole crate; it can honestly carry
  the `unsafe-forbidden` badge.
- A truncated or hostile blob degrades to a partial-but-sound result, never a
  crash of the consuming analyzer (ADR 0005).
- **Known gap — the dynamic partner is not yet committed.** The static lints
  make panics unreachable by construction; a `cargo-fuzz` target over
  `parse_idlist` is the empirical check that the README and CHANGELOG advertise
  ("fuzzed"), but `fuzz/fuzz_targets/` is currently empty and no target exists in
  history. Likewise there is no `ci.yml` yet to run clippy `-D warnings`, the
  low-MSRV job, or a coverage gate. Leading claim here is the *verifiable* static
  posture; the fuzz target and CI wiring remain outstanding work.
