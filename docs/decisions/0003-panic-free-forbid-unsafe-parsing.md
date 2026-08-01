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
- **The dynamic partner is committed** (`fuzz/`, 2026-08-01). The static lints
  make panics unreachable *by construction*; two `cargo-fuzz` targets test that
  empirically — `idlist` drives `parse_idlist` alone, `pipeline` drives
  `parse_idlist` → `reconstruct_path` → `display_name`. First run: no crashes in
  8.2M and 9.1M executions respectively (local, aarch64-apple-darwin,
  libFuzzer 120s each). `ci.yml` now runs clippy `-D warnings`, the low-MSRV
  job, the coverage gate, and a 30s smoke-fuzz of each target on every PR.
  Fuzzing shows present-robustness over N executions; it does not prove the
  absence of a panicking input, which is why the lints — not the exec count —
  remain the load-bearing guarantee.
