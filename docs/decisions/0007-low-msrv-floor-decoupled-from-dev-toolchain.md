# 7. Low MSRV floor decoupled from the dev toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates the **dev toolchain** (what the repo builds,
formats, and lints with) from the **declared MSRV** (`rust-version` — a
downstream-facing compatibility promise). Published libraries keep a **low,
CI-verified MSRV** as a deliberate compatibility feature; only apps declare their
MSRV equal to the pinned dev toolchain. `shellitem` is a published library that
several other crates link, so a low floor widens its usable audience.

## Decision

1. Declare **`rust-version = "1.81"`** in `Cargo.toml` `[package]` as the
   downstream MSRV promise.
2. Pin the **dev/CI toolchain to `1.96.0`** in `rust-toolchain.toml` (the fleet
   single-source-of-truth pin), with `clippy` and `rustfmt` components — so
   contributors develop on the current stable while the crate still *compiles*
   on 1.81.

## Consequences

- Downstream consumers on an older stable can link `shellitem` without being
  forced to the fleet's newest toolchain.
- The two-number split is intentional: raising the declared MSRV later is a
  near-breaking change, so it stays as low as the code truly needs.
- **Honest gaps.** (a) The specific choice of `1.81` — rather than the fleet's
  usual `1.75`/`1.80` library floor — is not explained in the code or history;
  Rationale reconstructed from structure; original intent not recovered in
  available history (likely a language/stdlib feature floor, but unconfirmed).
  (b) A low MSRV is only a real guarantee when a CI job verifies it; there is no
  `ci.yml` in the repo yet (only `docs.yml`, `release-plz.yml`, `vet.yml`), so
  the 1.81 floor is currently declared-but-unverified — a dedicated low-MSRV job
  is outstanding work.
