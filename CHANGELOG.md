# Changelog

## [0.2.3](https://github.com/SecurityRonin/shellitem/compare/shellitem-v0.2.2...shellitem-v0.2.3) - 2026-08-20

### Fixed

- *(msrv)* lower the declared floor to 1.75, which is the measured one ([#13](https://github.com/SecurityRonin/shellitem/pull/13))
- *(gitignore)* unanchor the target rule so nested cargo projects are ignored

## [0.2.2](https://github.com/SecurityRonin/shellitem/compare/shellitem-v0.2.1...shellitem-v0.2.2) - 2026-08-05

### Documentation

- replace the unearned "fuzzed" claim with measured exec counts

### Fixed

- *(supply-chain)* trust our own crates instead of exempting them

## [0.2.1](https://github.com/SecurityRonin/shellitem/compare/shellitem-v0.2.0...shellitem-v0.2.1) - 2026-07-25

### Documentation

- use verbatim Apache-2.0 license text

### Fixed

- *(vet)* declare own crates first-party so version bumps don't break supply-chain audit

## 0.1.0 — 2026-06-13

Initial release. `parse_idlist` + `reconstruct_path` over Windows `ITEMIDLIST`
(PIDL) blobs, decoding Root / Volume / FileEntry (with `0xbeef0004` long-name,
timestamps, and NTFS MFT reference) / Network / URI / ControlPanel shell items.
A reusable decoder primitive (no findings); format constants sourced from
`forensicnomicon::shellbags`. Panic-free, `forbid(unsafe_code)`, fuzzed.
