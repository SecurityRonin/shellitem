# Changelog

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
