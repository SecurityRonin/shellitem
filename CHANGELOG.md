# Changelog

## 0.1.0 — 2026-06-13

Initial release. `parse_idlist` + `reconstruct_path` over Windows `ITEMIDLIST`
(PIDL) blobs, decoding Root / Volume / FileEntry (with `0xbeef0004` long-name,
timestamps, and NTFS MFT reference) / Network / URI / ControlPanel shell items.
A reusable decoder primitive (no findings); format constants sourced from
`forensicnomicon::shellbags`. Panic-free, `forbid(unsafe_code)`, fuzzed.
