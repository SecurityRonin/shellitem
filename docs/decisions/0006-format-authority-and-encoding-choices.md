# 6. Format authority (libfwsi) and byte-encoding choices

Date: 2026-07-24
Status: Accepted

## Context

Microsoft publishes no complete public specification for the internal layout of
an `ITEMIDLIST` or its per-class shell items. The reverse-engineered reference
the forensic community has settled on is libyal's **libfwsi** — *Windows Shell
Item format* (Joachim Metz). Implementing this format from memory of "how it
probably works" is how inverted bit-splits and wrong offsets ship; the fleet
research-first rule requires coding from the authoritative reference.

Two encoding details in the format are non-obvious and easy to get wrong: the
Microsoft **mixed-endian GUID** on-disk layout, and the packed **FAT date/time**
representation.

## Decision

1. **Follow libfwsi** for the `ITEMIDLIST` framing and every class layout — root
   `0x1f`, volume `0x2e`/`0x2f`, file-entry `0x30`-major and its `0xbeef0004`
   extension, network `0xc3` — and cite it in the crate docs
   (`src/lib.rs:27-36`). Class-type constants come from
   `forensicnomicon::shellbags` (ADR 0002), themselves sourced from libfwsi and
   winshl-kb.
2. **GUID mixed-endian.** Format the 16-byte GUID with the first three groups
   little-endian and the last two big-endian, matching the on-disk Windows
   encoding, into the canonical upper-case string
   (`src/reader.rs:81-93`).
3. **Strings.** ASCII is mapped 1:1 (Latin-1 style) so a high byte becomes its
   code point rather than being dropped; UTF-16LE is decoded **lossily** so an
   unpaired surrogate becomes U+FFFD rather than failing or dropping the unit
   (`src/reader.rs:41-79`).
4. **Timestamps.** File-entry and `0xbeef0004` timestamps are 32-bit packed FAT
   date/time in UTC, converted to Unix epoch seconds
   (`src/dosdate.rs:1-13,24-59`).

## Consequences

- The decoder is byte-compatible with the established reference implementation,
  so its output can be validated directly against libfwsi and against
  spec-derived `ITEMIDLIST` fixtures.
- No data is silently lost to encoding edge cases: high ASCII bytes survive,
  unpaired surrogates render visibly as U+FFFD, and a malformed FAT field
  degrades to `None` (ADR 0005) rather than a wrong time.
