//! Anomaly-audit tests driven through the REAL parser.
//!
//! `ShellItem` is `#[non_exhaustive]`, so it cannot be struct-literalled from
//! outside `shellitem-core`. That is a feature here: every case below builds
//! spec-exact ITEMIDLIST bytes (libfwsi layout) and runs them through
//! `parse_idlist`, so the tests exercise the real parse -> audit pipeline
//! rather than a hand-made struct the parser could never produce.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use shellitem_core::parse_idlist;
use shellitem_forensic::{audit, ShellItemAnomaly};

/// Pack a FAT date/time pair into the `u32` a file-entry item carries.
fn fat(year: u16, month: u16, day: u16, hour: u16, min: u16, sec: u16) -> u32 {
    let date: u16 = ((year - 1980) << 9) | (month << 5) | day;
    let time: u16 = (hour << 11) | (min << 5) | (sec / 2);
    (u32::from(date) << 16) | u32::from(time)
}

/// Build a spec-exact `0x32` file-entry item with a `beef0004` v8 block,
/// mirroring the builder in `shellitem-core`'s own tests.
fn file_entry(short: &str, long: &str, modified: u32, created: u32, accessed: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0x32);
    body.push(0x00);
    body.extend_from_slice(&1024u32.to_le_bytes());
    body.extend_from_slice(&modified.to_le_bytes());
    body.extend_from_slice(&0x0020u16.to_le_bytes());
    body.extend_from_slice(short.as_bytes());
    body.push(0x00);
    if body.len() % 2 != 0 {
        body.push(0x00);
    }
    let block_start_in_body = body.len();
    let mut block = Vec::new();
    block.extend_from_slice(&[0u8, 0u8]);
    block.extend_from_slice(&8u16.to_le_bytes());
    block.extend_from_slice(&0xBEEF_0004u32.to_le_bytes());
    block.extend_from_slice(&created.to_le_bytes());
    block.extend_from_slice(&accessed.to_le_bytes());
    let long_name_off_pos = block.len();
    block.extend_from_slice(&[0u8, 0u8]);
    block.extend_from_slice(&[0u8, 0u8]);
    block.extend_from_slice(&0u64.to_le_bytes()[..6]);
    block.extend_from_slice(&0u16.to_le_bytes());
    let long_name_offset_in_block = u16::try_from(block.len()).unwrap();
    for u in long.encode_utf16() {
        block.extend_from_slice(&u.to_le_bytes());
    }
    block.extend_from_slice(&[0u8, 0u8]);
    let first_ext_off = u16::try_from(2 + block_start_in_body).unwrap();
    block.extend_from_slice(&first_ext_off.to_le_bytes());
    let block_size = u16::try_from(block.len()).unwrap();
    block[0..2].copy_from_slice(&block_size.to_le_bytes());
    block[long_name_off_pos..long_name_off_pos + 2]
        .copy_from_slice(&long_name_offset_in_block.to_le_bytes());
    body.extend_from_slice(&block);
    let cb = u16::try_from(2 + body.len()).unwrap();
    let mut item = cb.to_le_bytes().to_vec();
    item.extend_from_slice(&body);
    item
}

fn list(item: Vec<u8>) -> Vec<u8> {
    let mut v = item;
    v.extend_from_slice(&[0u8, 0u8]);
    v
}

const JAN_2020: u32 = 0; // replaced in each test via fat()

#[test]
fn a_clean_file_entry_raises_nothing() {
    // CONTROL. If this ever fires, the detectors below prove nothing: a rule
    // that flags ordinary evidence is noise, not detection.
    let _ = JAN_2020;
    let m = fat(2020, 6, 1, 12, 0, 0);
    let c = fat(2020, 1, 1, 9, 0, 0);
    let bytes = list(file_entry("REPORT~1.PDF", "quarterly report.pdf", m, c, m));
    let items = parse_idlist(&bytes);
    assert_eq!(items.len(), 1, "fixture must parse to exactly one item");
    assert!(
        audit(&items).is_empty(),
        "clean entry raised: {:?}",
        audit(&items)
    );
}

#[test]
fn right_to_left_override_in_a_name_is_reported_with_the_codepoint() {
    // U+202E disguises "...cod.exe" as "...exe.doc" in Explorer. MITRE T1036.002.
    let m = fat(2021, 3, 4, 10, 30, 0);
    let spoofed = "invoice\u{202E}cod.exe";
    let bytes = list(file_entry("INVOIC~1.EXE", spoofed, m, m, m));
    let items = parse_idlist(&bytes);
    let found = audit(&items);
    let hit = found
        .iter()
        .find(|a| matches!(a, ShellItemAnomaly::BidiControlInName { .. }))
        .expect("RTL override not reported");
    match hit {
        ShellItemAnomaly::BidiControlInName { codepoint, .. } => {
            assert_eq!(*codepoint, 0x202E, "must name the offending codepoint");
        }
        _ => unreachable!(),
    }
}

#[test]
fn a_long_name_whose_extension_contradicts_the_short_name_is_reported() {
    let m = fat(2022, 7, 9, 8, 15, 0);
    let bytes = list(file_entry("SETUP~1.EXE", "readme.txt", m, m, m));
    let items = parse_idlist(&bytes);
    assert!(
        audit(&items)
            .iter()
            .any(|a| matches!(a, ShellItemAnomaly::ExtensionMismatch { .. })),
        "extension mismatch not reported"
    );
}

#[test]
fn a_creation_time_after_the_modification_time_is_reported() {
    let modified = fat(2019, 1, 1, 0, 0, 0);
    let created = fat(2024, 1, 1, 0, 0, 0);
    let bytes = list(file_entry(
        "OLD~1.TXT",
        "old.txt",
        modified,
        created,
        modified,
    ));
    let items = parse_idlist(&bytes);
    assert!(
        audit(&items)
            .iter()
            .any(|a| matches!(a, ShellItemAnomaly::TimestampOrderInversion { .. })),
        "created-after-modified not reported"
    );
}

#[test]
fn an_unrecognised_class_byte_is_reported_verbatim() {
    // Never report "unknown" without the offending value.
    // 0x4A: major class 0x40 is unhandled, so the parser yields Unknown.
    let mut body = vec![0x4Au8, 0x00, 0xAA, 0xBB];
    let cb = u16::try_from(2 + body.len()).unwrap();
    let mut item = cb.to_le_bytes().to_vec();
    item.append(&mut body);
    let items = parse_idlist(&list(item));
    let found = audit(&items);
    assert!(
        found.iter().any(|a| matches!(
            a,
            ShellItemAnomaly::UnrecognizedClass { class, .. } if *class == 0x4A
        )),
        "unrecognised class not reported with its byte: {found:?}"
    );
}

#[test]
fn a_timestamp_beyond_the_far_future_bound_is_reported() {
    // FAT encodes year-1980 in 7 bits, so 2107 is expressible yet sits past the
    // analyzer's fixed 2100 ceiling -- a value the format allows and reality
    // does not.
    let sane = fat(2020, 5, 5, 5, 0, 0);
    let absurd = fat(2107, 12, 31, 23, 58, 58);
    let bytes = list(file_entry("FUTURE~1.TXT", "future.txt", sane, sane, absurd));
    let items = parse_idlist(&bytes);
    let found = audit(&items);
    let hit = found
        .iter()
        .find(|a| matches!(a, ShellItemAnomaly::ImplausibleTimestamp { .. }))
        .unwrap_or_else(|| panic!("implausible timestamp not reported: {found:?}"));
    match hit {
        ShellItemAnomaly::ImplausibleTimestamp { field, value, .. } => {
            assert_eq!(*field, "accessed");
            assert!(
                *value > 4_102_444_800,
                "value {value} should exceed the ceiling"
            );
        }
        _ => unreachable!(),
    }
}

#[test]
fn a_name_without_an_extension_is_not_an_extension_mismatch() {
    // A directory entry carries no suffix on either name, so the comparison
    // must not run at all -- the branch where extension() yields None.
    let m = fat(2023, 2, 2, 2, 0, 0);
    let bytes = list(file_entry("DOCUME~1", "Documents", m, m, m));
    let items = parse_idlist(&bytes);
    assert!(
        audit(&items).is_empty(),
        "extension-less names raised: {:?}",
        audit(&items)
    );
}
