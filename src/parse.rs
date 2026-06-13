//! `ITEMIDLIST` framing and per-class shell-item decoding.

use crate::reader;
use crate::{dosdate, ShellItem, ShellItemKind};
use forensicnomicon::shellbags;

/// Parse a Windows `ITEMIDLIST` (PIDL) blob into its sequence of shell items.
///
/// The list is a run of `ItemID { u16 cb; data[cb-2] }` records terminated by
/// a `cb == 0` item (libfwsi). Parsing is **lenient**: it stops at the
/// terminator, at a `cb` that would run past the end of the buffer, or at a
/// `cb < 2` (which cannot make progress), returning whatever items were
/// decoded so far. It never panics on malformed input.
#[must_use]
pub fn parse_idlist(data: &[u8]) -> Vec<ShellItem> {
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos + 2 <= data.len() {
        let cb = crate::reader::le_u16(data, pos) as usize;
        if cb == 0 {
            break; // terminator
        }
        if cb < 3 {
            break; // cannot hold a class byte — cannot make progress
        }
        let end = match pos.checked_add(cb) {
            Some(e) if e <= data.len() => e,
            _ => break, // cb lies / overruns the buffer — stop cleanly
        };
        let raw = data[pos..end].to_vec();
        let class = raw[2];
        items.push(decode_item(class, raw));
        pos = end;
    }
    items
}

/// Reconstruct a human-readable path from a parsed item list by joining each
/// item's best display name with `\`.
#[must_use]
pub fn reconstruct_path(items: &[ShellItem]) -> String {
    // stub — implemented in GREEN
    let _ = items;
    String::new()
}

/// A freshly-constructed `ShellItem` with the given class/kind and the raw
/// bytes attached; every optional field starts empty for the per-class decoder
/// to fill in.
fn blank(class: u8, kind: ShellItemKind, raw: Vec<u8>) -> ShellItem {
    ShellItem {
        class,
        kind,
        name: None,
        long_name: None,
        file_size: None,
        modified: None,
        created: None,
        accessed: None,
        mft_entry: None,
        mft_sequence: None,
        guid: None,
        raw,
    }
}

/// Map a well-known shell-folder GUID to its canonical display name. Only the
/// universally-stable My-Computer / "This PC" GUID is hard-named here (sourced
/// from [`forensicnomicon::shellbags::MY_COMPUTER_GUID`]); every other GUID is
/// surfaced verbatim so consumers can resolve it against their own CLSID map.
fn known_folder_name(guid: &str) -> Option<&'static str> {
    if guid.eq_ignore_ascii_case(shellbags::MY_COMPUTER_GUID) {
        Some("My Computer")
    } else {
        None
    }
}

fn decode_item(class: u8, raw: Vec<u8>) -> ShellItem {
    if shellbags::is_file_entry(class) {
        return decode_file_entry(class, raw);
    }
    match class {
        shellbags::CLASS_ROOT_FOLDER => decode_root(class, raw),
        shellbags::CLASS_VOLUME_2E | shellbags::CLASS_VOLUME_2F => decode_volume(class, raw),
        _ => blank(class, ShellItemKind::Unknown, raw),
    }
}

/// Decode a file-entry item (major class `0x30`: `0x31` dir, `0x32` file,
/// `0x35`/`0x36`, `0xb1` Unicode). Reads the fixed-offset short name, file
/// size and FAT modification time, then parses the trailing `0xbeef0004`
/// extension block (long name, create/access times, NTFS MFT reference).
fn decode_file_entry(class: u8, raw: Vec<u8>) -> ShellItem {
    let mut item = blank(class, ShellItemKind::FileEntry, raw);
    let data = &item.raw;

    item.file_size = Some(reader::le_u32(data, 4));
    item.modified = dosdate::fat_to_epoch(reader::le_u32(data, 8));

    // Primary (short) name at offset 14. The 0xb1 Unicode class stores it as
    // UTF-16; the classic 0x31/0x32 classes store ASCII (libfwsi).
    let (short, short_end) = if class == shellbags::CLASS_FILE_ENTRY_UNICODE {
        let s = reader::utf16_z(data, 14);
        let consumed = (s.encode_utf16().count() + 1) * 2;
        (s, 14 + consumed)
    } else {
        let s = reader::ascii_z(data, 14);
        // ASCII string + its NUL, then 16-bit aligned (a padding zero may
        // follow so the extension block starts on an even offset).
        let mut end = 14 + s.len() + 1;
        if end % 2 != 0 {
            end += 1;
        }
        (s, end)
    };
    if !short.is_empty() {
        item.name = Some(short);
    }

    parse_beef0004(&mut item, short_end);
    item
}

/// Parse the `0xbeef0004` file-entry extension block, if present, starting at
/// or near `block_start`. Fills the long name, create/access timestamps and
/// the NTFS MFT reference. Tolerant of a slightly-off `block_start`: the
/// block is accepted only when its signature validates, and is otherwise
/// located by scanning the item bytes for the `0xbeef0004` signature.
fn parse_beef0004(item: &mut ShellItem, block_start: usize) {
    let data = item.raw.clone();
    let Some(block_off) = locate_beef0004(&data, block_start) else {
        return;
    };

    let version = reader::le_u16(&data, block_off + 2);
    item.created = dosdate::fat_to_epoch(reader::le_u32(&data, block_off + 8));
    item.accessed = dosdate::fat_to_epoch(reader::le_u32(&data, block_off + 12));

    // Long name offset is relative to the start of the extension block.
    let long_name_offset = reader::le_u16(&data, block_off + 16) as usize;
    if long_name_offset != 0 {
        if let Some(abs) = block_off.checked_add(long_name_offset) {
            let long = reader::utf16_z(&data, abs);
            if !long.is_empty() {
                item.long_name = Some(long);
            }
        }
    }

    // Version >= 7 carries 2 unknown bytes then the 8-byte NTFS file reference
    // (6-byte MFT entry index + 2-byte sequence number) at block+20.
    if version >= 7 {
        let entry = reader::le_u48(&data, block_off + 20);
        let seq = reader::le_u16(&data, block_off + 26);
        // A zero file reference is the "absent" sentinel — leave the fields None.
        if entry != 0 || seq != 0 {
            item.mft_entry = Some(entry);
            item.mft_sequence = Some(seq);
        }
    }
}

/// Locate the `0xbeef0004` extension block within a file-entry item. Tries the
/// computed `hint` offset first (verifying the signature at `hint + 4`), then
/// falls back to scanning for the little-endian signature bytes. Returns the
/// block start offset, or `None` if no valid block is found.
fn locate_beef0004(data: &[u8], hint: usize) -> Option<usize> {
    let sig = shellbags::EXTENSION_BLOCK_0XBEEF0004.to_le_bytes();
    if reader::le_u32(data, hint.wrapping_add(4)) == shellbags::EXTENSION_BLOCK_0XBEEF0004 {
        return Some(hint);
    }
    // Fallback: scan for the signature; the block starts 4 bytes before it.
    data.windows(4)
        .position(|w| w == sig)
        .and_then(|p| p.checked_sub(4))
}

/// Decode a volume item (`0x2e`/`0x2f`). For the drive-letter form (`0x2f`)
/// the 20-byte ASCII volume name starts at offset 3 (libfwsi). The `0x2e`
/// GUID form is classified but not name-decoded.
fn decode_volume(class: u8, raw: Vec<u8>) -> ShellItem {
    let mut item = blank(class, ShellItemKind::Volume, raw);
    if class == shellbags::CLASS_VOLUME_2F {
        let name = reader::ascii_z(&item.raw, 3);
        if !name.is_empty() {
            item.name = Some(name);
        }
    }
    item
}

/// Decode a root / known-folder item (`0x1f`): a 1-byte sort index followed by
/// a 16-byte shell-folder GUID at offset 4 (libfwsi).
fn decode_root(class: u8, raw: Vec<u8>) -> ShellItem {
    let mut item = blank(class, ShellItemKind::Root, raw);
    if let Some(guid) = reader::guid(&item.raw, 4) {
        item.name = known_folder_name(&guid).map(ToString::to_string);
        item.guid = Some(guid);
    }
    item
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod framing_tests {
    use super::*;

    /// Build one raw item with the given class byte and trailing data, framed
    /// with its `cb` size prefix (cb = 2 + 1 + data.len()).
    fn item(class: u8, data: &[u8]) -> Vec<u8> {
        let cb = (3 + data.len()) as u16;
        let mut v = cb.to_le_bytes().to_vec();
        v.push(class);
        v.extend_from_slice(data);
        v
    }

    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        for it in items {
            v.extend_from_slice(it);
        }
        v.extend_from_slice(&[0u8, 0u8]); // terminator cb == 0
        v
    }

    #[test]
    fn splits_two_items_and_stops_at_terminator() {
        let blob = list(&[item(0x1F, &[0xAA; 16]), item(0x32, &[0xBB; 8])]);
        let items = parse_idlist(&blob);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].class, 0x1F);
        assert_eq!(items[1].class, 0x32);
    }

    #[test]
    fn empty_input_yields_no_items() {
        assert!(parse_idlist(&[]).is_empty());
        assert!(parse_idlist(&[0u8, 0u8]).is_empty());
    }

    #[test]
    fn cb_overrunning_buffer_stops_cleanly() {
        // cb claims 100 bytes but only a few are present — must not panic,
        // must stop without emitting a bogus item.
        let blob = vec![100u8, 0u8, 0x32, 0xAA, 0xBB];
        let items = parse_idlist(&blob);
        assert!(items.is_empty());
    }

    #[test]
    fn cb_below_minimum_stops_cleanly() {
        // cb == 1 cannot make progress (no room for the class byte).
        let blob = vec![1u8, 0u8, 0x32];
        let items = parse_idlist(&blob);
        assert!(items.is_empty());
    }

    #[test]
    fn raw_bytes_are_preserved_per_item() {
        let raw0 = item(0x1F, &[0xAA; 16]);
        let blob = list(&[raw0.clone()]);
        let items = parse_idlist(&blob);
        assert_eq!(items[0].raw, raw0);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod root_tests {
    use super::*;
    use crate::ShellItemKind;

    /// The My-Computer GUID `20D04FE0-3AEA-1069-A2D8-08002B30309D` in on-disk
    /// mixed-endian byte order (first three groups little-endian).
    const MY_COMPUTER_BYTES: [u8; 16] = [
        0xE0, 0x4F, 0xD0, 0x20, // 20D04FE0 (LE)
        0xEA, 0x3A, // 3AEA (LE)
        0x69, 0x10, // 1069 (LE)
        0xA2, 0xD8, // A2D8 (BE)
        0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D, // 08002B30309D (BE)
    ];

    fn root_item(sort: u8, guid: &[u8; 16]) -> Vec<u8> {
        let mut data = vec![sort];
        data.extend_from_slice(guid);
        // frame: cb = 2 + 1(class) + 1(sort) + 16(guid)
        let cb = (3 + data.len()) as u16;
        let mut v = cb.to_le_bytes().to_vec();
        v.push(0x1F);
        v.extend_from_slice(&data);
        v.extend_from_slice(&[0u8, 0u8]); // terminator
        v
    }

    #[test]
    fn root_item_decodes_guid_and_kind() {
        let blob = root_item(0x00, &MY_COMPUTER_BYTES);
        let items = parse_idlist(&blob);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, ShellItemKind::Root);
        assert_eq!(
            items[0].guid.as_deref(),
            Some("20D04FE0-3AEA-1069-A2D8-08002B30309D")
        );
    }

    #[test]
    fn my_computer_guid_maps_to_display_name() {
        let blob = root_item(0x00, &MY_COMPUTER_BYTES);
        let items = parse_idlist(&blob);
        // "My Computer" is the canonical display name for the My-Computer GUID.
        assert_eq!(items[0].name.as_deref(), Some("My Computer"));
        assert_eq!(items[0].display_name(), Some("My Computer"));
    }

    #[test]
    fn unknown_root_guid_has_no_name_but_keeps_guid() {
        let other = [0x11u8; 16];
        let blob = root_item(0x00, &other);
        let items = parse_idlist(&blob);
        assert_eq!(items[0].kind, ShellItemKind::Root);
        assert!(items[0].name.is_none());
        assert!(items[0].guid.is_some());
        // display_name falls back to the GUID string.
        assert_eq!(items[0].display_name(), items[0].guid.as_deref());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod volume_tests {
    use super::*;
    use crate::ShellItemKind;

    /// Build a 0x2F drive-letter volume item: class 0x2F then a 20-byte ASCII
    /// volume name (NUL-terminated, zero-padded) per libfwsi.
    fn volume_2f(name: &str) -> Vec<u8> {
        let mut field = [0u8; 20];
        for (i, b) in name.bytes().enumerate().take(19) {
            field[i] = b;
        }
        let mut v = Vec::new();
        let cb = (3 + field.len()) as u16;
        v.extend_from_slice(&cb.to_le_bytes());
        v.push(0x2F);
        v.extend_from_slice(&field);
        v.extend_from_slice(&[0u8, 0u8]);
        v
    }

    #[test]
    fn drive_letter_volume_decodes_name() {
        let blob = volume_2f("C:\\");
        let items = parse_idlist(&blob);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, ShellItemKind::Volume);
        assert_eq!(items[0].class, 0x2F);
        assert_eq!(items[0].name.as_deref(), Some("C:\\"));
        assert_eq!(items[0].display_name(), Some("C:\\"));
    }

    #[test]
    fn volume_2e_is_classified_as_volume() {
        // 0x2E variant: still major-class volume (0x20). We classify the kind
        // even though its inner layout (a GUID) is not name-decoded here.
        let mut v = Vec::new();
        v.extend_from_slice(&(3u16 + 16).to_le_bytes());
        v.push(0x2E);
        v.extend_from_slice(&[0u8; 16]);
        v.extend_from_slice(&[0u8, 0u8]);
        let items = parse_idlist(&v);
        assert_eq!(items[0].kind, ShellItemKind::Volume);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod file_entry_tests {
    use super::*;
    use crate::ShellItemKind;

    /// Encode a packed FAT date/time (UTC). day 1-31, month 1-12, year>=1980.
    fn fat(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> u32 {
        let date: u16 =
            ((year - 1980) << 9) | (u16::from(month) << 5) | u16::from(day);
        let time: u16 =
            (u16::from(hour) << 11) | (u16::from(minute) << 5) | u16::from(second / 2);
        (u32::from(date) << 16) | u32::from(time)
    }

    /// Build a spec-exact 0x32 file-entry item with a beef0004 extension block
    /// (version 8 → carries the NTFS file reference) per libfwsi.
    ///
    /// Returns the framed item bytes (no list terminator).
    fn file_entry_with_beef0004(
        short: &str,
        long: &str,
        size: u32,
        modified: u32,
        created: u32,
        accessed: u32,
        mft_entry: u64,
        mft_seq: u16,
    ) -> Vec<u8> {
        // ── item body (starting at offset 2, the class byte) ──
        let mut body = Vec::new();
        body.push(0x32); // class (offset 2)
        body.push(0x00); // unknown (offset 3)
        body.extend_from_slice(&size.to_le_bytes()); // offset 4
        body.extend_from_slice(&modified.to_le_bytes()); // offset 8
        body.extend_from_slice(&0x0020u16.to_le_bytes()); // attrs (offset 12) ARCHIVE
        // primary (short) name, ASCII NUL-terminated, 16-bit aligned (offset 14)
        body.extend_from_slice(short.as_bytes());
        body.push(0x00);
        if body.len() % 2 != 0 {
            body.push(0x00); // 16-bit alignment pad
        }

        // ── beef0004 extension block (version 8) ──
        let block_start_in_body = body.len();
        let mut block = Vec::new();
        // size placeholder (offset 0)
        block.extend_from_slice(&[0u8, 0u8]);
        block.extend_from_slice(&8u16.to_le_bytes()); // version 8 (offset 2)
        block.extend_from_slice(&0xBEEF_0004u32.to_le_bytes()); // signature (offset 4)
        block.extend_from_slice(&created.to_le_bytes()); // creation FAT (offset 8)
        block.extend_from_slice(&accessed.to_le_bytes()); // access FAT (offset 12)
        // long name offset placeholder (offset 16) — filled after we know it
        let long_name_off_pos = block.len();
        block.extend_from_slice(&[0u8, 0u8]);
        // version >= 7: 2 unknown bytes (offset 18) + 8-byte file reference (offset 20)
        block.extend_from_slice(&[0u8, 0u8]); // unknown
        block.extend_from_slice(&mft_entry.to_le_bytes()[..6]); // 6-byte MFT entry
        block.extend_from_slice(&mft_seq.to_le_bytes()); // 2-byte sequence
        // long name (UTF-16LE, NUL-terminated)
        let long_name_offset_in_block = block.len() as u16;
        for u in long.encode_utf16() {
            block.extend_from_slice(&u.to_le_bytes());
        }
        block.extend_from_slice(&[0u8, 0u8]); // UTF-16 NUL
        // first extension block offset (relative to start of shell item, i.e.
        // start of body + 2 for the cb prefix). 2-byte trailer.
        let first_ext_off = (2 + block_start_in_body) as u16;
        block.extend_from_slice(&first_ext_off.to_le_bytes());

        // patch block size + long-name offset
        let block_size = block.len() as u16;
        block[0..2].copy_from_slice(&block_size.to_le_bytes());
        block[long_name_off_pos..long_name_off_pos + 2]
            .copy_from_slice(&long_name_offset_in_block.to_le_bytes());

        body.extend_from_slice(&block);

        // frame with cb (= 2 + body.len())
        let cb = (2 + body.len()) as u16;
        let mut item = cb.to_le_bytes().to_vec();
        item.extend_from_slice(&body);
        item
    }

    fn list_one(item: Vec<u8>) -> Vec<u8> {
        let mut v = item;
        v.extend_from_slice(&[0u8, 0u8]);
        v
    }

    #[test]
    fn decodes_short_name_size_and_modified() {
        let modified = fat(2024, 3, 14, 9, 26, 30);
        let item = file_entry_with_beef0004(
            "SECRET~1.DOC", "secret report.docx", 4096, modified, 0, 0, 0, 0,
        );
        let items = parse_idlist(&list_one(item));
        assert_eq!(items.len(), 1);
        let it = &items[0];
        assert_eq!(it.kind, ShellItemKind::FileEntry);
        assert_eq!(it.name.as_deref(), Some("SECRET~1.DOC"));
        assert_eq!(it.file_size, Some(4096));
        // 2024-03-14 09:26:30 UTC
        assert_eq!(it.modified, Some(1_710_408_390));
    }

    #[test]
    fn decodes_long_name_from_beef0004() {
        let item = file_entry_with_beef0004(
            "SECRET~1.DOC", "secret report.docx", 4096, 0, 0, 0, 0, 0,
        );
        let items = parse_idlist(&list_one(item));
        assert_eq!(items[0].long_name.as_deref(), Some("secret report.docx"));
        // display_name prefers the long name.
        assert_eq!(items[0].display_name(), Some("secret report.docx"));
    }

    #[test]
    fn decodes_created_and_accessed_timestamps() {
        let created = fat(2020, 1, 2, 3, 4, 10);
        let accessed = fat(2025, 12, 31, 23, 58, 0);
        let item = file_entry_with_beef0004(
            "F~1.TXT", "file.txt", 10, 0, created, accessed, 0, 0,
        );
        let items = parse_idlist(&list_one(item));
        assert_eq!(items[0].created, Some(1_577_934_250)); // 2020-01-02 03:04:10
        assert_eq!(items[0].accessed, Some(1_767_225_480)); // 2025-12-31 23:58:00
    }

    #[test]
    fn decodes_mft_entry_and_sequence() {
        let item = file_entry_with_beef0004(
            "F~1.TXT", "file.txt", 10, 0, 0, 0, 0x1234_5678_9ABC, 0x0007,
        );
        let items = parse_idlist(&list_one(item));
        assert_eq!(items[0].mft_entry, Some(0x1234_5678_9ABC));
        assert_eq!(items[0].mft_sequence, Some(0x0007));
    }

    #[test]
    fn beef0004_version3_has_no_mft_reference() {
        // Version 3 (XP) blocks have no file reference; mft fields stay None,
        // but the long name still decodes.
        let mut body = Vec::new();
        body.push(0x32);
        body.push(0x00);
        body.extend_from_slice(&100u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(b"OLD~1.TXT\0");
        if body.len() % 2 != 0 {
            body.push(0);
        }
        let mut block = Vec::new();
        block.extend_from_slice(&[0u8, 0u8]); // size
        block.extend_from_slice(&3u16.to_le_bytes()); // version 3
        block.extend_from_slice(&0xBEEF_0004u32.to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes()); // created
        block.extend_from_slice(&0u32.to_le_bytes()); // accessed
        let lno_pos = block.len();
        block.extend_from_slice(&[0u8, 0u8]); // long name offset
        let lno = block.len() as u16;
        for u in "old.txt".encode_utf16() {
            block.extend_from_slice(&u.to_le_bytes());
        }
        block.extend_from_slice(&[0u8, 0u8]);
        block.extend_from_slice(&0u16.to_le_bytes()); // first ext offset
        let bs = block.len() as u16;
        block[0..2].copy_from_slice(&bs.to_le_bytes());
        block[lno_pos..lno_pos + 2].copy_from_slice(&lno.to_le_bytes());
        body.extend_from_slice(&block);
        let cb = (2 + body.len()) as u16;
        let mut item = cb.to_le_bytes().to_vec();
        item.extend_from_slice(&body);

        let items = parse_idlist(&list_one(item));
        assert_eq!(items[0].long_name.as_deref(), Some("old.txt"));
        assert!(items[0].mft_entry.is_none());
        assert!(items[0].mft_sequence.is_none());
    }

    #[test]
    fn file_entry_without_extension_block_still_decodes_short_name() {
        // No beef0004: short name + size only, no long name / mft.
        let mut body = Vec::new();
        body.push(0x32);
        body.push(0x00);
        body.extend_from_slice(&55u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(b"BARE.TXT\0");
        let cb = (2 + body.len()) as u16;
        let mut item = cb.to_le_bytes().to_vec();
        item.extend_from_slice(&body);
        let items = parse_idlist(&list_one(item));
        assert_eq!(items[0].name.as_deref(), Some("BARE.TXT"));
        assert_eq!(items[0].file_size, Some(55));
        assert!(items[0].long_name.is_none());
    }

    #[test]
    fn directory_class_0x31_is_file_entry() {
        let mut body = Vec::new();
        body.push(0x31); // directory
        body.push(0x00);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0x10u16.to_le_bytes()); // DIRECTORY attr
        body.extend_from_slice(b"USERS\0");
        let cb = (2 + body.len()) as u16;
        let mut item = cb.to_le_bytes().to_vec();
        item.extend_from_slice(&body);
        let items = parse_idlist(&list_one(item));
        assert_eq!(items[0].kind, ShellItemKind::FileEntry);
        assert_eq!(items[0].name.as_deref(), Some("USERS"));
    }
}
