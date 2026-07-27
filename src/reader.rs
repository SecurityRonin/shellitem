//! Bounds-checked little-endian integer readers.
//!
//! Every read returns `0` (or `None` for the slice helper) when the requested
//! range falls outside the buffer — never a panic, never an out-of-bounds
//! index. Shell-item blobs are attacker-controllable (lifted from `.lnk`
//! `LinkTargetIDList` structures and registry ShellBags values), so the
//! Paranoid Gatekeeper rule applies: distrust every offset and length.

/// Read a little-endian `u16` at `off`, or `0` if out of range.
#[must_use]
pub(crate) fn le_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off.wrapping_add(2)) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

/// Read a little-endian `u32` at `off`, or `0` if out of range.
#[must_use]
pub(crate) fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off.wrapping_add(4)) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

/// Read a 48-bit little-endian unsigned integer at `off`, or `0` if out of
/// range. Used for the NTFS MFT entry index in the `0xbeef0004` file
/// reference (6 bytes entry + 2 bytes sequence).
#[must_use]
pub(crate) fn le_u48(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off.wrapping_add(6)) {
        b[..6].copy_from_slice(s);
    }
    u64::from_le_bytes(b)
}

/// Decode a NUL-terminated ASCII (single-byte) string starting at `off`,
/// stopping at the first NUL or the end of the buffer. Bytes are mapped
/// 1:1 to `char` (Latin-1 style); non-ASCII high bytes become their
/// `char` code point rather than being dropped, so no data is silently lost.
#[must_use]
pub(crate) fn ascii_z(data: &[u8], off: usize) -> String {
    let mut out = String::new();
    let Some(slice) = data.get(off..) else {
        return out; // cov:unreachable: off is always derived from within-bounds field positions
    };
    for &byte in slice {
        if byte == 0 {
            break;
        }
        out.push(byte as char);
    }
    out
}

/// Decode a NUL-terminated UTF-16 little-endian string starting at `off`,
/// stopping at the first U+0000 code unit or the end of the buffer.
/// Unpaired surrogates are decoded lossily to U+FFFD rather than dropped.
#[must_use]
pub(crate) fn utf16_z(data: &[u8], off: usize) -> String {
    let Some(slice) = data.get(off..) else {
        return String::new();
    };
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < slice.len() {
        let unit = u16::from_le_bytes([slice[i], slice[i + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

/// Format a 16-byte little-endian-mixed-endian Microsoft GUID at `off` into the
/// canonical `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` upper-case string. The
/// first three groups are little-endian, the last two are big-endian, matching
/// the on-disk Windows GUID encoding. Returns `None` if 16 bytes are not
/// available at `off`.
#[must_use]
pub(crate) fn guid(data: &[u8], off: usize) -> Option<String> {
    let g = data.get(off..off.wrapping_add(16))?;
    Some(format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_z_offset_past_end_returns_empty() {
        // `off` beyond the buffer must degrade to an empty string, never panic —
        // the Paranoid Gatekeeper contract for attacker-controlled offsets.
        assert_eq!(utf16_z(&[0x41, 0x00], 8), "");
    }

    #[test]
    fn utf16_z_decodes_until_nul_and_ignores_trailing_bytes() {
        // "Hi" then a UTF-16 NUL; trailing bytes after the NUL are ignored.
        let data = [0x48, 0x00, 0x69, 0x00, 0x00, 0x00, 0x5A, 0x00];
        assert_eq!(utf16_z(&data, 0), "Hi");
    }
}
