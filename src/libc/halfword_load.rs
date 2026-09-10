//! Halfword-aligned word-load helper recovered from retailOS.

/// load_u32_halfword_aligned — original: `FUN_080539d4` @ `0x080539d4`
/// (28 bytes).
///
/// Raw ARM establishes the exact extent: seven words from `0x080539d4`
/// through `pop {ip,pc}` at `0x080539ec`; the separately linked next
/// function begins at `0x080539f0`. Decoding every ARM B/BL immediate in
/// `osos.dec` finds 12 direct call sites, all unconditional `bl` (no direct
/// `b` or predicated forms).
///
/// The helper reads the low and high halves with two aligned `ldrh` loads,
/// spills them as adjacent halfwords, then reloads the resulting little-endian
/// word. This accepts a two-byte-aligned pointer without requiring word
/// alignment. No NULL or alignment guard exists in the original, so callers
/// must provide at least four readable bytes at a two-byte-aligned address.
///
/// Deliberate deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn load_u32_halfword_aligned(p: *const u8) -> u32 {
    let low = (p as *const u16).read() as u32;
    let high = (p.add(2) as *const u16).read() as u32;
    low | (high << 16)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::load_u32_halfword_aligned;

    #[repr(align(4))]
    struct AlignedBytes([u8; 16]);

    #[test]
    fn loads_every_two_byte_aligned_window() {
        let bytes = AlignedBytes([
            0x53, 0x80, 0xd4, 0x39, 0x00, 0xff, 0x12, 0x34,
            0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22,
        ]);

        for offset in (0..=12).step_by(2) {
            let expected = u32::from_le_bytes([
                bytes.0[offset],
                bytes.0[offset + 1],
                bytes.0[offset + 2],
                bytes.0[offset + 3],
            ]);
            let actual = unsafe { load_u32_halfword_aligned(bytes.0.as_ptr().add(offset)) };
            assert_eq!(actual, expected, "offset {offset}");
        }
    }

    #[test]
    fn preserves_each_halfword_byte_lane() {
        let bytes = AlignedBytes([
            0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff,
            0xa5, 0x5a, 0x5a, 0xa5, 0x01, 0x80, 0xfe, 0x7f,
        ]);

        for (offset, expected) in [
            (0, 0xffff_0000),
            (2, 0x00ff_ffff),
            (4, 0xff00_00ff),
            (6, 0x5aa5_ff00),
            (8, 0xa55a_5aa5),
            (10, 0x8001_a55a),
            (12, 0x7ffe_8001),
        ] {
            assert_eq!(
                unsafe { load_u32_halfword_aligned(bytes.0.as_ptr().add(offset)) },
                expected,
                "offset {offset}"
            );
        }
    }
}
