//! TrueType format-12 iterator advance — `FUN_0808ca54` at 0x0808ca54.
//! Raw extent [0x0808ca54, 0x0808cb30): 220 bytes; next word is a
//! separate BX LR leaf. Two incoming plain BLs (0x080d7d48, 0x08394984),
//! zero incoming predicated BLs and zero outgoing plain/predicated BLs.
//! Advance the cached character through big-endian start/end/startGlyph
//! groups, skipping glyph zero. Success updates character, glyph and group;
//! exhaustion clears only validity. Arithmetic wraps exactly as on ARM.
//! Deliberate deviation: repr(C) native pointers scale on hosts, while ARM
//! retains the original offsets. No extra validation or sentinel gates.

use crate::ft::glyph_slot::FtCMap;

#[repr(C)]
pub struct TtCMap12 {
    pub cmap: FtCMap,
    pub table: *const u8,
    pub flags: u32,
    pub valid: u8,
    pub padding: [u8; 3],
    pub current_char: u32,
    pub current_glyph: u32,
    pub current_group: u32,
    pub group_count: u32,
}

#[inline(always)]
unsafe fn read_be32(p: *const u8) -> u32 {
    u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
}

/// Advance a validated format-12 charmap's cached iterator.
///
/// # Safety
/// `cmap` must be writable and its table must contain `group_count` groups
/// at byte offset 16. Table and state must not overlap. Like retailOS,
/// malformed ranges whose zero-glyph increment wraps can loop forever.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tt_cmap12_next(cmap: *mut TtCMap12) {
    if (*cmap).current_char != u32::MAX {
        let mut char_code = (*cmap).current_char.wrapping_add(1);
        let mut group = (*cmap).current_group;
        let count = (*cmap).group_count;
        while group < count {
            let p = (*cmap).table.add(16 + group as usize * 12);
            let start = read_be32(p);
            let end = read_be32(p.add(4));
            let start_glyph = read_be32(p.add(8));
            if char_code < start { char_code = start; }
            while char_code <= end {
                let glyph = start_glyph.wrapping_add(char_code).wrapping_sub(start);
                if glyph != 0 {
                    (*cmap).current_char = char_code;
                    (*cmap).current_glyph = glyph;
                    (*cmap).current_group = group;
                    return;
                }
                char_code = char_code.wrapping_add(1);
            }
            group = group.wrapping_add(1);
        }
    }
    (*cmap).valid = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    fn state(table: *const u8, count: u32, character: u32, group: u32) -> TtCMap12 {
        TtCMap12 {
            cmap: FtCMap {
                charmap: crate::ft::glyph_slot::FtCharMap {
                    face: core::ptr::null_mut(), encoding: 0, platform_id: 0, encoding_id: 0,
                },
                clazz: core::ptr::null(),
            },
            table, flags: 0x1234, valid: 7, padding: [0xa5; 3], current_char: character,
            current_glyph: 99, current_group: group, group_count: count,
        }
    }

    fn table(groups: &[[u32; 3]]) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0xa5; 16];
        for group in groups {
            for word in group { bytes.extend_from_slice(&word.to_be_bytes()); }
        }
        bytes
    }

    #[test]
    fn advances_across_gaps_zero_glyphs_and_empty_groups() {
        let bytes = table(&[[10, 11, 0], [30, 29, 123], [0x12345678, 0x12345679, 0xabcdef01]]);
        let mut cmap = state(bytes.as_ptr(), 3, 4, 0);
        unsafe { tt_cmap12_next(&mut cmap); }
        assert_eq!((cmap.current_char, cmap.current_glyph, cmap.current_group), (11, 1, 0));
        unsafe { tt_cmap12_next(&mut cmap); }
        assert_eq!((cmap.current_char, cmap.current_glyph, cmap.current_group),
                   (0x12345678, 0xabcdef01, 2));
        unsafe { tt_cmap12_next(&mut cmap); }
        assert_eq!((cmap.current_char, cmap.current_glyph), (0x12345679, 0xabcdef02));
        unsafe { tt_cmap12_next(&mut cmap); }
        assert_eq!((cmap.valid, cmap.current_char, cmap.current_glyph, cmap.current_group),
                   (0, 0x12345679, 0xabcdef02, 2));
        assert_eq!(cmap.padding, [0xa5; 3]);
    }

    #[test]
    fn wraps_glyph_arithmetic_and_skips_wrapped_zero() {
        let bytes = table(&[[100, 103, u32::MAX]]);
        let mut cmap = state(bytes.as_ptr(), 1, 100, 0);
        unsafe { tt_cmap12_next(&mut cmap); }
        assert_eq!((cmap.current_char, cmap.current_glyph, cmap.valid), (102, 1, 7));
        let bytes = table(&[[u32::MAX - 1, u32::MAX, 42]]);
        cmap = state(bytes.as_ptr(), 1, u32::MAX - 1, 0);
        unsafe { tt_cmap12_next(&mut cmap); }
        assert_eq!((cmap.current_char, cmap.current_glyph), (u32::MAX, 43));
        unsafe { tt_cmap12_next(&mut cmap); }
        assert_eq!((cmap.valid, cmap.current_glyph), (0, 43));
    }

    #[test]
    fn exhaustion_and_sentinel_do_not_touch_table_or_cached_values() {
        for (character, group, count) in [(u32::MAX, 0, 4), (12, 0, 0), (12, 4, 3)] {
            let mut cmap = state(core::ptr::null(), count, character, group);
            unsafe { tt_cmap12_next(&mut cmap); }
            assert_eq!((cmap.valid, cmap.current_char, cmap.current_glyph, cmap.current_group),
                       (0, character, 99, group));
            assert_eq!(cmap.padding, [0xa5; 3]);
        }
    }

    #[test]
    fn retains_unsigned_cursor_and_does_not_enable_invalid_cache() {
        let bytes = table(&[[2, 4, 7], [0x80000000, 0x80000002, 17]]);
        let mut cmap = state(bytes.as_ptr(), 2, 0x80000000, 0);
        cmap.valid = 0;
        unsafe { tt_cmap12_next(&mut cmap); }
        assert_eq!((cmap.current_char, cmap.current_glyph, cmap.current_group, cmap.valid),
                   (0x80000001, 18, 1, 0));
    }
}
