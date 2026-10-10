//! TrueType format-4 segment selection — `FUN_080a9eec` at 0x080a9eec.
//! Raw A32 extent [0x080a9eec, 0x080a9f80): 148 bytes, followed by a
//! fresh push prologue. Two incoming plain BLs (0x0808639c, 0x080d4ef4),
//! zero predicated incoming BLs, and zero outgoing plain/predicated BLs.
//! Scan from the supplied segment index, caching end/start codes and signed
//! delta even for skipped segments. Skip idRangeOffset == 0xffff; otherwise
//! cache the index and either NULL or the offset-relative glyph array.
//! Return 0 on selection, -1 on exhaustion. Deliberate deviation: repr(C)
//! pointer fields scale on hosts; ARM retains the original word offsets.

use crate::ft::glyph_slot::FtCMap;

/// FreeType format-4 charmap state, through its cached glyph-array pointer.
#[repr(C)]
pub struct TtCMap4 {
    pub cmap: FtCMap,
    pub table: *const u8,
    pub flags: u32,
    pub current_char: u32,
    pub current_glyph: u32,
    pub segment_count: u32,
    pub current_segment: u32,
    pub start_code: u32,
    pub end_code: u32,
    pub delta: i32,
    pub glyph_array: *const u8,
}

/// Select the next usable segment in a validated format-4 table.
///
/// # Safety
/// `cmap` must be writable and its table must contain all four big-endian
/// arrays for `segment_count` segments. Nonzero offsets must designate valid
/// glyph-array storage. The table and state must not overlap.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tt_cmap4_next_segment(cmap: *mut TtCMap4, mut segment: u32) -> i32 {
    let count = (*cmap).segment_count;
    let table = (*cmap).table;
    while segment < count {
        let end = table.add(14 + segment as usize * 2);
        let start = end.add(count as usize * 2 + 2);
        let delta = start.add(count as usize * 2);
        let offset = delta.add(count as usize * 2);
        (*cmap).end_code = u16::from_be_bytes([*end, *end.add(1)]) as u32;
        (*cmap).start_code = u16::from_be_bytes([*start, *start.add(1)]) as u32;
        (*cmap).delta = i16::from_be_bytes([*delta, *delta.add(1)]) as i32;
        let range_offset = u16::from_be_bytes([*offset, *offset.add(1)]);
        if range_offset != 0xffff {
            (*cmap).current_segment = segment;
            (*cmap).glyph_array = if range_offset == 0 {
                core::ptr::null()
            } else {
                offset.add(range_offset as usize)
            };
            return 0;
        }
        segment += 1;
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(table: *const u8, count: u32) -> TtCMap4 {
        TtCMap4 {
            cmap: FtCMap {
                charmap: crate::ft::glyph_slot::FtCharMap {
                    face: core::ptr::null_mut(), encoding: 0, platform_id: 0, encoding_id: 0,
                },
                clazz: core::ptr::null(),
            },
            table, flags: 0x1234, current_char: 42, current_glyph: 17,
            segment_count: count, current_segment: 99, start_code: 11,
            end_code: 22, delta: 33, glyph_array: table,
        }
    }

    fn table(offsets: [u16; 3]) -> [u8; 64] {
        let mut table = [0xa5; 64];
        for (base, values) in [(14, [0x127f, 0x80ff, 0xffff]),
                               (22, [0x1200, 0x8000, 0xfffe]),
                               (28, [0x7fff, 0x8000, 0xffff]), (34, offsets)] {
            for (i, value) in values.into_iter().enumerate() {
                table[base + i * 2..base + i * 2 + 2].copy_from_slice(&value.to_be_bytes());
            }
        }
        table
    }

    #[test]
    fn selects_big_endian_fields_signed_delta_and_relative_pointer() {
        let table = table([8, 0, 12]);
        for (segment, start, end, delta, pointer) in [
            (0, 0x1200, 0x127f, 32767, unsafe { table.as_ptr().add(42) }),
            (1, 0x8000, 0x80ff, -32768, core::ptr::null()),
            (2, 0xfffe, 0xffff, -1, unsafe { table.as_ptr().add(50) }),
        ] {
            let mut cmap = state(table.as_ptr(), 3);
            assert_eq!(unsafe { tt_cmap4_next_segment(&mut cmap, segment) }, 0);
            assert_eq!((cmap.current_segment, cmap.start_code, cmap.end_code, cmap.delta,
                        cmap.glyph_array), (segment, start, end, delta, pointer));
            assert_eq!((cmap.flags, cmap.current_char, cmap.current_glyph, cmap.segment_count),
                       (0x1234, 42, 17, 3));
        }
    }

    #[test]
    fn skips_sentinels_and_preserves_selected_state_on_exhaustion() {
        for offsets in [[0xffff, 0xffff, 0], [0xffff; 3]] {
            let table = table(offsets);
            let mut cmap = state(table.as_ptr(), 3);
            let result = unsafe { tt_cmap4_next_segment(&mut cmap, 0) };
            assert_eq!((cmap.start_code, cmap.end_code, cmap.delta), (0xfffe, 0xffff, -1));
            if offsets[2] == 0 {
                assert_eq!(result, 0);
                assert_eq!(cmap.current_segment, 2);
                assert!(cmap.glyph_array.is_null());
            } else {
                assert_eq!(result, -1);
                assert_eq!((cmap.current_segment, cmap.glyph_array), (99, table.as_ptr()));
            }
        }
    }

    #[test]
    fn exhausted_indices_do_not_read_table_or_mutate_cache() {
        for (count, segment) in [(0, 0), (3, 3), (3, 4), (3, u32::MAX)] {
            let mut cmap = state(core::ptr::null(), count);
            assert_eq!(unsafe { tt_cmap4_next_segment(&mut cmap, segment) }, -1);
            assert_eq!((cmap.current_segment, cmap.start_code, cmap.end_code, cmap.delta),
                       (99, 11, 22, 33));
            assert!(cmap.glyph_array.is_null());
        }
    }
}
