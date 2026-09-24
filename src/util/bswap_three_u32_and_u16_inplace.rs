//! Reverses the scalar fields in a fourteen-byte record.

/// `bswap_three_u32_and_u16_inplace` — original: `FUN_080cbfa0` @ **0x080cbfa0**
/// (120 bytes exactly, `0x080cbfa0..0x080cc017`; the separately linked next
/// function begins at `0x080cc018`).
///
/// Raw `osos.dec` words decode as three aligned `ldr`, shift/mask/OR, and
/// `str` sequences, then an `ldrh`, shift/mask/OR, and `strh`, followed by
/// `bx lr`. The body contains no direct calls. A full-image A32 decode finds
/// no plain inbound `bl` sites and three predicated inbound `blne` sites
/// (0x0807fa3c, 0x080963f8, and 0x0809ee0c). The function reverses three
/// consecutive u32 fields followed by one u16 field and preserves the input
/// pointer in r0; Ghidra's `void` signature loses that return value.
/// Deliberate deviations: none.
///
/// # Safety
///
/// `record` must be non-NULL, four-byte aligned, and writable for fourteen
/// bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bswap_three_u32_and_u16_inplace")]
#[inline(never)]
pub unsafe extern "C" fn bswap_three_u32_and_u16_inplace(record: *mut u32) -> *mut u32 {
    record.write_volatile(record.read_volatile().swap_bytes());
    record.add(1).write_volatile(record.add(1).read_volatile().swap_bytes());
    record.add(2).write_volatile(record.add(2).read_volatile().swap_bytes());

    let tail = record.add(3) as *mut u16;
    tail.write_volatile(tail.read_volatile().swap_bytes());
    record
}

#[cfg(test)]
mod tests {
    use super::bswap_three_u32_and_u16_inplace;

    #[repr(C)]
    struct Record {
        words: [u32; 3],
        tail: u16,
    }

    #[test]
    fn reverses_each_scalar_field_and_preserves_the_pointer() {
        let mut record = Record {
            words: [0x0123_4567, 0x80fe_7fa5, 0],
            tail: 0xa1b2,
        };
        let pointer = record.words.as_mut_ptr();

        let returned = unsafe { bswap_three_u32_and_u16_inplace(pointer) };

        assert_eq!(returned, pointer);
        assert_eq!(record.words, [0x6745_2301, 0xa57f_fe80, 0]);
        assert_eq!(record.tail, 0xb2a1);
    }

    #[test]
    fn does_not_modify_adjacent_records() {
        let mut records = [
            Record { words: [1, 2, 3], tail: 4 },
            Record { words: [0x1020_3040, 0x89ab_cdef, 0xffff_0000], tail: 0x00ff },
            Record { words: [5, 6, 7], tail: 8 },
        ];

        unsafe { bswap_three_u32_and_u16_inplace(records[1].words.as_mut_ptr()) };

        assert_eq!(records[0].words, [1, 2, 3]);
        assert_eq!(records[0].tail, 4);
        assert_eq!(records[1].words, [0x4030_2010, 0xefcd_ab89, 0x0000_ffff]);
        assert_eq!(records[1].tail, 0xff00);
        assert_eq!(records[2].words, [5, 6, 7]);
        assert_eq!(records[2].tail, 8);
    }
}
