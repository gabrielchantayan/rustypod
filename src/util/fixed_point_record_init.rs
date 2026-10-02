//! Initializes the sparse fixed-point defaults of an embedded record.

/// Original: `FUN_0827d6b4` @ **0x0827d6b4**, **48 bytes**, ending at the
/// distinct next function's push at 0x0827d6e4.
///
/// Raw ARM decoding verifies two plain incoming BLs (0x0827bcc0 and
/// 0x0827bcd4), zero predicated incoming BLs, and zero outgoing BLs.
/// Clears words 0, 1, 3, and 4; sets words 5 through 8 to 0x10000; clears
/// only byte 36. Word 2 and bytes 37 onward are untouched. The enclosing
/// constructor initializes two such records. Their finer field identities
/// are not established; 0x10000 is the fixed-point unity default.
/// Returns the original pointer, as the raw r0 pass-through and both callers
/// require (despite Ghidra's void declaration).
///
/// Deliberate deviations: none.
///
/// # Safety
/// `record` must be non-NULL, four-byte aligned, and writable for 37 bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.fixed_point_record_init")]
#[inline(never)]
pub unsafe extern "C" fn fixed_point_record_init(record: *mut u32) -> *mut u32 {
    record.write(0);
    record.add(1).write(0);
    record.add(3).write(0);
    record.add(4).write(0);
    record.add(5).write(0x10000);
    record.add(6).write(0x10000);
    record.add(7).write(0x10000);
    record.add(8).write(0x10000);
    record.cast::<u8>().add(36).write(0);
    record
}

#[cfg(test)]
mod tests {
    use super::fixed_point_record_init;

    #[test]
    fn initializes_defaults_without_touching_holes_or_neighbors() {
        for fill in [0, u32::MAX, 0x1234_5678, 0x8000_0001] {
            let mut words = [fill; 12];
            let record = unsafe { words.as_mut_ptr().add(1) };
            assert_eq!(unsafe { fixed_point_record_init(record) }, record);
            let mut tail = fill.to_ne_bytes();
            tail[0] = 0;
            assert_eq!(words, [fill, 0, 0, fill, 0, 0, 0x10000,
                0x10000, 0x10000, 0x10000, u32::from_ne_bytes(tail), fill]);
        }
    }

    #[test]
    fn repeated_initialization_preserves_caller_owned_word_and_flag_neighbors() {
        let mut words = [u32::MAX; 10];
        unsafe { fixed_point_record_init(words.as_mut_ptr()) };
        words[2] = 0xdead_beef;
        words[5] = 7;
        words[9] = u32::from_ne_bytes([9, 10, 11, 12]);
        unsafe { fixed_point_record_init(words.as_mut_ptr()) };
        assert_eq!(words, [0, 0, 0xdead_beef, 0, 0, 0x10000, 0x10000,
            0x10000, 0x10000, u32::from_ne_bytes([0, 10, 11, 12])]);
    }
}
