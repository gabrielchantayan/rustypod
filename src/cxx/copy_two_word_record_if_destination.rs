//! `copy_two_word_record_if_destination` — original: `FUN_083d800c` @ 0x083d800c
//! (16 bytes).
//!
//! Raw `osos.dec` words establish the exact four-instruction extent
//! 0x083d800c..0x083d801b: `movs r0,r1`, `ldmiane r2,{r1,r2}`,
//! `stmiane r0,{r1,r2}`, and `bx lr`. The next independently linked function
//! begins at 0x083d801c. Whole-image ARM branch decoding finds two inbound
//! unconditional plain `bl` calls (0x083e6efc and 0x083e6f7c), no inbound
//! predicated `bl` calls, and no body `bl` instructions. A third caller at
//! 0x083e7164 reaches this body through a predicated `bne` tail branch.
//!
//! Algorithm: replace the ignored context in `r0` with `destination`; if it is
//! non-null, load both aligned source words before storing either destination
//! word, then return `destination`. A null destination returns null without
//! accessing `source`. Deliberate deviations: none.

/// Copy an eight-byte record when `destination` is non-null.
///
/// The first ABI argument is retained because the original receives a context
/// in `r0`, then overwrites it with `destination` before testing it.
///
/// # Safety
///
/// When `destination` is non-null, `source` and `destination` must each be
/// valid and four-byte aligned for two `u32` accesses. The two source reads
/// precede both destination writes, preserving the original's overlap behavior.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_two_word_record_if_destination")]
#[inline(never)]
pub unsafe extern "C" fn copy_two_word_record_if_destination(
    _context: *mut u8,
    destination: *mut u32,
    source: *const u32,
) -> *mut u32 {
    if destination.is_null() {
        return core::ptr::null_mut();
    }

    let first = source.read_volatile();
    let second = source.add(1).read_volatile();
    destination.write_volatile(first);
    destination.add(1).write_volatile(second);
    destination
}

#[cfg(test)]
mod tests {
    use super::copy_two_word_record_if_destination;

    #[test]
    fn null_destination_returns_null_without_reading_source() {
        let result = unsafe {
            copy_two_word_record_if_destination(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::dangling(),
            )
        };

        assert!(result.is_null());
    }

    #[test]
    fn copies_both_words_and_returns_destination() {
        let source = [0x1122_3344, 0x5566_7788];
        let mut destination = [0; 2];

        let result = unsafe {
            copy_two_word_record_if_destination(
                core::ptr::null_mut(),
                destination.as_mut_ptr(),
                source.as_ptr(),
            )
        };

        assert_eq!(result, destination.as_mut_ptr());
        assert_eq!(destination, source);
    }

    #[test]
    fn snapshots_source_before_overlapping_stores() {
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333];

        unsafe {
            copy_two_word_record_if_destination(
                core::ptr::null_mut(),
                words.as_mut_ptr().add(1),
                words.as_ptr(),
            );
        }

        assert_eq!(words, [0x1111_1111, 0x1111_1111, 0x2222_2222]);
    }
}
