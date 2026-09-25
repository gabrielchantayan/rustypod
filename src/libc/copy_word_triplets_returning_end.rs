//! copy_word_triplets_returning_end — original: `FUN_083e9bdc` @ 0x083e9bdc (36 bytes).
//!
//! Raw `osos.dec` words establish the exact nine-instruction body from
//! 0x083e9bdc through 0x083e9bfc (`pop {pc}`); the next real function begins
//! at 0x083e9c00. Full-image A32 decoding finds two inbound unconditional plain
//! `bl` sites (0x083e1564 and 0x083e15b4), zero inbound predicated `bl` sites,
//! and no outbound plain or predicated `bl` instructions.
//!
//! It copies each aligned three-word record in the half-open source range to
//! destination, loading all three words before storing the record, then returns
//! the advanced destination cursor. An empty range dereferences neither pointer.
//!
//! Deliberate deviation: volatile word accesses prevent LLVM from replacing this
//! separately linked retail leaf with a memcpy intrinsic; the target-only unique
//! text section prevents identical-code folding with other range-copy ports.

/// Copies aligned three-word records from `[source, source_end)` and returns the destination end.
///
/// # Safety
///
/// `source` and `destination` must be four-byte aligned. `source_end` must be
/// reachable from `source` in positive three-word steps, and both ranges must be
/// valid for every copied record. Overlap has forward, record-grouped semantics.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_word_triplets_returning_end")]
#[inline(never)]
pub unsafe extern "C" fn copy_word_triplets_returning_end(
    mut source: *const u32,
    source_end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != source_end {
        let first = source.read_volatile();
        let second = source.add(1).read_volatile();
        let third = source.add(2).read_volatile();
        destination.write_volatile(first);
        destination.add(1).write_volatile(second);
        destination.add(2).write_volatile(third);
        source = source.add(3);
        destination = destination.add(3);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_word_triplets_returning_end;

    unsafe fn reference_copy(
        mut source: *const u32,
        source_end: *const u32,
        mut destination: *mut u32,
    ) -> *mut u32 {
        while source != source_end {
            let record = [source.read(), source.add(1).read(), source.add(2).read()];
            destination.write(record[0]);
            destination.add(1).write(record[1]);
            destination.add(2).write(record[2]);
            source = source.add(3);
            destination = destination.add(3);
        }
        destination
    }

    #[test]
    fn copies_complete_triplets_and_returns_end() {
        let source = [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 4, 5, 6, 7, 8, 9];
        let mut destination = [0xa5a5_a5a5; 12];
        let returned = unsafe {
            copy_word_triplets_returning_end(source.as_ptr(), source.as_ptr().add(9), destination.as_mut_ptr())
        };

        assert_eq!(returned, unsafe { destination.as_mut_ptr().add(9) });
        assert_eq!(&destination[..9], &source);
        assert_eq!(&destination[9..], &[0xa5a5_a5a5; 3]);
    }

    #[test]
    fn overlap_preserves_forward_record_grouping() {
        let initial = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let mut actual = initial;
        let mut expected = initial;
        let actual_returned = unsafe {
            copy_word_triplets_returning_end(actual.as_ptr(), actual.as_ptr().add(6), actual.as_mut_ptr().add(2))
        };
        let expected_returned = unsafe {
            reference_copy(expected.as_ptr(), expected.as_ptr().add(6), expected.as_mut_ptr().add(2))
        };

        assert_eq!(actual_returned, unsafe { actual.as_mut_ptr().add(8) });
        assert_eq!(actual_returned as usize - actual.as_mut_ptr() as usize, expected_returned as usize - expected.as_mut_ptr() as usize);
        assert_eq!(actual, expected);
    }

    #[test]
    fn empty_range_returns_destination_without_accessing_pointers() {
        let returned = unsafe {
            copy_word_triplets_returning_end(core::ptr::null(), core::ptr::null(), core::ptr::null_mut())
        };
        assert!(returned.is_null());
    }
}
