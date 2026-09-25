//! Conditional forward word-range copy loop entry.

/// copy_word_range_if_destination_loop_entry_91d8 — retailOS
/// `thunk_FUN_083e91f0` @ **0x083e91d8** (**4 bytes exactly**,
/// `0x083e91d8..0x083e91dc`). Raw firmware is `b 0x083e91f0`, entering the
/// loop test of the separately entered 32-byte transfer body at
/// `0x083e91dc..0x083e91fc`; the next real function boundary is `0x083e91fc`.
/// It conditionally copies aligned words in `[source, end)` forward when
/// `destination` is non-null, advances both cursors, and returns the advanced
/// destination. Two verified inbound plain `bl` calls (0x083e49b4 and
/// 0x083e49f0), zero predicated `bl` calls, and no outbound calls.
///
/// Deliberate deviations: Rust implements the branch entry's complete behavior
/// directly. A unique no-code assembly barrier retains this otherwise-identical
/// implementation as an independently hookable target. `wrapping_add` models
/// cursor address arithmetic without Rust pointer-arithmetic UB; volatile
/// accesses retain ordered loads and stores and prevent libc-copy substitution.
///
/// # Safety
///
/// When `destination` is non-null, `[source, end)` must be a valid forward
/// aligned word range and the corresponding destination range must be writable.
/// Overlap follows the original forward load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_word_range_if_destination_loop_entry_91d8(
    mut source: *const u32,
    end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    core::arch::asm!("/* copy_word_range_if_destination_loop_entry_91d8 */", options(nostack, preserves_flags));
    while source != end {
        if !destination.is_null() {
            destination.write_volatile(source.read_volatile());
        }
        source = source.wrapping_add(1);
        destination = destination.wrapping_add(1);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_word_range_if_destination_loop_entry_91d8;

    fn reference(words: &mut [u32], mut source: usize, end: usize, mut destination: usize) {
        while source != end {
            let value = words[source];
            words[destination] = value;
            source += 1;
            destination += 1;
        }
    }

    #[test]
    fn copies_empty_and_nonempty_ranges_and_returns_cursor() {
        let source = [0x11223344, 0x55667788, 0xa5a5a5a5];
        let mut destination = [0; 3];

        let empty_result = unsafe {
            copy_word_range_if_destination_loop_entry_91d8(
                source.as_ptr(),
                source.as_ptr(),
                destination.as_mut_ptr(),
            )
        };
        assert_eq!(empty_result, destination.as_mut_ptr());

        let result = unsafe {
            copy_word_range_if_destination_loop_entry_91d8(
                source.as_ptr(),
                source.as_ptr().wrapping_add(source.len()),
                destination.as_mut_ptr(),
            )
        };
        assert_eq!(destination, source);
        assert_eq!(result, destination.as_mut_ptr().wrapping_add(3));
    }

    #[test]
    fn preserves_forward_load_store_order_for_overlaps() {
        for destination in 0..=5 {
            let initial = [1u32, 2, 3, 4, 5, 6, 7, 8];
            let mut expected = initial;
            let mut actual = initial;
            reference(&mut expected, 2, 5, destination);

            let result = unsafe {
                copy_word_range_if_destination_loop_entry_91d8(
                    actual.as_ptr().wrapping_add(2),
                    actual.as_ptr().wrapping_add(5),
                    actual.as_mut_ptr().wrapping_add(destination),
                )
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(result, actual.as_mut_ptr().wrapping_add(destination + 3));
        }
    }

    #[test]
    fn null_destination_skips_source_access_and_advances_numerically() {
        let result = unsafe {
            copy_word_range_if_destination_loop_entry_91d8(
                core::ptr::null(),
                4usize as *const u32,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 4usize as *mut u32);
    }
}
