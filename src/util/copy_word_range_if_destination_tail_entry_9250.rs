//! Conditional forward word-range copy tail entry.

/// copy_word_range_if_destination_tail_entry_9250 — retailOS
/// `thunk_FUN_083e9268` @ **0x083e9250** (**4 bytes exactly**,
/// `0x083e9250..0x083e9254`; the next real function boundary is the transfer
/// body at `0x083e9254`). Raw firmware is `b 0x083e9268`, entering that body's
/// loop test. It conditionally copies aligned words in `[source, end)` forward
/// when `destination` is non-null, advances both cursors, and returns the
/// advanced destination. Two verified inbound plain `bl` calls (0x083e4e94,
/// 0x083e4ed0), zero predicated `bl` calls, and no outbound calls.
///
/// Deliberate deviations: Rust implements the branch entry's complete behavior
/// directly. The empty assembly barrier retains this byte-identical body as an
/// independently hookable target. `wrapping_add` models cursor address
/// arithmetic without Rust pointer-arithmetic UB; volatile access
/// retains ordered loads and stores and prevents libc-copy substitution.
///
/// # Safety
///
/// When `destination` is non-null, `[source, end)` must be a valid forward
/// aligned word range and the corresponding destination range must be writable.
/// Overlap follows the original forward load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_word_range_if_destination_tail_entry_9250(
    mut source: *const u32,
    end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    core::arch::asm!("", options(nostack, preserves_flags));
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

    use super::copy_word_range_if_destination_tail_entry_9250;

    fn reference(words: &mut [u32], mut source: usize, end: usize, mut destination: usize) {
        while source != end {
            if destination != 0 {
                words[destination] = words[source];
            }
            source += 1;
            destination += 1;
        }
    }

    #[test]
    fn copies_empty_and_nonempty_ranges_and_returns_cursor() {
        for length in 0..=6 {
            let source = [0x1122_3344, 0x5566_7788, 0xa5a5_a5a5, 4, 5, 6];
            let mut destination = [0xdead_beef; 6];
            let result = unsafe {
                copy_word_range_if_destination_tail_entry_9250(
                    source.as_ptr(),
                    source.as_ptr().add(length),
                    destination.as_mut_ptr(),
                )
            };

            assert_eq!(&destination[..length], &source[..length], "length={length}");
            assert_eq!(result, destination.as_mut_ptr().wrapping_add(length));
        }
    }

    #[test]
    fn preserves_forward_load_store_order_for_overlaps() {
        for destination in 1..=5 {
            let initial = [1u32, 2, 3, 4, 5, 6, 7, 8];
            let mut expected = initial;
            let mut actual = initial;

            reference(&mut expected, 2, 5, destination);
            let result = unsafe {
                copy_word_range_if_destination_tail_entry_9250(
                    actual.as_ptr().add(2),
                    actual.as_ptr().add(5),
                    actual.as_mut_ptr().add(destination),
                )
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(result, actual.as_mut_ptr().wrapping_add(destination + 3));
        }
    }

    #[test]
    fn null_destination_skips_source_access_and_advances_numerically() {
        let result = unsafe {
            copy_word_range_if_destination_tail_entry_9250(
                core::ptr::null(),
                4usize as *const u32,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result as usize, 4);
    }
}
