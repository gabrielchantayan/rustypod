//! A conditional forward word-range copy helper.

/// copy_word_range_if_destination — original: `thunk_FUN_083e9290` @
/// **0x083e9278** (**40 bytes exactly**, `0x083e9278..0x083e92a0`; the next
/// distinct function starts at `0x083e92a0` with an identical body).
///
/// Raw firmware establishes that the four-byte entry is a branch to the loop
/// test at `0x083e9290`, whose back-edge enters the word transfer at
/// `0x083e927c`. Four direct inbound `bl` calls target the entry
/// (0x083e4fd0, 0x083e5024, 0x083e50a4, 0x083e50e4), all unconditional;
/// there are no predicated `bl` calls. The function advances `source` and
/// `destination` together until `source == end`, copying each 32-bit word
/// only when `destination` is non-null (both the load and the store are
/// predicated on `destination != 0`), then returns the advanced destination.
///
/// Deliberate deviations: the Rust export incorporates the entry branch rather
/// than reproducing it, so it remains the direct replacement for all four
/// callers. `wrapping_add` expresses the firmware's address arithmetic for a
/// null destination without Rust pointer-arithmetic UB. Volatile word accesses
/// preserve the original ordered `ldr`/`str` loop and prevent LLVM from
/// substituting a libc copy routine.
///
/// # Safety
///
/// When `destination` is non-null, `[source, end)` must be a valid forward
/// word range and `[destination, destination + (end - source))` must be valid
/// for writes. Overlap follows the original forward load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_word_range_if_destination(
    mut source: *const u32,
    end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
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

    use super::copy_word_range_if_destination;

    fn reference_conditional_forward_copy(words: &mut [u32], source: usize, end: usize, destination: usize) {
        let mut source = source;
        let mut destination = destination;
        while source != end {
            let value = words[source];
            words[destination] = value;
            source += 1;
            destination += 1;
        }
    }

    #[test]
    fn copies_range_and_returns_advanced_destination() {
        let source = [0x11223344, 0x55667788, 0xa5a5a5a5];
        let mut destination = [0; 3];

        let result = unsafe {
            copy_word_range_if_destination(
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

            reference_conditional_forward_copy(&mut expected, 2, 5, destination);
            let result = unsafe {
                copy_word_range_if_destination(
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
            copy_word_range_if_destination(
                core::ptr::null(),
                4usize as *const u32,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 4usize as *mut u32);
    }
}
