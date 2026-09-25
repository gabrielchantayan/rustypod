//! Tail-entry conditional forward word-range copy helper.

/// copy_word_range_if_destination_tail_entry — original:
/// `thunk_FUN_083e9380` @ **0x083e9368** (**4 bytes exactly**,
/// `0x083e9368..0x083e936c`; the next real function boundary is the transfer
/// body at `0x083e936c`).
///
/// Raw firmware is `b 0x083e9380`; that target is the loop test in the
/// 36-byte `0x083e936c..0x083e9390` conditional forward word-copy routine.
/// Two direct inbound plain `bl` calls target this entry (0x083e58c0 and
/// 0x083e58fc); there are no predicated `bl` calls. It advances `source` and
/// `destination` together until `source == end`, copying each 32-bit word only
/// when `destination` is non-null, then returns the advanced destination.
///
/// Deliberate deviations: the Rust export implements the tail-entry behavior
/// directly rather than its four-byte branch. Its empty inline-assembly barrier
/// keeps this otherwise-identical implementation as a distinct hook target.
/// `wrapping_add` represents the firmware's numerical advancement of a null
/// destination without Rust pointer-arithmetic UB. Volatile accesses preserve
/// the ordered `ldr`/`str` loop and prevent LLVM from substituting a libc copy
/// routine.
///
/// # Safety
///
/// When `destination` is non-null, `[source, end)` must be a valid forward
/// word range and the corresponding destination range must be writable.
/// Overlap follows the original forward load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_word_range_if_destination_tail_entry(
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

    use super::copy_word_range_if_destination_tail_entry;

    fn reference(words: &mut [u32], mut source: usize, end: usize, mut destination: usize) {
        while source != end {
            let word = words[source];
            words[destination] = word;
            source += 1;
            destination += 1;
        }
    }

    #[test]
    fn copies_range_and_returns_advanced_destination() {
        let source = [0x11223344, 0x55667788, 0xa5a5a5a5];
        let mut destination = [0; 3];

        let result = unsafe {
            copy_word_range_if_destination_tail_entry(
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
                copy_word_range_if_destination_tail_entry(
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
            copy_word_range_if_destination_tail_entry(
                core::ptr::null(),
                4usize as *const u32,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 4usize as *mut u32);
    }
}
