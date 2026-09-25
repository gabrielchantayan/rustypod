//! A conditional forward word-range copy helper used during vector relocation.

/// relocation_word_range_copy — original: `thunk_FUN_083e92e0` @
/// **0x083e92c8** (**40 bytes exactly**, `0x083e92c8..0x083e92f0`; the next
/// distinct function starts at `0x083e92f0`).
///
/// Raw firmware establishes that the four-byte entry branches to the loop test
/// at `0x083e92e0`, whose back-edge enters the word transfer at `0x083e92cc`.
/// Two direct inbound `bl` calls target the entry (0x083e5380, 0x083e53bc),
/// both unconditional; there are no predicated inbound `bl` calls or outbound
/// calls. The function advances `source` and `destination` together until
/// `source == end`, copying each 32-bit word only when `destination` is
/// non-null (both the load and store are predicated on `destination != 0`),
/// then returns the advanced destination. The two callers relocate either side
/// of an insertion in a growable word vector.
///
/// Deliberate deviations: the Rust export incorporates the entry branch rather
/// than reproducing it. `wrapping_add` expresses the firmware's address
/// arithmetic for a null destination without Rust pointer-arithmetic UB.
/// Volatile word accesses preserve the original ordered `ldr`/`str` loop and
/// prevent LLVM from substituting a libc copy routine. Empty target inline
/// assembly keeps this externally named target distinct from its byte-identical
/// sibling at 0x083e9278; it emits no runtime instruction.
///
/// # Safety
///
/// When `destination` is non-null, `[source, end)` must be a valid forward
/// word range and `[destination, destination + (end - source))` must be valid
/// for writes. Overlap follows the original forward load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn relocation_word_range_copy(
    mut source: *const u32,
    end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    #[cfg(target_os = "none")]
    core::arch::asm!("", options(nomem, nostack, preserves_flags));
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

    use super::relocation_word_range_copy;

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
            relocation_word_range_copy(
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
                relocation_word_range_copy(
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
    fn empty_range_does_not_access_either_pointer() {
        let pointer = 4usize as *const u32;
        let result = unsafe { relocation_word_range_copy(pointer, pointer, core::ptr::null_mut()) };

        assert_eq!(result, core::ptr::null_mut());
    }

    #[test]
    fn null_destination_skips_source_access_and_advances_numerically() {
        let result = unsafe {
            relocation_word_range_copy(
                core::ptr::null(),
                4usize as *const u32,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 4usize as *mut u32);
    }
}
