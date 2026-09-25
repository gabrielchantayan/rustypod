//! An unconditional forward word-range copy helper.

/// copy_word_range — retailOS `FUN_083e9eb8` @ **0x083e9eb8** (**24 bytes
/// exactly**, `0x083e9eb8..0x083e9ed0`; `0x083e9ed0` begins the next distinct
/// function with `push {r0-r6,lr}`). Raw words are `cmp r0,r1; ldrne r3,
/// [r0],#4; strne r3,[r2],#4; bne 0x083e9eb8; mov r0,r2; bx lr`: it copies
/// `[source,end)` forward one aligned 32-bit word at a time and returns the
/// advanced destination. There are two verified inbound `bl` calls: one plain
/// call at 0x08181908 and one predicated `blne` at 0x0817ea10.
///
/// Deliberate deviations: none. Volatile accesses preserve the firmware's
/// ordered load/store loop and prevent LLVM from replacing it with a libc
/// copy routine.
///
/// # Safety
///
/// `[source,end)` must be a valid forward range of aligned `u32` values and
/// the equally long destination range must be valid for writes. Overlap
/// follows the original forward load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_word_range(
    mut source: *const u32,
    end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != end {
        destination.write_volatile(source.read_volatile());
        source = source.add(1);
        destination = destination.add(1);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::copy_word_range;

    fn reference_forward_copy(words: &mut [u32], mut source: usize, end: usize, mut destination: usize) {
        while source != end {
            words[destination] = words[source];
            source += 1;
            destination += 1;
        }
    }

    #[test]
    fn copies_a_nonempty_range_and_returns_advanced_destination() {
        let source = [0x1122_3344, 0x5566_7788, 0xa5a5_a5a5];
        let mut destination = [0; 3];

        let result = unsafe {
            copy_word_range(source.as_ptr(), source.as_ptr().add(source.len()), destination.as_mut_ptr())
        };

        assert_eq!(destination, source);
        assert_eq!(result, destination.as_mut_ptr().wrapping_add(3));
    }

    #[test]
    fn empty_range_leaves_destination_unchanged() {
        let words = [0x1234_5678];
        let mut destination = [0xdead_beef];

        let result = unsafe { copy_word_range(words.as_ptr(), words.as_ptr(), destination.as_mut_ptr()) };

        assert_eq!(destination, [0xdead_beef]);
        assert_eq!(result, destination.as_mut_ptr());
    }

    #[test]
    fn preserves_forward_load_store_order_for_overlaps() {
        for destination in 0..=5 {
            let initial = [1u32, 2, 3, 4, 5, 6, 7, 8];
            let mut expected = initial;
            let mut actual = initial;

            reference_forward_copy(&mut expected, 2, 5, destination);
            let result = unsafe {
                copy_word_range(actual.as_ptr().add(2), actual.as_ptr().add(5), actual.as_mut_ptr().add(destination))
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(result, actual.as_mut_ptr().wrapping_add(destination + 3));
        }
    }
}
