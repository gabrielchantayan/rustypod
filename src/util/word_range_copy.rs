//! A forward aligned word-range copy helper.

/// word_range_copy — retailOS `FUN_083e9ea0` @ **0x083e9ea0** (**24 bytes
/// exactly**, `0x083e9ea0..0x083e9eb8`; `0x083e9eb8` begins the next distinct
/// function). Raw words are `cmp r0,r1; ldrne r3,[r0],#4; strne r3,[r2],#4;
/// bne 0x083e9ea0; mov r0,r2; bx lr`: copies `[source,end)` forward one
/// aligned 32-bit word at a time and returns the advanced destination. There
/// are two verified inbound plain `bl` calls (0x083de2b4 and 0x083de438), no
/// predicated inbound `bl` calls, and no outbound calls.
/// Deliberate deviations: none in behavior. LLVM folds this byte-identical
/// implementation with `copy_word_range` (retailOS `FUN_083e9eb8`), but
/// `word_range_copy` remains a distinct exported symbol at the shared body.
/// Volatile accesses preserve the firmware's ordered load/store loop and
/// prevent LLVM from replacing it with a libc copy routine.
///
/// # Safety
///
/// `[source,end)` must be a valid forward range of aligned `u32` values and
/// the equally long destination range must be valid for writes. Overlap follows
/// the original forward load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_range_copy(
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

    use super::word_range_copy;

    fn reference_forward_copy(words: &mut [u32], mut source: usize, end: usize, mut destination: usize) {
        while source != end {
            words[destination] = words[source];
            source += 1;
            destination += 1;
        }
    }

    #[test]
    fn copies_each_valid_length_and_returns_advanced_destination() {
        for length in 0..=6 {
            let source = [0x1122_3344, 0x5566_7788, 0xa5a5_a5a5, 4, 5, 6];
            let mut destination = [0xdead_beef; 6];
            let result = unsafe {
                word_range_copy(source.as_ptr(), source.as_ptr().add(length), destination.as_mut_ptr())
            };

            assert_eq!(&destination[..length], &source[..length], "length={length}");
            assert_eq!(result, destination.as_mut_ptr().wrapping_add(length));
        }
    }

    #[test]
    fn preserves_forward_load_store_order_for_overlaps() {
        for destination in 0..=5 {
            let initial = [1u32, 2, 3, 4, 5, 6, 7, 8];
            let mut expected = initial;
            let mut actual = initial;

            reference_forward_copy(&mut expected, 2, 5, destination);
            let result = unsafe {
                word_range_copy(actual.as_ptr().add(2), actual.as_ptr().add(5), actual.as_mut_ptr().add(destination))
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(result, actual.as_mut_ptr().wrapping_add(destination + 3));
        }
    }
}
