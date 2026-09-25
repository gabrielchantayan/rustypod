//! Conditional forward two-word-range copy helper.

/// copy_u32_pair_range_if_destination — retailOS `FUN_083e8b74` @
/// **0x083e8b74** (**44 bytes exactly**, `0x083e8b74..0x083e8ba0`; the next
/// independently linked function begins with `push {r4-r6,lr}` at
/// `0x083e8ba0`).
///
/// Raw words are `push {lr}; b loop_test; cmp r2,#0; ldmne r0,{r12,lr};
/// stmne r2,{r12,lr}; add r2,#8; add r0,#8; cmp r0,r1; bne copy; mov r0,r2;
/// pop {pc}`. It advances `source` and `destination` over `[source,end)` in
/// aligned two-`u32` records, copying a complete record only while the current
/// destination is non-null, and returns the advanced destination. Full-image
/// A32 decoding verifies two inbound plain `bl` calls (0x083e1a3c,
/// 0x083e1a7c), zero inbound predicated `bl` calls, and no outbound calls.
///
/// Deliberate deviations: Rust incorporates the entry branch into the loop.
/// `wrapping_add` expresses the firmware's numerical null-cursor advance
/// without pointer-arithmetic UB. Volatile accesses preserve the ordered
/// grouped loads and stores and prevent LLVM libc-copy substitution.
///
/// # Safety
///
/// When `destination` is non-null, `[source,end)` must be an aligned range of
/// complete two-`u32` records, and the equally long destination range must be
/// writable. Overlap follows the original forward load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.copy_u32_pair_range_if_destination")]
#[inline(never)]
pub unsafe extern "C" fn copy_u32_pair_range_if_destination(
    mut source: *const u32,
    end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != end {
        if !destination.is_null() {
            let first = source.read_volatile();
            let second = source.add(1).read_volatile();
            destination.write_volatile(first);
            destination.add(1).write_volatile(second);
        }
        source = source.add(2);
        destination = destination.wrapping_add(2);
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::copy_u32_pair_range_if_destination;

    fn reference(words: &mut [u32], mut source: usize, end: usize, mut destination: usize) {
        while source != end {
            let first = words[source];
            let second = words[source + 1];
            words[destination] = first;
            words[destination + 1] = second;
            source += 2;
            destination += 2;
        }
    }

    #[test]
    fn copies_complete_record_ranges_and_returns_advanced_destination() {
        for records in 0..=3 {
            let source = [0x1122_3344, 0x5566_7788, 0xa5a5_a5a5, 4, 5, 6];
            let mut destination = [0xdead_beef; 6];
            let returned = unsafe {
                copy_u32_pair_range_if_destination(
                    source.as_ptr(),
                    source.as_ptr().add(records * 2),
                    destination.as_mut_ptr(),
                )
            };
            assert_eq!(&destination[..records * 2], &source[..records * 2], "records={records}");
            assert_eq!(returned, destination.as_mut_ptr().wrapping_add(records * 2));
        }
    }

    #[test]
    fn preserves_grouped_forward_copy_order_for_overlaps() {
        let initial = [1u32, 2, 3, 4, 5, 6, 7, 8];
        for destination in 0..=4 {
            let mut expected = initial;
            let mut actual = initial;
            reference(&mut expected, 2, 6, destination);
            let returned = unsafe {
                copy_u32_pair_range_if_destination(
                    actual.as_ptr().add(2),
                    actual.as_ptr().add(6),
                    actual.as_mut_ptr().add(destination),
                )
            };
            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(returned, actual.as_mut_ptr().wrapping_add(destination + 4));
        }
    }

    #[test]
    fn null_destination_skips_one_record_and_advances_numerically() {
        let returned = unsafe {
            copy_u32_pair_range_if_destination(
                core::ptr::null(),
                core::ptr::null::<u32>().wrapping_add(2),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(returned as usize, 8);
    }
}
