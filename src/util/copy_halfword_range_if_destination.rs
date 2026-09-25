//! A conditional forward halfword-range copy helper.

/// copy_halfword_range_if_destination — retailOS `thunk_FUN_083e94a8` @
/// **0x083e9490** (**40 bytes exactly**, `0x083e9490..0x083e94b8`; the next
/// distinct function starts at `0x083e94b8`).
///
/// Raw firmware establishes that the four-byte entry branches to the loop test
/// at `0x083e94a8`, whose back-edge enters the halfword transfer at
/// `0x083e9494`. Two direct inbound `bl` calls target the entry (0x083e6c04
/// and 0x083e6c40), both unconditional; there are no predicated inbound `bl`
/// calls and no outbound calls. The function advances `source` and
/// `destination` together until `source == end`, copying each 16-bit halfword
/// only when `destination` is non-null (both the load and store are predicated
/// on `destination != 0`), then returns the advanced destination.
///
/// Deliberate deviations: the Rust export incorporates the entry branch rather
/// than reproducing it, so it remains the direct replacement for both callers.
/// `wrapping_add` expresses the firmware's address arithmetic for a null
/// destination without Rust pointer-arithmetic UB. Volatile halfword accesses
/// preserve the firmware's ordered `ldrh`/`strh` loop and prevent LLVM from
/// substituting a libc copy routine.
///
/// # Safety
///
/// When `destination` is non-null, `[source, end)` must be a valid forward
/// range of aligned `u16` values and `[destination, destination + (end -
/// source))` must be valid for writes. Overlap follows the original forward
/// load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_halfword_range_if_destination(
    mut source: *const u16,
    end: *const u16,
    mut destination: *mut u16,
) -> *mut u16 {
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

    use super::copy_halfword_range_if_destination;

    fn reference_conditional_forward_copy(halfwords: &mut [u16], source: usize, end: usize, destination: usize) {
        let mut source = source;
        let mut destination = destination;
        while source != end {
            let value = halfwords[source];
            halfwords[destination] = value;
            source += 1;
            destination += 1;
        }
    }

    #[test]
    fn copies_all_lengths_and_returns_advanced_destination() {
        for length in 0..=6 {
            let source = [0x1122, 0x3344, 0xa5a5, 3, 4, 5];
            let mut destination = [0xdead; 6];
            let result = unsafe {
                copy_halfword_range_if_destination(
                    source.as_ptr(),
                    source.as_ptr().wrapping_add(length),
                    destination.as_mut_ptr(),
                )
            };

            assert_eq!(&destination[..length], &source[..length], "length={length}");
            assert_eq!(result, destination.as_mut_ptr().wrapping_add(length));
        }
    }

    #[test]
    fn preserves_forward_load_store_order_for_overlaps() {
        for destination in 0..=5 {
            let initial = [1u16, 2, 3, 4, 5, 6, 7, 8];
            let mut expected = initial;
            let mut actual = initial;

            reference_conditional_forward_copy(&mut expected, 2, 5, destination);
            let result = unsafe {
                copy_halfword_range_if_destination(
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
            copy_halfword_range_if_destination(
                core::ptr::null(),
                2usize as *const u16,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 2usize as *mut u16);
    }
}
