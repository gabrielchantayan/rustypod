//! Forward byte-range copy loop entry with a non-null destination.

/// copy_range_nonnull_destination_loop_entry_9138 — retailOS
/// `thunk_FUN_083e9150` @ **0x083e9138** (**4 bytes exactly**,
/// `0x083e9138..0x083e913c`). Raw firmware is `b 0x083e9150`, entering the
/// loop test of the separately entered 32-byte transfer body at
/// `0x083e913c..0x083e9160`; the next real function boundary is `0x083e9160`.
/// Two verified inbound plain `bl` calls (0x083e4154 and 0x083e4188), zero
/// predicated `bl` calls, and no outbound calls. It copies `[source, end)`
/// forward, advancing both cursors, and returns the advanced destination.
///
/// Deliberate deviations: Rust implements the branch entry directly. The
/// branch skips the transfer body's null-destination test, so this entry
/// requires a non-null destination; a unique no-code assembly barrier retains
/// it as an independently hookable target. Volatile byte accesses preserve the
/// original ordered `ldrb`/`strb` loop and prevent libc-copy substitution.
///
/// # Safety
///
/// `[source, end)` must be a valid forward byte range and
/// `[destination, destination + (end - source))` must be valid for writes.
/// `destination` must be non-null. Overlap follows the original forward
/// load/store order.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn copy_range_nonnull_destination_loop_entry_9138(
    mut source: *const u8,
    end: *const u8,
    mut destination: *mut u8,
) -> *mut u8 {
    core::arch::asm!("/* copy_range_nonnull_destination_loop_entry_9138 */", options(nostack, preserves_flags));
    while source != end {
        destination.write_volatile(source.read_volatile());
        source = source.wrapping_add(1);
        destination = destination.wrapping_add(1);
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::copy_range_nonnull_destination_loop_entry_9138;

    fn reference_forward_copy(bytes: &mut [u8], mut source: usize, end: usize, mut destination: usize) {
        while source != end {
            let value = bytes[source];
            bytes[destination] = value;
            source += 1;
            destination += 1;
        }
    }

    #[test]
    fn copies_empty_and_nonempty_ranges_and_returns_cursor() {
        let source = [0x11, 0x22, 0x33];
        let mut destination = [0; 3];

        let result = unsafe {
            copy_range_nonnull_destination_loop_entry_9138(
                source.as_ptr(),
                source.as_ptr().wrapping_add(source.len()),
                destination.as_mut_ptr(),
            )
        };

        assert_eq!(destination, source);
        assert_eq!(result, destination.as_mut_ptr().wrapping_add(3));

        let empty_result = unsafe {
            copy_range_nonnull_destination_loop_entry_9138(
                source.as_ptr(),
                source.as_ptr(),
                destination.as_mut_ptr(),
            )
        };
        assert_eq!(empty_result, destination.as_mut_ptr());
    }

    #[test]
    fn preserves_forward_load_store_order_for_overlaps() {
        for destination in 0..=5 {
            let initial = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
            let mut expected = initial;
            let mut actual = initial;

            reference_forward_copy(&mut expected, 2, 5, destination);
            let result = unsafe {
                copy_range_nonnull_destination_loop_entry_9138(
                    actual.as_ptr().wrapping_add(2),
                    actual.as_ptr().wrapping_add(5),
                    actual.as_mut_ptr().wrapping_add(destination),
                )
            };

            assert_eq!(actual, expected, "destination={destination}");
            assert_eq!(result, actual.as_mut_ptr().wrapping_add(destination + 3));
        }
    }
}
