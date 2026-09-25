//! 8-byte record-range copy with a nullable destination — retailOS
//! `FUN_083e8908` at load address `0x083e8908` (44 bytes).
//!
//! Raw `osos.dec` establishes the exact extent `0x083e8908..0x083e8933`:
//! `push {lr}`, a loop that conditionally `ldmne`/`stmne`s two words, and
//! `pop {pc}`. The next independently linked function begins at `0x083e8934`.
//! Full-image A32 decoding finds two inbound plain direct `bl` calls
//! (`0x083e0354` and `0x083e0394`), zero inbound predicated direct `bl` calls,
//! and no body calls.
//!
//! The loop forward-copies each 8-byte record in `[source, source_end)` when
//! `destination` is non-null, advances both cursors after every record, and
//! returns the advanced destination cursor. Deliberate deviation: volatile word
//! accesses preserve the retail ordered two-word load/store grouping and
//! prevent LLVM from substituting a libc copy routine.

/// Copies 8-byte records from `source` through `source_end` to `destination`
/// when it is non-null.
///
/// # Safety
///
/// `source` and `source_end` must delimit a forward-reachable range in 8-byte
/// increments. A non-null `destination` must identify writable storage for the
/// same number of records. Like retailOS, overlapping ranges copy forward. A
/// null destination is only safe for an empty or one-record range: retailOS
/// advances it before the next null check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record8_range_copy_if_destination")]
#[inline(never)]
pub unsafe extern "C" fn record8_range_copy_if_destination(
    mut source: *const u32,
    source_end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != source_end {
        if !destination.is_null() {
            let first = unsafe { source.read_volatile() };
            let second = unsafe { source.add(1).read_volatile() };
            unsafe {
                destination.write_volatile(first);
                destination.add(1).write_volatile(second);
            }
        }
        source = source.wrapping_add(2);
        destination = destination.wrapping_add(2);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::record8_range_copy_if_destination;

    #[test]
    fn copies_complete_records_and_returns_advanced_destination() {
        let source = [11_u32, 12, 21, 22];
        let mut destination = [0_u32; 4];
        let result = unsafe {
            record8_range_copy_if_destination(
                source.as_ptr(),
                source.as_ptr().add(source.len()),
                destination.as_mut_ptr(),
            )
        };

        assert_eq!(destination, source);
        assert_eq!(result, unsafe { destination.as_mut_ptr().add(destination.len()) });
    }

    #[test]
    fn leaves_destination_unchanged_for_an_empty_range() {
        let source = [1_u32, 2];
        let mut destination = [9_u32; 2];
        let result = unsafe {
            record8_range_copy_if_destination(source.as_ptr(), source.as_ptr(), destination.as_mut_ptr())
        };

        assert_eq!(destination, [9; 2]);
        assert_eq!(result, destination.as_mut_ptr());
    }

    #[test]
    fn null_destination_advances_without_reading_source() {
        let result = unsafe {
            record8_range_copy_if_destination(
                core::ptr::null(),
                8_usize as *const u32,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result as usize, 8);
    }

    #[test]
    fn preserves_grouped_forward_overlap() {
        let mut words = [1_u32, 2, 3, 4, 5, 6];
        let source = words.as_ptr();
        unsafe {
            record8_range_copy_if_destination(source, source.add(4), words.as_mut_ptr().add(2));
        }

        assert_eq!(words, [1, 2, 1, 2, 1, 2]);
    }
}
