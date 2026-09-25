//! 16-byte record-range copy with a nullable destination — original:
//! `FUN_083e899c` at load address `0x083e899c` (52 bytes).
//!
//! Raw `osos.dec` establishes the exact extent `0x083e899c..0x083e89cf`:
//! `push {r4,r5,lr}`, a loop that conditionally `ldm`/`stm`s four words, and
//! `pop {r4,r5,pc}`. The next independently linked function begins at
//! `0x083e89d0`. Full-image A32 decoding finds two inbound plain direct `bl`
//! calls (`0x083e073c` and `0x083e0778`), zero inbound predicated direct `bl`
//! calls, and no body calls.
//!
//! The loop forward-copies each 16-byte record in `[source, source_end)` when
//! `destination` is non-null, advances both cursors after every record, and
//! returns the advanced destination cursor. Deliberate deviation: volatile
//! word accesses preserve the retail ordered four-word load/store grouping and
//! prevent LLVM from substituting a libc copy routine.

/// Copies 16-byte records from `source` through `source_end` to `destination`
/// when it is non-null.
///
/// # Safety
///
/// `source` and `source_end` must delimit a forward-reachable range in
/// 16-byte increments. A non-null `destination` must identify writable storage
/// for the same number of records. Like retailOS, overlapping ranges copy
/// forward. A null destination is only safe for an empty or one-record range:
/// retailOS advances it before the next null check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record16_range_copy_if_destination")]
#[inline(never)]
pub unsafe extern "C" fn record16_range_copy_if_destination(
    mut source: *const u32,
    source_end: *const u32,
    mut destination: *mut u32,
) -> *mut u32 {
    while source != source_end {
        if !destination.is_null() {
            let first = unsafe { source.read_volatile() };
            let second = unsafe { source.add(1).read_volatile() };
            let third = unsafe { source.add(2).read_volatile() };
            let fourth = unsafe { source.add(3).read_volatile() };
            unsafe {
                destination.write_volatile(first);
                destination.add(1).write_volatile(second);
                destination.add(2).write_volatile(third);
                destination.add(3).write_volatile(fourth);
            }
        }
        source = source.wrapping_add(4);
        destination = destination.wrapping_add(4);
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::record16_range_copy_if_destination;

    #[test]
    fn copies_complete_records_and_returns_advanced_destination() {
        let source = [11_u32, 12, 13, 14, 21, 22, 23, 24];
        let mut destination = [0_u32; 8];
        let end = unsafe { source.as_ptr().add(source.len()) };
        let result = unsafe {
            record16_range_copy_if_destination(source.as_ptr(), end, destination.as_mut_ptr())
        };

        assert_eq!(destination, source);
        assert_eq!(result, unsafe { destination.as_mut_ptr().add(destination.len()) });
    }

    #[test]
    fn leaves_destination_unchanged_for_an_empty_range() {
        let source = [1_u32, 2, 3, 4];
        let mut destination = [9_u32; 4];
        let result = unsafe {
            record16_range_copy_if_destination(source.as_ptr(), source.as_ptr(), destination.as_mut_ptr())
        };
        assert_eq!(destination, [9; 4]);
        assert_eq!(result, destination.as_mut_ptr());
    }

    #[test]
    fn null_destination_advances_without_reading_source() {
        let result = unsafe {
            record16_range_copy_if_destination(
                core::ptr::null(),
                16_usize as *const u32,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result as usize, 16);
    }

    #[test]
    fn preserves_grouped_forward_overlap() {
        let mut words = [1_u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let source = words.as_ptr();
        let end = unsafe { source.add(8) };
        unsafe {
            record16_range_copy_if_destination(source, end, words.as_mut_ptr().add(4));
        }

        assert_eq!(words, [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4]);
    }
}
