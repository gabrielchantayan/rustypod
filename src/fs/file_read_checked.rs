//! Checked file read — `FUN_0805a6e8` @ 0x0805a6e8.
//!
//! True extent: 76 bytes, [0x0805a6e8, 0x0805a734); the next function
//! is MVN r0,#3 / BX lr. Raw A32 has two plain outbound BLs, no predicated
//! BLs, and a BNE tail branch to 0x0809da3c. Whole-image decoding finds two
//! inbound plain BLs (0x0805b7fc, 0x080a7550), no predicated BLs.
//! Reject descriptor -1 or destination zero with -50. Read even a zero
//! count, selecting mode 2 only for flags bit 1; preserve partial progress
//! and translate statuses 2/5/7/13/14 to -35/-39/-43/-48/-37.
//!
//! Deviations: reuse the ported read wrappers. Inline the raw mapper's
//! semantics because the existing map_status_code port is off by one for
//! statuses 2, 5, 7 and 14; do not propagate that unrelated port's defect.

#[inline(always)]
unsafe fn checked_read(
    descriptor: u32, destination: u32, requested: u32, flags: u32, transferred: *mut u32,
    read: impl FnOnce(u32, u32, u32, *mut u32, bool) -> i32,
) -> i32 {
    if descriptor == u32::MAX || destination == 0 {
        return -50;
    }
    match read(descriptor, requested, destination, transferred, flags & 2 != 0) {
        2 => -35,
        5 => -39,
        7 => -43,
        13 => -48,
        14 => -37,
        status => status,
    }
}

/// # Safety
/// Except on rejection, descriptor must identify a live retail file,
/// destination must cover requested bytes, and transferred must be writable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn file_read_checked(
    descriptor: u32, destination: u32, requested: u32, flags: u32, transferred: *mut u32,
) -> i32 {
    checked_read(descriptor, destination, requested, flags, transferred,
        |descriptor, requested, destination, transferred, mode_2| {
            let handle = descriptor as usize as *mut core::ffi::c_void;
            let buffer = destination as usize as *mut u8;
            if mode_2 {
                super::file_read::retail_file_read_mode_2(handle, requested, buffer, transferred)
            } else {
                super::file_read::retail_file_read(handle, requested, buffer, transferred)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_arguments_leave_progress_untouched() {
        for (descriptor, destination) in [(u32::MAX, 1), (0, 0), (u32::MAX, 0)] {
            assert_eq!(unsafe { checked_read(descriptor, destination, 9, 2, core::ptr::null_mut(),
                |_, _, _, _, _| panic!("rejected read")) }, -50);
        }
    }

    #[test]
    fn short_reads_and_errors_preserve_progress_and_translate_exactly() {
        for (status, expected) in [(0, 0), (2, -35), (5, -39), (7, -43), (13, -48),
                                   (14, -37), (1, 1), (15, 15), (-1, -1),
                                   (i32::MIN, i32::MIN), (i32::MAX, i32::MAX)] {
            let mut count = 99;
            let result = unsafe { checked_read(0, 1, 8, 0, &mut count,
                |_, _, _, count, _| { count.write(3); status }) };
            assert_eq!(result, expected);
            assert_eq!(count, 3);
        }
    }

    #[test]
    fn zero_length_reads_are_not_skipped_and_only_bit_one_selects_mode() {
        for flags in [0, 1, 2, 3, 4, 0x80000000, u32::MAX] {
            let mut count = 123;
            assert_eq!(unsafe { checked_read(0, 1, 0, flags, &mut count,
                |_, requested, _, count, mode_2| {
                    assert_eq!(requested, 0);
                    assert_eq!(mode_2, flags & 2 != 0);
                    count.write(0);
                    0
                }) }, 0);
            assert_eq!(count, 0);
        }
    }
}
