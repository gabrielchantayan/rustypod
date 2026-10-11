//! File write with optional flush — `FUN_0805ae18` @ 0x0805ae18.
//!
//! True extent: 84 bytes, [0x0805ae18, 0x0805ae6c); next word is a
//! separate PUSH. Raw A32 words contain one plain BL to stream_write
//! (0x0827899c), one BLNE to platform_file_flush (0x08278938), and a
//! BNE tail branch to map_status_code (0x0809da3c). Reject descriptor -1
//! or data address zero with -50. Write the requested count, translate a
//! nonzero write status, otherwise flush only for flags bit 0 and return
//! zero regardless of flush status. Zero-length writes are not skipped.
//!
//! Deviations: reuse the Rust mapper and flush port. On-device the writer
//! remains the verified retail entry because the existing Rust stream_write
//! core is unwired; hosts use that port's replaceable core. Tests inject
//! operations into the same algorithm without dereferencing target addresses.

#[inline(always)]
unsafe fn write_with_flush(
    descriptor: u32, data: u32, requested: u32, flags: u32, transferred: *mut u32,
    write: impl FnOnce(u32, u32, u32, *mut u32) -> u32,
    flush: impl FnOnce(u32) -> u32,
) -> i32 {
    if descriptor == u32::MAX || data == 0 {
        return -50;
    }
    let status = write(descriptor, requested, data, transferred);
    if status != 0 {
        return crate::status_code_map::map_status_code(status as i32);
    }
    if flags & 1 != 0 {
        let _ = flush(descriptor);
    }
    0
}

/// # Safety
/// Except on rejection, descriptor must name a live platform file, data must
/// cover the requested bytes, and transferred must be writable. A requested
/// flush additionally requires the platform_file_flush object contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn file_write(
    descriptor: u32, data: u32, requested: u32, flags: u32, transferred: *mut u32,
) -> i32 {
    write_with_flush(descriptor, data, requested, flags, transferred,
        |descriptor, requested, data, transferred| {
            #[cfg(target_os = "none")]
            {
                let write: unsafe extern "C" fn(*mut u8, u32, *const u8, *mut u32) -> u32 =
                    core::mem::transmute(0x0827899cusize);
                write(descriptor as usize as *mut u8, requested, data as usize as *const u8, transferred)
            }
            #[cfg(not(target_os = "none"))]
            crate::cxx::stream_write::stream_write(
                descriptor as usize as *mut u8, requested, data as usize as *const u8, transferred)
        },
        |descriptor| crate::cxx::platform_file_flush::platform_file_flush(descriptor as usize as *mut u8))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn rejected_arguments_do_not_access_count_or_call_operations() {
        for (descriptor, data) in [(u32::MAX, 1), (0, 0), (u32::MAX, 0)] {
            assert_eq!(unsafe { write_with_flush(descriptor, data, 99, 1, core::ptr::null_mut(),
                |_, _, _, _| panic!("rejected write"), |_| panic!("rejected flush")) }, -50);
        }
    }

    #[test]
    fn partial_errors_translate_without_flushing_and_preserve_progress() {
        for (status, expected) in [(2, -34), (5, -38), (7, -42), (13, -48),
                                   (14, -36), (21, 21), (u32::MAX, -1), (0x80000000, i32::MIN)] {
            let mut count = 9;
            let result = unsafe { write_with_flush(0, 1, 9, 1, &mut count,
                |_, requested, _, count| { count.write(requested - 2); status },
                |_| panic!("failed write must not flush")) };
            assert_eq!(result, expected);
            assert_eq!(count, 7);
        }
    }

    #[test]
    fn success_flushes_only_bit_zero_after_write_and_ignores_flush_errors() {
        for requested in [0, 1, u32::MAX] {
            for flags in [0, 1, 2, 0x80000000, u32::MAX] {
                for flush_status in [0, 5, u32::MAX] {
                    let phase = Cell::new(0);
                    let mut count = 123;
                    let result = unsafe { write_with_flush(0, 1, requested, flags, &mut count,
                        |_, len, _, count| { phase.set(1); count.write(len); 0 },
                        |_| { assert_eq!(phase.get(), 1); phase.set(2); flush_status }) };
                    assert_eq!(result, 0);
                    assert_eq!(count, requested);
                    assert_eq!(phase.get(), if flags & 1 != 0 { 2 } else { 1 });
                }
            }
        }
    }
}
