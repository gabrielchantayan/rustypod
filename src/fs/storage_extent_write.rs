//! Write-enabled extent-list storage wrapper.
//!
//! `storage_extent_write` — retailOS `FUN_08136a94` @ load address
//! 0x08136a94, 68 bytes through 0x08136ad8 (next function's push).
//! Raw A32 words verify one outbound plain BL to 0x08136c64, zero
//! predicated BLs, and two inbound plain BLs at 0x081bfbd4 and 0x081c0014.
//! A nonzero write-disabled byte at object offset 0xf9 returns status 0x15
//! without touching outputs. Otherwise forwards the logical block request
//! with operation zero and returns the stock helper's status unchanged.
//!
//! Deviations: reuse the existing verified raw-address extent-transfer seam;
//! host tests inject a behavioral backend because retailOS is unavailable.
//! No target layout, status, or dispatch semantics are changed.

use super::storage_extent_read::storage_extent_transfer;

type Transfer = unsafe fn(*mut u8, u32, u32, *mut u32, *mut u8, u32, u32) -> i32;

#[inline(always)]
unsafe fn write_with(
    extent_list: *mut u8,
    block: u32,
    count: u32,
    completed_blocks: *mut u32,
    buffer: *mut u8,
    flags: u32,
    transfer: Transfer,
) -> i32 {
    if core::ptr::read(extent_list.add(0xf9)) != 0 {
        return 0x15;
    }
    transfer(extent_list, block, count, completed_blocks, buffer, 0, flags)
}

/// Writes logical blocks unless the extent-list object's write gate is set.
///
/// # Safety
/// `extent_list` must be readable through offset 0xf9. When the gate is zero,
/// all arguments must satisfy the stock extent-transfer helper's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn storage_extent_write(
    extent_list: *mut u8,
    block: u32,
    count: u32,
    completed_blocks: *mut u32,
    buffer: *mut u8,
    flags: u32,
) -> i32 {
    write_with(extent_list, block, count, completed_blocks, buffer, flags, storage_extent_transfer)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn forbidden(
        _: *mut u8, _: u32, _: u32, _: *mut u32, _: *mut u8, _: u32, _: u32,
    ) -> i32 {
        panic!("disabled writes must not reach the backend")
    }

    #[test]
    fn every_nonzero_gate_preserves_outputs() {
        let mut object = [0u8; 0xfa];
        for gate in 1..=255 {
            object[0xf9] = gate;
            let mut completed = 0xdead_beef;
            let mut buffer = [0x57u8; 4];
            let before = object;
            let result = unsafe {
                write_with(object.as_mut_ptr(), u32::MAX, 0, &mut completed,
                           buffer.as_mut_ptr(), u32::MAX, forbidden)
            };
            assert_eq!(result, 0x15);
            assert_eq!(completed, 0xdead_beef);
            assert_eq!(buffer, [0x57; 4]);
            assert_eq!(object, before);
            // The real exported path must also reject invalid output pointers.
            assert_eq!(unsafe {
                storage_extent_write(object.as_mut_ptr(), 0, 0,
                                     core::ptr::null_mut(), core::ptr::null_mut(), 0)
            }, 0x15);
        }
    }

    // Small finite backend: two one-byte logical blocks, partial progress on
    // exhaustion, and a flags-selected error. Tests observe actual mutations.
    unsafe fn finite_backend(
        object: *mut u8, block: u32, count: u32, completed: *mut u32,
        buffer: *mut u8, operation: u32, flags: u32,
    ) -> i32 {
        assert_eq!(operation, 0);
        *completed = 0;
        if flags != 0 { return -7; }
        if block >= 2 { return 5; }
        let available = 2 - block;
        let written = count.min(available);
        for i in 0..written {
            *object.add((block + i) as usize) = *buffer.add(i as usize);
        }
        *completed = written;
        if written == count { 0 } else { 5 }
    }

    #[test]
    fn enabled_zero_full_partial_and_failed_writes() {
        for (block, count, flags, expected, progress, data) in [
            (0, 0, 0, 0, 0, [0x11, 0x22]),
            (0, 2, 0, 0, 2, [0xa1, 0xb2]),
            (1, u32::MAX, 0, 5, 1, [0x11, 0xa1]),
            (u32::MAX, 1, 0, 5, 0, [0x11, 0x22]),
            (0, 2, u32::MAX, -7, 0, [0x11, 0x22]),
        ] {
            let mut object = [0u8; 0xfa];
            object[..2].copy_from_slice(&[0x11, 0x22]);
            let mut buffer = [0xa1, 0xb2];
            let mut completed = u32::MAX;
            let result = unsafe {
                write_with(object.as_mut_ptr(), block, count, &mut completed,
                           buffer.as_mut_ptr(), flags, finite_backend)
            };
            assert_eq!(result, expected);
            assert_eq!(completed, progress);
            assert_eq!(&object[..2], &data);
            assert_eq!(object[0xf9], 0);
            assert_eq!(buffer, [0xa1, 0xb2]);
        }
    }
}
