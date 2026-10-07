//! Owned storage initialization — `FUN_08150238` @ `0x08150238`.
//!
//! True extent [0x08150238, 0x08150280): 72 instruction bytes, ending
//! before the next PUSH prologue. Verified outgoing calls: two plain BLs,
//! zero predicated BLs, to operator_new_tag3 and strlen.
//! Allocate the requested capacity; on success store the allocation and
//! capacity, with ownership byte 1. On failure store the borrowed fallback
//! and its unguarded string length, with ownership byte 0. Return receiver.
//! Preserve padding bytes +1..+3 and all bytes beyond +11. No behavioral
//! deviations; pointer fields remain target-width u32 words on hosts.

use crate::heap::veneers::operator_new_tag3;
use crate::libc::strlen::strlen;

type Allocate = unsafe extern "C" fn(usize) -> *mut u8;

#[inline(always)]
unsafe fn initialize_with(
    storage: *mut u8, capacity: u32, fallback: *mut u8, allocate: Allocate,
) -> *mut u8 {
    let allocation = allocate(capacity as usize);
    let words = storage.cast::<u32>();
    if !allocation.is_null() {
        words.add(1).write(allocation as usize as u32);
        words.add(2).write(capacity);
    } else {
        words.add(1).write(fallback as usize as u32);
        words.add(2).write(strlen(fallback) as u32);
    }
    storage.write(u8::from(!allocation.is_null()));
    storage
}

/// # Safety
/// `storage` must be aligned and writable for 12 bytes. If allocation fails,
/// `fallback` must point to a readable NUL-terminated string. The returned
/// allocation or fallback address must fit the target's 32-bit pointer field.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_storage_initialize(
    storage: *mut u8, capacity: u32, fallback: *mut u8,
) -> *mut u8 {
    initialize_with(storage, capacity, fallback, operator_new_tag3)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn fail(_: usize) -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn succeed(size: usize) -> *mut u8 {
        // Opaque target address: initialization must not touch the allocation.
        (0x1000usize + size) as *mut u8
    }

    #[test]
    fn successful_allocation_preserves_padding_and_does_not_read_fallback() {
        for capacity in [0, 1, 0x3500, u32::MAX] {
            let mut record = [0xa5a5_a5a5u32; 4];
            let storage = record.as_mut_ptr().cast::<u8>();
            unsafe {
                assert_eq!(initialize_with(storage, capacity, core::ptr::null_mut(), succeed), storage);
            }
            assert_eq!(record, [0xa5a5_a501, (0x1000u64 + capacity as u64) as u32,
                               capacity, 0xa5a5_a5a5]);
        }
    }

    #[test]
    fn failure_borrows_fallback_and_measures_only_through_first_nul() {
        for text in [&b"\0ignored"[..], &b"x\0ignored"[..], &b"fallback\0ignored"[..]] {
            let mut record = [0xffff_ffffu32; 4];
            let storage = record.as_mut_ptr().cast::<u8>();
            let fallback = text.as_ptr() as *mut u8;
            unsafe {
                assert_eq!(initialize_with(storage, 0x3500, fallback, fail), storage);
            }
            let length = text.iter().position(|&byte| byte == 0).unwrap() as u32;
            assert_eq!(record, [0xffff_ff00, fallback as usize as u32, length, 0xffff_ffff]);
        }
    }
}
