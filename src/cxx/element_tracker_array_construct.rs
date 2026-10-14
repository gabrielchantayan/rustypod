//! Element-tracker array constructor — `FUN_083d4818` @ `0x083d4818`.
//!
//! True extent [0x083d4818, 0x083d48dc): 196 bytes, comprising 160
//! instruction bytes and 36 literal bytes. Next function starts with cmp r1,#0.
//! Whole-image aligned A32 decoding verifies one incoming plain BL at
//! 0x080edb58, nine outgoing plain BLs, and no predicated BLs either way.
//!
//! Initialize six fields, allocate wrapping capacity*4 bytes and clear them.
//! Read the name from runtime tracker record 0x0897bff0 + 4; allocate exactly
//! strlen(name) bytes and strncpy that many bytes from name+1 for lengths
//! <=10, otherwise name+2. The skipped prefix becomes trailing NUL padding.
//! Return this; allocation failures are not checked in the original.
//!
//! Deviations: combine three stable-name length scans; omit the diagnostic
//! at 0x083d4678 (raw word e12fff1e, bx lr) and its unobservable arguments.
//! Native pointers widen host fields, but the ARM layout remains six words.
//! Private providers isolate host fixtures; volatile memory-helper dispatch
//! prevents builtin substitution. No additional allocations or copies.

use super::tracked_slot_array_construct::TrackedSlotArray;
use crate::libc::{memzero::memzero_aligned, strlen::strlen, strncpy::strncpy};

#[inline(always)]
unsafe fn construct_with(
    array: *mut TrackedSlotArray, options: u32, capacity: u32, growth: u32,
    mut allocate: impl FnMut(usize) -> *mut u8,
    name_source: impl FnOnce() -> *const u8,
) -> *mut TrackedSlotArray {
    array.write(TrackedSlotArray {
        data: core::ptr::null_mut(), slots: capacity, used: 0,
        options, growth, tracker_label: core::ptr::null_mut(),
    });
    let bytes = capacity.wrapping_shl(2) as usize;
    let storage = allocate(bytes);
    (*array).data = storage.cast();
    let zero = memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
    core::ptr::read_volatile(&zero)(storage, bytes);
    let name = name_source();
    let length = strlen(name);
    let label = allocate(length);
    (*array).tracker_label = label;
    let skip = if length <= 10 { 1 } else { 2 };
    let copy = strncpy as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8;
    core::ptr::read_volatile(&copy)(label, name.add(skip), length);
    array
}

/// Construct an empty element-tracker pointer array with a retained label.
///
/// # Safety
/// `array` must be aligned and writable. The runtime record must contain a
/// stable readable NUL-terminated name; allocations must succeed for nonzero
/// sizes and storage must be word-aligned. Existing fields are not freed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_tracker_array_construct(
    array: *mut TrackedSlotArray, options: u32, capacity: u32, growth: u32,
) -> *mut TrackedSlotArray {
    construct_with(array, options, capacity, growth,
        |bytes| crate::runtime::malloc_rt::malloc(bytes),
        || (0x0897_bff4 as *const u32).read() as usize as *const u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_wrap_and_name_threshold_preserve_exact_write_boundaries() {
        for capacity in [0u32, 1, 10, 0x4000_0000] {
            for length in [0usize, 1, 2, 10, 11, 32] {
                let mut array = core::mem::MaybeUninit::<TrackedSlotArray>::uninit();
                let mut storage = [0xa5a5_a5a5u32; 16];
                let mut label = [0xa5u8; 64];
                let mut name = [0u8; 33];
                for index in 0..length { name[index] = b'A' + index as u8 % 26; }
                let mut calls = 0;
                unsafe {
                    let returned = construct_with(array.as_mut_ptr(), 0x1234, capacity, 2,
                        |bytes| {
                            calls += 1;
                            if calls == 1 {
                                assert_eq!(bytes, capacity.wrapping_shl(2) as usize);
                                storage.as_mut_ptr().cast()
                            } else {
                                assert_eq!(bytes, length);
                                label.as_mut_ptr()
                            }
                        }, || name.as_ptr());
                    assert_eq!(returned, array.as_mut_ptr());
                    let array = array.assume_init();
                    assert_eq!(array.data, storage.as_mut_ptr());
                    assert_eq!(array.slots, capacity);
                    assert_eq!(array.used, 0);
                    assert_eq!(array.options, 0x1234);
                    assert_eq!(array.growth, 2);
                    assert_eq!(array.tracker_label, label.as_mut_ptr());
                }
                for (index, word) in storage.iter().enumerate() {
                    assert_eq!(*word, if index < capacity.wrapping_shl(2) as usize / 4 {
                        0
                    } else { 0xa5a5_a5a5 });
                }
                let skip = if length <= 10 { 1 } else { 2 };
                for index in 0..label.len() {
                    let expected = if index >= length { 0xa5 }
                        else if index + skip >= length { 0 }
                        else { name[index + skip] };
                    assert_eq!(label[index], expected, "length={length}, index={index}");
                }
            }
        }
    }
}
