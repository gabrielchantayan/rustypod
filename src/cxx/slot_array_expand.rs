//! Slot-array expansion — `FUN_083d4e78` @ `0x083d4e78`.
//!
//! True occupied extent: 180 bytes [0x083d4e78,0x083d4f2c): 120 bytes
//! of ARM code followed by 60 diagnostic-string bytes. Raw aligned A32
//! decoding finds zero incoming plain BLs, one BLEQ at 0x083d4e1c,
//! three outgoing plain BLs and zero outgoing predicated BLs.
//! Multiply capacity by growth modulo 2^32, publish realloc's result even
//! on failure, zero the wrapped added byte range on success, then commit
//! capacity. Count, options, growth and tracker label remain unchanged.
//! Deviations: the verified inert diagnostic is called without its unused
//! variadic arguments. Existing realloc and zero-fill ports are used through
//! volatile function pointers to retain calls and avoid builtin substitution.

use super::slot_array_construct::TrackedSlotArray;
use super::slot_array_tracker_diagnostic_no_op::slot_array_tracker_diagnostic_no_op;
use crate::libc::memzero::memzero_aligned;

#[inline(always)]
unsafe fn expand_with(
    array: *mut TrackedSlotArray,
    reallocate: impl FnOnce(*mut u8, usize) -> *mut u8,
) {
    let capacity = (*array).slots.capacity as u32;
    let expanded = capacity.wrapping_mul((*array).growth);
    let storage = reallocate((*array).slots.storage as usize as *mut u8,
        expanded.wrapping_shl(2) as usize);
    (*array).slots.storage = storage as usize as u32;
    if !storage.is_null() {
        let zero = memzero_aligned as unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
        core::ptr::read_volatile(&zero)(
            storage.wrapping_add(capacity.wrapping_shl(2) as usize),
            expanded.wrapping_sub(capacity).wrapping_shl(2) as usize,
        );
        (*array).slots.capacity = expanded as i32;
    }
    slot_array_tracker_diagnostic_no_op(array.cast());
}

/// # Safety
/// `array` is a writable six-word header. Its storage must be a valid heap
/// allocation; successful resizing must leave the wrapped tail range writable
/// and word-aligned. Pointer fields must fit in u32, including on hosts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_expand(array: *mut TrackedSlotArray) {
    let reallocate = crate::runtime::malloc_rt::realloc
        as unsafe extern "C" fn(*mut u8, usize) -> *mut u8;
    expand_with(array, |storage, size| core::ptr::read_volatile(&reallocate)(storage, size));
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::slot_array_index_in_bounds::SlotArray;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn relocation_preserves_prefix_and_zeroes_only_added_slots() {
        let Some(base) = try_map_u32_slab(hints::SLOT_ARRAY_EXPAND, 0x1000) else { return };
        unsafe {
            let old = base.cast::<u32>();
            let new = old.add(32);
            old.write(0x12345678);
            old.add(1).write(0x87654321);
            for growth in [1u32, 2, 3] {
                for index in 0..8 { new.add(index).write(0xdeadbeef); }
                core::ptr::copy_nonoverlapping(old, new, 2);
                let mut array = TrackedSlotArray {
                    slots: SlotArray { storage: old as usize as u32, capacity: 2, count: 2 },
                    options: 0x1234, growth, tracker_label: 0x5678,
                };
                expand_with(&mut array, |pointer, bytes| {
                    assert_eq!(pointer, old.cast());
                    assert_eq!(bytes, (2 * growth * 4) as usize);
                    new.cast()
                });
                assert_eq!(array.slots.storage, new as usize as u32);
                assert_eq!(array.slots.capacity, (2 * growth) as i32);
                assert_eq!((array.slots.count, array.options, array.growth, array.tracker_label),
                    (2, 0x1234, growth, 0x5678));
                assert_eq!(new.read(), 0x12345678);
                assert_eq!(new.add(1).read(), 0x87654321);
                for index in 2..(2 * growth) { assert_eq!(new.add(index as usize).read(), 0); }
                assert_eq!(new.add((2 * growth) as usize).read(), 0xdeadbeef);
                assert_eq!(old.read(), 0x12345678);
            }
        }
    }

    #[test]
    fn failure_publishes_null_preserves_header_and_wraps_size() {
        for (capacity, growth, bytes) in [(2u32, 3u32, 24usize), (0, 0, 0),
            (0x40000001, 4, 16), (0xffffffff, 2, 0xfffffff8)] {
            let mut array = TrackedSlotArray {
                slots: SlotArray { storage: 0x12340000, capacity: capacity as i32, count: 7 },
                options: 11, growth, tracker_label: 13,
            };
            unsafe { expand_with(&mut array, |pointer, size| {
                assert_eq!(pointer as usize, 0x12340000);
                assert_eq!(size, bytes);
                core::ptr::null_mut()
            }); }
            assert_eq!(array.slots.storage, 0);
            assert_eq!(array.slots.capacity, capacity as i32);
            assert_eq!((array.slots.count, array.options, array.growth, array.tracker_label),
                (7, 11, growth, 13));
        }
    }
}
