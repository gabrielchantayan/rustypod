//! Removes an occupied pointer slot after virtual dispatch.
//!
//! Original: `FUN_083d518c` @ **0x083d518c**, 80 bytes, true extent
//! `0x083d518c..0x083d51dc` (next word begins a constructor's push).
//! Whole-image raw A32 decoding: 0 incoming plain BL, 1 predicated BL
//! at `0x08106244`; body: 0 plain/predicated BL, 1 `blx r1` at
//! `0x083d51bc`. Ghidra's second caller is an overlapping function fragment.
//!
//! Reject negative indices and indices at or above signed capacity. For an
//! occupied slot, call the object's virtual slot +0x40, reload storage, clear
//! that index, and decrement the current occupied count with wrapping arithmetic.
//! The concrete virtual method identity is unknown; no direct callee seam is
//! invented. Deliberate deviation: host objects and vtables use native-width
//! pointers, while storage entries and the array retain target-width words.

use super::slot_array_index_in_bounds::SlotArray;

/// # Safety
/// For a nonnegative index, `this` must be valid. An in-range index requires
/// valid storage; an occupied object requires a callable vtable word 16.
/// The callback must leave the array and its possibly replaced storage valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_remove_at_virtual_40(this: *mut SlotArray, index: i32) {
    if index < 0 {
        return;
    }
    unsafe {
        if core::ptr::read_volatile(core::ptr::addr_of!((*this).capacity)) <= index {
            return;
        }
        let storage = core::ptr::read_volatile(core::ptr::addr_of!((*this).storage)) as usize as *mut u32;
        let object = core::ptr::read_volatile(storage.add(index as usize)) as usize as *mut u8;
        if object.is_null() {
            return;
        }
        #[cfg(target_os = "none")]
        let method: unsafe extern "C" fn(*mut u8) = {
            let vtable = core::ptr::read_volatile(object.cast::<u32>()) as usize as *const u32;
            core::mem::transmute(core::ptr::read_volatile(vtable.add(16)) as usize)
        };
        #[cfg(not(target_os = "none"))]
        let method: unsafe extern "C" fn(*mut u8) = {
            let vtable = core::ptr::read_unaligned(object.cast::<usize>()) as *const usize;
            core::mem::transmute(core::ptr::read_unaligned(vtable.add(16)))
        };
        method(object);
        let storage = core::ptr::read_volatile(core::ptr::addr_of!((*this).storage)) as usize as *mut u32;
        core::ptr::write_volatile(storage.add(index as usize), 0);
        let count = core::ptr::read_volatile(core::ptr::addr_of!((*this).count));
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).count), count.wrapping_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Object {
        vtable: *const usize,
        array: *mut SlotArray,
        replacement: u32,
        calls: u32,
    }

    unsafe extern "C" fn replace_storage(object: *mut u8) {
        unsafe {
            let object = &mut *object.cast::<Object>();
            let array = &mut *object.array;
            let slots = array.storage as usize as *mut u32;
            assert_eq!(slots.add(1).read(), object as *mut Object as usize as u32);
            assert_eq!(array.count, 7);
            object.calls += 1;
            array.storage = object.replacement;
            array.count = i32::MIN;
        }
    }

    #[test]
    fn callback_observes_live_slot_then_replaced_storage_is_cleared_and_count_wraps() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::CXX_SLOT_ARRAY_REMOVE_VIRTUAL_40, 0x1000) else {
            crate::testing::note_missing_u32_fixture(module_path!());
            return;
        };
        unsafe {
            let old = slab.cast::<u32>();
            let replacement = old.add(8);
            let object = slab.add(0x100).cast::<Object>();
            let mut vtable = [0usize; 17];
            vtable[16] = replace_storage as *const () as usize;
            let mut array = SlotArray { storage: old as usize as u32, capacity: 2, count: 7 };
            object.write(Object { vtable: vtable.as_ptr(), array: &mut array,
                replacement: replacement as usize as u32, calls: 0 });
            old.write(0x12345678);
            old.add(1).write(object as usize as u32);
            replacement.write(0x87654321);
            replacement.add(1).write(0xabcdef01);
            slot_array_remove_at_virtual_40(&mut array, 1);
            assert_eq!((*object).calls, 1);
            assert_eq!(old.add(1).read(), object as usize as u32);
            assert_eq!(replacement.read(), 0x87654321);
            assert_eq!(replacement.add(1).read(), 0);
            assert_eq!(array.count, i32::MAX);
            slot_array_remove_at_virtual_40(&mut array, 1);
            assert_eq!((*object).calls, 1);
            assert_eq!(array.count, i32::MAX);
        }
    }

    #[test]
    fn signed_bounds_short_circuit_without_storage_access() {
        unsafe {
            slot_array_remove_at_virtual_40(core::ptr::null_mut(), -1);
            slot_array_remove_at_virtual_40(core::ptr::null_mut(), i32::MIN);
            for capacity in [i32::MIN, -1, 0, 2] {
                let mut array = SlotArray { storage: 0, capacity, count: 17 };
                for index in [capacity.max(0), i32::MAX] {
                    slot_array_remove_at_virtual_40(&mut array, index);
                    assert_eq!(array.count, 17);
                    assert_eq!(array.storage, 0);
                }
            }
        }
    }
}
