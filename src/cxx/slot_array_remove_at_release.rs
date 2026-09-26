//! Releases and removes a pointer slot — original: `FUN_083d4f2c` @ 0x083d4f2c
//! (**76 bytes**, 0x083d4f2c..0x083d4f78; `push {r2,r3,r4,r5,r6,lr}` at
//! 0x083d4f78 starts the next real function).
//!
//! Raw ARM has one plain direct `bl` (`slot_array_index_in_bounds` at
//! 0x083d4f38), no predicated direct `bl`, and one indirect `blx r1` through
//! the selected object's vtable slot `+4`. Both inbound calls, at 0x081ee458
//! and 0x081ef3ac, are plain direct `bl` instructions.
//!
//! Algorithm: if `index` is within the slot array's capacity and its storage
//! entry is non-NULL, invoke that object's vtable `+4` release callback, clear
//! the slot, then decrement the occupied count. Invalid indices and empty
//! slots do nothing. Deliberate deviation: host builds model the object's
//! vtable as native-width pointers so host callbacks remain callable; target
//! builds preserve retailOS's u32 pointer words and vtable `+4` layout.

use super::slot_array_index_in_bounds::{slot_array_index_in_bounds, SlotArray};

#[cfg(target_os = "none")]
type ReleaseCallback = unsafe extern "C" fn(*mut u8);

/// slot_array_remove_at_release — original: `FUN_083d4f2c` @ `0x083d4f2c`
/// (76 bytes; 1 plain direct `bl`, 0 predicated direct `bl`, and 1 indirect
/// `blx` through vtable slot +4, binary-decoded). See the module header for
/// the raw listing and algorithm.
///
/// # Safety
///
/// `this` must point to a valid slot array. For an in-bounds occupied slot,
/// its storage word must be a valid target object pointer whose first word is
/// a vtable pointer and whose second vtable word is callable with the object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_remove_at_release(this: *mut SlotArray, index: i32) {
    if unsafe { slot_array_index_in_bounds(this, index) } == 0 {
        return;
    }

    let slot = unsafe { (core::ptr::read_volatile(core::ptr::addr_of!((*this).storage)) as usize as *mut u32).add(index as usize) };
    let object = unsafe { core::ptr::read_volatile(slot) };
    if object == 0 {
        return;
    }

    #[cfg(target_os = "none")]
    unsafe {
        let object = object as usize as *mut u8;
        let vtable = core::ptr::read_volatile(object.cast::<u32>()) as usize as *const u32;
        let release: ReleaseCallback = core::mem::transmute(core::ptr::read_volatile(vtable.add(1)) as usize);
        release(object);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let object = object as usize as *mut u8;
        let vtable = core::ptr::read_unaligned(object.cast::<usize>()) as *const usize;
        let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(core::ptr::read_unaligned(vtable.add(1)));
        release(object);
    }

    unsafe {
        core::ptr::write_volatile(slot, 0);
        let count = core::ptr::read_volatile(core::ptr::addr_of!((*this).count));
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).count), count - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASED_OBJECT: AtomicUsize = AtomicUsize::new(0);
    static COUNT_DURING_RELEASE: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn release(object: *mut u8) {
        RELEASED_OBJECT.store(object as usize, Ordering::SeqCst);
        let array = unsafe { (object.add(0x20) as *const *const SlotArray).read() };
        COUNT_DURING_RELEASE.store(unsafe { (*array).count as usize }, Ordering::SeqCst);
    }

    #[test]
    fn only_releases_occupied_in_bounds_slots_and_clears_after_callback() {
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::CXX_SLOT_ARRAY_REMOVE_AT_RELEASE, 0x1000) else {
            crate::testing::note_missing_u32_fixture(module_path!());
            return;
        };
        let slots = slab.cast::<u32>();
        let object = unsafe { slab.add(0x100) };
        let vtable = [0usize, release as usize];
        let mut array = SlotArray { storage: slots as usize as u32, capacity: 2, count: 1 };
        unsafe {
            slots.write(object as usize as u32);
            slots.add(1).write(0);
            (object as *mut usize).write(vtable.as_ptr() as usize);
            (object.add(0x20) as *mut *const SlotArray).write(&array);
        }

        RELEASED_OBJECT.store(0, Ordering::SeqCst);
        COUNT_DURING_RELEASE.store(usize::MAX, Ordering::SeqCst);
        unsafe { slot_array_remove_at_release(&mut array, 0) };
        assert_eq!(RELEASED_OBJECT.load(Ordering::SeqCst), object as usize);
        assert_eq!(COUNT_DURING_RELEASE.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { slots.read() }, 0);
        assert_eq!(array.count, 0);

        unsafe { slot_array_remove_at_release(&mut array, 1) };
        unsafe { slot_array_remove_at_release(&mut array, -1) };
        unsafe { slot_array_remove_at_release(&mut array, 2) };
        assert_eq!(RELEASED_OBJECT.load(Ordering::SeqCst), object as usize);
        assert_eq!(array.count, 0);
    }
}
