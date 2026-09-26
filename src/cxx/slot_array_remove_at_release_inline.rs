//! Inline-checked pointer-slot release and removal.
//!
//! `slot_array_remove_at_release_inline` — original: `FUN_083d47c8` @
//! **0x083d47c8** (80 bytes; true extent `0x083d47c8..0x083d4818`, with the
//! next independently linked function beginning at `0x083d4818`). Raw A32
//! decoding finds two incoming direct calls, both unconditional plain `bl`
//! (at `0x08076b94` and `0x082c9a80`); there are no predicated direct `bl`
//! calls. The body has no direct call and one indirect `blx r1` through an
//! occupied object's vtable slot `+4`.
//!
//! Algorithm: reject an index outside `0 <= index < capacity`; otherwise, if
//! the slot is occupied, invoke its vtable `+4` callback, clear the slot, and
//! decrement the occupied count. Deliberate deviation: host builds use
//! native-width vtable pointers so the callback remains callable; target
//! builds preserve the retailOS u32-pointer layout.

use super::slot_array_index_in_bounds::SlotArray;

#[cfg(target_os = "none")]
type ReleaseCallback = unsafe extern "C" fn(*mut u8);

/// Removes an occupied slot after invoking its vtable `+4` release callback.
///
/// # Safety
///
/// For a nonnegative in-range `index`, `this` must reference a valid slot
/// array. An occupied storage entry must identify an object whose first word
/// is a vtable pointer and whose second vtable word is callable with it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_remove_at_release_inline(this: *mut SlotArray, index: i32) {
    if index < 0 {
        return;
    }
    let capacity = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*this).capacity)) };
    if capacity <= index {
        return;
    }

    let slot = unsafe {
        (core::ptr::read_volatile(core::ptr::addr_of!((*this).storage)) as usize as *mut u32)
            .add(index as usize)
    };
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
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).count), count.wrapping_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static RELEASED_OBJECT: AtomicUsize = AtomicUsize::new(0);
    static COUNT_DURING_RELEASE: AtomicUsize = AtomicUsize::new(usize::MAX);

    unsafe extern "C" fn release(object: *mut u8) {
        RELEASED_OBJECT.store(object as usize, Ordering::SeqCst);
        let array = unsafe { (object.add(0x20) as *const *const SlotArray).read() };
        COUNT_DURING_RELEASE.store(unsafe { (*array).count as usize }, Ordering::SeqCst);
    }

    #[test]
    fn releases_then_clears_and_decrements_an_occupied_slot() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::CXX_SLOT_ARRAY_REMOVE_AT_RELEASE_INLINE, 0x1000) else {
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
        unsafe { slot_array_remove_at_release_inline(&mut array, 0) };
        assert_eq!(RELEASED_OBJECT.load(Ordering::SeqCst), object as usize);
        assert_eq!(COUNT_DURING_RELEASE.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { slots.read() }, 0);
        assert_eq!(array.count, 0);
    }

    #[test]
    fn ignores_negative_out_of_range_and_empty_slots() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::CXX_SLOT_ARRAY_REMOVE_AT_RELEASE_INLINE_EMPTY, 0x1000) else {
            crate::testing::note_missing_u32_fixture(module_path!());
            return;
        };
        let slots = slab.cast::<u32>();
        let mut array = SlotArray { storage: slots as usize as u32, capacity: 1, count: 7 };
        unsafe { slots.write(0) };
        RELEASED_OBJECT.store(0, Ordering::SeqCst);
        for index in [-1, 0, 1, i32::MAX] {
            unsafe { slot_array_remove_at_release_inline(&mut array, index) };
        }
        assert_eq!(RELEASED_OBJECT.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { slots.read() }, 0);
        assert_eq!(array.count, 7);
    }
}
