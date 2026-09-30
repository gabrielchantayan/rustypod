//! Indexed object store — `FUN_082a7454` @ load address `0x082a7454`.
//! True size: 220 bytes (216 code bytes plus literal at 0x082a752c);
//! next function begins at 0x082a7530. Raw A32 decoding finds two inbound
//! plain BLs (0x082a7418, 0x082a7440), zero predicated BLs. Outbound:
//! one plain BL to vector4_resize_fill and two legacy virtual PC transfers.
//!
//! If object flag bit 0 is clear, assign a fresh global index when the
//! supplied index is zero, call vtable slot +8 with object and owner, then
//! set bit 0. Grow owner's word-vector to index+1 with zero fill if needed.
//! Release the previous slot, destroying it through vtable +4 when its
//! wrapping reference count reaches zero; retain object and store it.
//! Deliberate deviations: reuse the existing Rust vector resize port; host
//! callbacks replace target vtable dispatch and the global index counter.
//! Raw code uses only r0-r2: Ghidra's fourth argument is unused stack padding.

use crate::cxx::vector4_resize_fill::vector4_resize_fill;

#[cfg(not(target_os = "none"))]
pub static mut NEXT_OBJECT_INDEX: u32 = 0;
#[cfg(not(target_os = "none"))]
pub static mut INITIALIZE_OBJECT: unsafe extern "C" fn(*mut u32, *mut u32) = missing_initialize;
#[cfg(not(target_os = "none"))]
pub static mut DESTROY_OBJECT: unsafe extern "C" fn(*mut u32) = missing_destroy;
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_initialize(_: *mut u32, _: *mut u32) { panic!("object initializer not installed") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_: *mut u32) { panic!("object destructor not installed") }

/// Store one retained object in an owner's indexed table.
///
/// # Safety
/// Owner points to a target-width pointer to an object with vector words at
/// +8/+12. Object has vtable, flags and references at +0/+8/+12. All pointers,
/// slots, callbacks and the index must be valid; callbacks may mutate owner.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_object_store(owner: *mut u32, object: *mut u32, index: *mut u32) {
    if object.add(2).read() & 1 == 0 {
        if index.read() == 0 {
            #[cfg(target_os = "none")]
            let counter = 0x08a0_fc70usize as *mut u32;
            #[cfg(not(target_os = "none"))]
            let counter = core::ptr::addr_of_mut!(NEXT_OBJECT_INDEX);
            let next = counter.read().wrapping_add(1);
            counter.write(next);
            index.write(next);
        }
        #[cfg(target_os = "none")]
        {
            let vtable = object.read() as usize as *const u32;
            let initialize: unsafe extern "C" fn(*mut u32, *mut u32) = core::mem::transmute(vtable.add(2).read() as usize);
            initialize(object, owner);
        }
        #[cfg(not(target_os = "none"))]
        INITIALIZE_OBJECT(object, owner);
        object.add(2).write(object.add(2).read() | 1);
    }
    let slot_index = index.read();
    let state = owner.read() as usize as *mut u32;
    if state.add(3).read() <= slot_index {
        let fill = 0;
        vector4_resize_fill(state.add(2), slot_index.wrapping_add(1), &fill);
    }
    let state = owner.read() as usize as *mut u32;
    let slots = state.add(2).read() as usize as *mut u32;
    let previous = slots.add(slot_index as usize).read() as usize as *mut u32;
    if !previous.is_null() {
        let references = previous.add(3).read().wrapping_sub(1);
        previous.add(3).write(references);
        if references == 0 {
            #[cfg(target_os = "none")]
            {
                let vtable = previous.read() as usize as *const u32;
                let destroy: unsafe extern "C" fn(*mut u32) = core::mem::transmute(vtable.add(1).read() as usize);
                destroy(previous);
            }
            #[cfg(not(target_os = "none"))]
            DESTROY_OBJECT(previous);
        }
    }
    object.add(3).write(object.add(3).read().wrapping_add(1));
    let state = owner.read() as usize as *mut u32;
    let slots = state.add(2).read() as usize as *mut u32;
    slots.add(slot_index as usize).write(object as usize as u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    static mut INITIALIZED: u32 = 0;
    static mut DESTROYED: u32 = 0;
    unsafe extern "C" fn initialize(object: *mut u32, _: *mut u32) {
        INITIALIZED += 1;
        object.add(2).write(0x80);
    }
    unsafe extern "C" fn destroy(object: *mut u32) {
        assert_eq!(object.add(3).read(), 0);
        DESTROYED += 1;
    }

    #[test]
    fn initializes_grows_replaces_and_preserves_wrapping_reference_semantics() {
        let _heap = mock_heap();
        let Some(slab) = try_map_u32_slab(hints::INDEXED_OBJECT_STORE, 0x1000) else {
            note_missing_u32_fixture("app/indexed_object_store");
            return;
        };
        unsafe {
            INITIALIZE_OBJECT = initialize;
            DESTROY_OBJECT = destroy;
            let owner = slab.cast::<u32>();
            let state = owner.add(8);
            let old_slots = owner.add(32);
            let new_slots = owner.add(64);
            let object = owner.add(96);
            let previous = owner.add(112);
            // Cases: null slot, live replacement, final release, underflow,
            // self replacement, initialized zero index, and index wraparound.
            for (initialized, supplied, counter, refs, same, expected_destroy) in [
                (false, 0, 1, 0, false, 0),
                (false, 2, 9, 2, false, 0),
                (true, 2, 9, 1, false, 1),
                (true, 2, 9, 0, false, 0),
                (true, 2, 9, 2, false, 0),
                (true, 2, 9, 2, true, 0),
                (true, 0, 9, 0, false, 0),
                (false, 0, u32::MAX, 0, false, 0),
            ] {
                ptr::write_bytes(slab, 0, 0x1000);
                INITIALIZED = 0;
                DESTROYED = 0;
                NEXT_OBJECT_INDEX = counter;
                owner.write(state as usize as u32);
                state.add(2).write(old_slots as usize as u32);
                state.add(3).write(if initialized { 3 } else { 1 });
                object.add(2).write(if initialized { 0x81 } else { 0x80 });
                object.add(3).write(if same { refs } else { u32::MAX });
                previous.add(3).write(refs);
                let mut index = supplied;
                let expected_index = if !initialized && supplied == 0 { counter.wrapping_add(1) } else { supplied };
                if same || refs != 0 || initialized && supplied == 2 {
                    old_slots.add(expected_index as usize).write(if same { object } else { previous } as usize as u32);
                }
                set_alloc_ret(new_slots.cast());
                indexed_object_store(owner, object, &mut index);
                assert_eq!(index, expected_index);
                assert_eq!(NEXT_OBJECT_INDEX, if !initialized && supplied == 0 { expected_index } else { counter });
                assert_eq!(INITIALIZED, u32::from(!initialized));
                assert_eq!(DESTROYED, expected_destroy);
                assert_eq!(object.add(2).read(), 0x81);
                assert_eq!(object.add(3).read(), if same { refs } else { 0 });
                let slots = state.add(2).read() as usize as *mut u32;
                assert_eq!(slots.add(index as usize).read(), object as usize as u32);
                if !initialized && expected_index == 2 {
                    assert_eq!(state.add(3).read(), 3);
                    assert_eq!(slots.add(1).read(), 0);
                }
                if !same && initialized && supplied == 2 { assert_eq!(previous.add(3).read(), refs.wrapping_sub(1)); }
            }
        }
    }
}
