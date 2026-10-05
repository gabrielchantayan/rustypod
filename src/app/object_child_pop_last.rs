//! Pop the last 16-bit value from an object's child collection.
//!
//! `FUN_081d1690` @ **0x081d1690**, **72 bytes**, ending at the distinct
//! push prologue at `0x081d16d8`. Raw A32 decoding finds two incoming plain
//! BLs (`0x0815faa4`, `0x081b9f00`), zero predicated BL callers; the body
//! has two plain BLs, zero predicated BLs, and one indirect BLX.
//!
//! Return zero for a null child or nonpositive signed count. Otherwise read
//! index count-1 through the existing slot-0x3c u16 wrapper, reload the child,
//! and invoke its slot-0x2c method with that index. Return the saved value,
//! not the mutation method's result. Incoming r3 survives the leaf predicate
//! and initializes the result cell; r1 and r2 do not contribute to the result.
//!
//! Deliberate deviations: ARM reuses both existing ports. Host child records
//! use a pointer-sized vtable followed by the signed count, rather than the
//! ARM count at +4; the host predicate mirrors the verified leaf algorithm.
//! The enclosing object's child remains a u32 pointer at +8 on all targets.
//! Volatile reads preserve the child reload after callback mutation.

use crate::cxx::vtable_slot_3c_result_u16::vtable_slot_3c_result_u16;

#[repr(C)]
struct Child {
    vtable: *const usize,
    count: i32,
}

/// # Safety
/// `object` must contain a readable u32 child pointer at +8. Non-null children
/// must have the layout above (target: vtable +0, count +4), and valid methods
/// at vtable word indices 15 and 11. Callbacks must maintain these invariants
/// for any replacement child. The slot-15 callback may leave its result cell
/// unchanged, in which case `initial_result` supplies its low 16 bits.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_child_pop_last(
    object: *const u32,
    _unused_r1: u32,
    _unused_r2: u32,
    initial_result: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    let positive = unsafe {
        crate::app::object_child_count_is_positive::object_child_count_is_positive(object)
    } != 0;
    #[cfg(not(target_os = "none"))]
    let positive = unsafe {
        let child = object.add(2).read_volatile() as *const Child;
        !child.is_null() && core::ptr::addr_of!((*child).count).read_volatile() > 0
    };
    if !positive {
        return 0;
    }
    unsafe {
        let child = object.add(2).read_volatile() as *mut Child;
        let index = core::ptr::addr_of!((*child).count).read_volatile() as u32 - 1;
        let value = vtable_slot_3c_result_u16(child.cast(), index, 0, initial_result);
        let child = object.add(2).read_volatile() as *mut Child;
        let vtable = core::ptr::addr_of!((*child).vtable).read();
        let method: unsafe extern "C" fn(*mut Child, u32) -> u32 =
            core::mem::transmute(vtable.add(0x2c / 4).read());
        method(child, index);
        value
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct FixtureChild {
        header: Child,
        owner: *mut u32,
        replacement: *mut Child,
        value: u32,
        read_index: u32,
        mutation_index: u32,
    }

    unsafe extern "C" fn read_last(receiver: *mut u8, index: u32, result: *mut u32) {
        unsafe {
            let child = &mut *receiver.cast::<FixtureChild>();
            child.read_index = index;
            if child.value != u32::MAX { result.write(child.value); }
            if !child.replacement.is_null() {
                child.owner.add(2).write(child.replacement as usize as u32);
            }
        }
    }

    unsafe extern "C" fn truncate(receiver: *mut Child, index: u32) -> u32 {
        unsafe {
            let child = &mut *receiver.cast::<FixtureChild>();
            child.mutation_index = index;
            child.header.count = index as i32;
        }
        0xdead_beef
    }

    #[test]
    fn empty_signed_boundaries_and_pop_transitions() {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = try_map_u32_slab(hints::OBJECT_CHILD_POP_LAST, 0x1000) else {
            assert!(note_missing_u32_fixture("app/object_child_pop_last"));
            return;
        };
        unsafe {
            let object = base.cast::<u32>();
            let child = base.add(0x100).cast::<FixtureChild>();
            let replacement = base.add(0x200).cast::<FixtureChild>();
            let mut vtable = [0usize; 16];
            vtable[15] = read_last as usize;
            vtable[11] = truncate as usize;
            let make = |count, value, next| FixtureChild {
                header: Child { vtable: vtable.as_ptr(), count },
                owner: object, replacement: next, value,
                read_index: u32::MAX, mutation_index: u32::MAX,
            };
            object.add(2).write(0);
            assert_eq!(object_child_pop_last(object, 0, 0, 0x1234), 0);
            for count in [i32::MIN, -1, 0, 1, 2, i32::MAX] {
                child.write(make(count, 0xabcd_9876, core::ptr::null_mut()));
                object.add(2).write(child as usize as u32);
                let value = object_child_pop_last(object, 0, 0, 0x1234);
                if count <= 0 {
                    assert_eq!(value, 0);
                    assert_eq!((*child).header.count, count);
                    assert_eq!((*child).read_index, u32::MAX);
                    assert_eq!((*child).mutation_index, u32::MAX);
                } else {
                    assert_eq!(value, 0x9876);
                    assert_eq!((*child).read_index, count as u32 - 1);
                    assert_eq!((*child).mutation_index, count as u32 - 1);
                    assert_eq!((*child).header.count, count - 1);
                }
            }
            child.write(make(3, u32::MAX, replacement.cast()));
            replacement.write(make(20, 0, core::ptr::null_mut()));
            object.add(2).write(child as usize as u32);
            assert_eq!(object_child_pop_last(object, 0, 0, 0xcafe_5678), 0x5678);
            assert_eq!((*child).header.count, 3);
            assert_eq!((*child).mutation_index, u32::MAX);
            assert_eq!((*replacement).header.count, 2);
            assert_eq!((*replacement).mutation_index, 2);
        }
    }
}
