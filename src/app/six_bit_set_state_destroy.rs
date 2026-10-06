//! six_bit_set_state_destroy — FUN_0816f5c0 @ 0x0816f5c0.
//!
//! True size: 124 bytes, [0x0816f5c0,0x0816f63c); the next independent
//! conditional tail-call function begins at 0x0816f63c. Whole-image aligned
//! A32 decoding verifies two inbound plain BLs (0x0815f4c8,0x0839cf8c),
//! nine outbound plain BLs, and zero predicated BLs in either direction.
//! Destroys and tag-2 deletes three optional bit sets in field order, tag-3
//! deletes the state allocation, clears fields in reverse bit-set order,
//! destroys the u16 vector, adjusts its returned subobject pointer back to
//! the owner, destroys that owner's counted mutex, and returns the owner.
//! Deliberate deviation: repr(C) semantic fields widen host pointers while
//! retaining the exact ARM offsets; all callees reuse existing Rust ports.
//! Codegen: LLVM folds the vector's proven identity return/container adjustment
//! and inlines counted-mutex teardown (including existing kernel dispatch).
//! match.py shows 54 instructions versus retailOS's 31; field offsets,
//! optional-set guards, release order, and clear order remain intact.

use crate::cxx::bit_set::{bit_set_destroy, BitSet};
use crate::cxx::u16_vector_destroy::{u16_vector_destroy, U16Vector};
use crate::heap::veneers::{operator_delete, operator_delete_tag3};
use crate::kernel::sync_mutex::{mutex_delete_counted, CountedMutex};

#[repr(C)]
pub struct SixBitSetState {
    pub header: u32,
    pub bit_sets: [*mut BitSet; 3],
    pub state_allocation: *mut u8,
    pub records: [u8; 0x48],
    pub lock: CountedMutex,
    pub vector: U16Vector,
}

/// # Safety
/// `state` must be a live state object with valid owned allocations, vector
/// range, and counted mutex as required by the corresponding destructors.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn six_bit_set_state_destroy(state: *mut u8) -> *mut u8 {
    destroy_with(state.cast(), |allocation, tag| {
        if tag == 3 { operator_delete_tag3(allocation) } else { operator_delete(allocation) }
    }).cast()
}

#[inline(always)]
unsafe fn destroy_with(
    state: *mut SixBitSetState,
    mut delete: impl FnMut(*mut u8, u32),
) -> *mut SixBitSetState {
    for index in 0..3 {
        let set = core::ptr::addr_of!((*state).bit_sets[index]).read_volatile();
        if !set.is_null() {
            delete(bit_set_destroy(set).cast(), 2);
        }
    }
    delete(core::ptr::addr_of!((*state).state_allocation).read_volatile(), 3);
    for index in [2, 1, 0] {
        core::ptr::addr_of_mut!((*state).bit_sets[index]).write_volatile(core::ptr::null_mut());
    }
    core::ptr::addr_of_mut!((*state).state_allocation).write_volatile(core::ptr::null_mut());
    let vector = u16_vector_destroy(core::ptr::addr_of_mut!((*state).vector));
    let owner = vector.cast::<u8>()
        .sub(core::mem::offset_of!(SixBitSetState, vector)).cast::<SixBitSetState>();
    mutex_delete_counted(core::ptr::addr_of_mut!((*owner).lock));
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn optional_sets_and_state_are_released_before_fields_clear() {
        for mask in 0..8 {
            unsafe {
                let mut sets: [BitSet; 3] = core::mem::zeroed();
                let mut state: SixBitSetState = core::mem::zeroed();
                state.header = 0xabcdef01;
                state.records.fill(0xa5);
                state.lock.mutex.unused = 17;
                state.lock.hold_count = 23;
                let mut allocation = 0u8;
                state.state_allocation = &mut allocation;
                for index in 0..3 {
                    if mask & (1 << index) != 0 {
                        state.bit_sets[index] = &mut sets[index];
                    }
                }
                let original = state.bit_sets;
                let ptr = &mut state as *mut SixBitSetState;
                let mut calls = std::vec::Vec::new();
                let returned = destroy_with(ptr, |p, tag| {
                    assert_eq!((*ptr).bit_sets, original);
                    assert_eq!((*ptr).state_allocation, &mut allocation as *mut u8);
                    calls.push((p, tag));
                });
                let mut expected = std::vec::Vec::new();
                for set in original {
                    if !set.is_null() { expected.push((set.cast(), 2)); }
                }
                expected.push((&mut allocation as *mut u8, 3));
                assert_eq!(calls, expected);
                assert_eq!(returned, ptr);
                assert_eq!(state.bit_sets, [core::ptr::null_mut(); 3]);
                assert!(state.state_allocation.is_null());
                assert!(state.lock.mutex.sem_cell.is_null());
                assert_eq!(state.lock.mutex.unused, 0);
                assert_eq!(state.lock.hold_count, 0);
                assert_eq!(state.header, 0xabcdef01);
                assert_eq!(state.records, [0xa5; 0x48]);
            }
        }
    }

    #[test]
    fn empty_state_can_be_destroyed_twice() {
        unsafe {
            let mut state: SixBitSetState = core::mem::zeroed();
            let ptr = (&mut state as *mut SixBitSetState).cast();
            assert_eq!(six_bit_set_state_destroy(ptr), ptr);
            assert_eq!(six_bit_set_state_destroy(ptr), ptr);
        }
    }
}
