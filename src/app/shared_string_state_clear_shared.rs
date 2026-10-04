//! Clear the shared-cell member of a shared-cell/string state object.
//!
//! Original: `FUN_08215364` @ 0x08215364; true size 44 bytes, ending
//! at 0x0821538c before the next real function at 0x08215390. Raw A32
//! decoding verifies two incoming plain BLs (0x082153d4, 0x08215410),
//! three outgoing plain BLs, and zero predicated BLs in either direction.
//!
//! Constructs an empty temporary handle, assigns it to the member at +8
//! (releasing its previous cell), then releases the temporary. Only r0 is
//! an argument: the saved r3 word supplies temporary stack storage, not an
//! input. No semantic deviations; repr(C) pointer fields widen on hosts.

use super::shared_string_state_construct::SharedStringState;
use crate::cxx::shared_cell::{shared_cell_construct, shared_cell_assign, shared_cell_release};

/// # Safety
/// `this` must point to aligned writable `SharedStringState` storage whose
/// shared member satisfies `shared_cell_release`'s ownership contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_string_state_clear_shared(this: *mut SharedStringState) {
    let mut empty = core::ptr::null_mut();
    let source = shared_cell_construct(&mut empty, core::ptr::null_mut());
    shared_cell_assign(core::ptr::addr_of_mut!((*this).shared), source);
    shared_cell_release(&mut empty);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::shared_cell::SharedCell;

    fn state() -> SharedStringState {
        // All fields are integers or raw pointers; untouched members need no
        // live pointees because the reset accesses only the shared member.
        let mut state: SharedStringState = unsafe { core::mem::zeroed() };
        state.vtable = 0x12345678;
        state.preserved_word = 0xabcdef01;
        state.cleared_word = 17;
        state.sentinel = 23;
        state.trailing_words = [31, 47];
        state.flag = 59;
        state.preserved_bytes = [61, 67, 71];
        state
    }

    #[test]
    fn empty_and_nonfinal_cells_clear_only_the_member_with_wrapping_decrement() {
        for count in [None, Some(2), Some(0), Some(i32::MIN)] {
            let mut state = state();
            let mut cell = SharedCell { value: 0, refcount: count.unwrap_or(0) };
            if count.is_some() {
                state.shared = &mut cell;
            }
            unsafe { shared_string_state_clear_shared(&mut state) };
            assert!(state.shared.is_null());
            if let Some(count) = count {
                assert_eq!(cell.refcount, count.wrapping_sub(1));
            }
            assert_eq!(state.vtable, 0x12345678);
            assert_eq!(state.preserved_word, 0xabcdef01);
            assert_eq!(state.cleared_word, 17);
            assert_eq!(state.sentinel, 23);
            assert!(state.string.vtable.is_null());
            assert!(state.string.payload.is_null());
            assert_eq!(state.trailing_words, [31, 47]);
            assert_eq!(state.flag, 59);
            assert_eq!(state.preserved_bytes, [61, 67, 71]);
        }
    }

    #[repr(C)]
    struct Payload {
        vtable: *const usize,
        slot: *mut *mut SharedCell,
        destroyed: bool,
    }

    unsafe extern "C" fn destroy_and_clear_slot(value: *mut u8) {
        let payload = &mut *value.cast::<Payload>();
        payload.destroyed = true;
        payload.slot.write(core::ptr::null_mut());
    }

    #[test]
    fn final_reference_dispatches_destructor_and_honors_its_slot_clear() {
        let mut state = state();
        let vtable = [0usize, destroy_and_clear_slot as *const () as usize];
        let mut payload = Payload {
            vtable: vtable.as_ptr(),
            slot: core::ptr::addr_of_mut!(state.shared),
            destroyed: false,
        };
        let mut cell = SharedCell {
            value: core::ptr::addr_of_mut!(payload) as usize,
            refcount: 1,
        };
        state.shared = &mut cell;
        unsafe { shared_string_state_clear_shared(&mut state) };
        assert!(payload.destroyed);
        assert_eq!(cell.refcount, 0);
        assert!(state.shared.is_null());
        unsafe { shared_string_state_clear_shared(&mut state) };
        assert_eq!(cell.refcount, 0);
    }
}
