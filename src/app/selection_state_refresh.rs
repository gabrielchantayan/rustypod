//! Refreshes cached selection resource state and notifies its vtable.
//!
//! `selection_state_refresh` — original: `FUN_08113a18` @ `0x08113a18`
//! (72 bytes, `0x08113a18..0x08113a60`). Raw ARM decoding establishes the
//! `bx r3` at `0x08113a5c` as the final instruction and the two following
//! literal-pool words as part of the extent; the `push` at `0x08113a68` begins
//! the next real function. There are three unconditional direct `bl` callers
//! (`0x08113f54`, `0x0811438c`, and `0x081148f8`) and no predicated direct
//! `bl` callers. The function itself has one unconditional direct `bl` to
//! `object_resource_count` and no predicated direct `bl` calls.
//!
//! It reads the resource count from the object at `self+0x30`, maps zero to
//! one, caches the resulting zero-based count at `+0xe8`, and dispatches
//! vtable slot `+0x58` only when that cached value changes. Deliberate
//! deviations: Rust uses an ordinary call for the ARM final `bx` tail dispatch;
//! host builds use seams for the ported resource-count helper and target-width
//! vtable function pointer.

#[cfg(target_os = "none")]
use core::mem;

const SELECTION_CHANGE_ACTION: u32 = 0x564d_6178;
const SELECTION_CHANGE_KIND: u32 = 0x0000_6387;
const SELECTION_CHANGE_SLOT_WORD: usize = 0x58 / 4;

type ObjectResourceCount = unsafe extern "C" fn(*const u8) -> u32;
type SelectionChangeDispatch = unsafe extern "C" fn(*mut SelectionState, u32, u32);

/// Target-width prefix through the cached selection resource index.
///
/// The vtable remains a `u32` so its offset follows the ARM target layout on
/// 64-bit hosts.
#[repr(C)]
pub struct SelectionState {
    vtable: u32,
    _unknown_04_2f: [u8; 0x2c],
    resource_object: *const u8,
    _unknown_34_e7: [u8; 0xb4],
    cached_resource_index: u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_resource_count(_object: *const u8) -> u32 {
    panic!("install selection-state refresh host resource-count seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selection_change_dispatch(_state: *mut SelectionState, _action: u32, _kind: u32) {
    panic!("install selection-state refresh host dispatch seam")
}

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_STATE_REFRESH_RESOURCE_COUNT: ObjectResourceCount = missing_object_resource_count;
#[cfg(not(target_os = "none"))]
pub static mut SELECTION_STATE_REFRESH_DISPATCH: SelectionChangeDispatch = missing_selection_change_dispatch;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn object_resource_count(object: *const u8) -> u32 {
    unsafe { crate::ui::object_resource_count::object_resource_count(object) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn object_resource_count(object: *const u8) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_STATE_REFRESH_RESOURCE_COUNT))(object) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_selection_change(state: *mut SelectionState) {
    let vtable = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*state).vtable)) };
    let address = unsafe { core::ptr::read_volatile((vtable as *const u32).add(SELECTION_CHANGE_SLOT_WORD)) };
    let dispatch: SelectionChangeDispatch = unsafe { mem::transmute(address as usize) };
    unsafe { dispatch(state, SELECTION_CHANGE_ACTION, SELECTION_CHANGE_KIND); }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_selection_change(state: *mut SelectionState) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_STATE_REFRESH_DISPATCH))(state, SELECTION_CHANGE_ACTION, SELECTION_CHANGE_KIND); }
}

/// # Safety
/// `state`, its resource object, the unported resource-count helper, and its
/// vtable selection-change slot must satisfy the unchecked retailOS contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_state_refresh(state: *mut SelectionState) {
    unsafe {
        let resource_index = object_resource_count((*state).resource_object).max(1) - 1;
        if (*state).cached_resource_index != resource_index {
            (*state).cached_resource_index = resource_index;
            dispatch_selection_change(state);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOURCE_COUNT: u32 = 0;
    static mut RESOURCE_OBJECT: usize = 0;
    static mut DISPATCH_COUNT: usize = 0;
    static mut DISPATCH_ARGUMENTS: (usize, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn resource_count_fixture(object: *const u8) -> u32 {
        unsafe {
            RESOURCE_OBJECT = object as usize;
            RESOURCE_COUNT
        }
    }

    unsafe extern "C" fn dispatch_fixture(state: *mut SelectionState, action: u32, kind: u32) {
        unsafe {
            DISPATCH_COUNT += 1;
            DISPATCH_ARGUMENTS = (state as usize, action, kind);
        }
    }

    fn fixture_state(resource_object: *const u8, cached_resource_index: u32) -> SelectionState {
        SelectionState {
            vtable: 0,
            _unknown_04_2f: [0; 0x2c],
            resource_object,
            _unknown_34_e7: [0; 0xb4],
            cached_resource_index,
        }
    }

    #[test]
    fn zero_count_becomes_zero_index_and_dispatches_change() {
        let _guard = TEST_LOCK.lock();
        let resource = [0u8; 1];
        let mut state = fixture_state(resource.as_ptr(), 9);
        unsafe {
            RESOURCE_COUNT = 0;
            RESOURCE_OBJECT = 0;
            DISPATCH_COUNT = 0;
            DISPATCH_ARGUMENTS = (0, 0, 0);
            SELECTION_STATE_REFRESH_RESOURCE_COUNT = resource_count_fixture;
            SELECTION_STATE_REFRESH_DISPATCH = dispatch_fixture;
            selection_state_refresh(&mut state);
            SELECTION_STATE_REFRESH_RESOURCE_COUNT = missing_object_resource_count;
            SELECTION_STATE_REFRESH_DISPATCH = missing_selection_change_dispatch;
            assert_eq!(RESOURCE_OBJECT, resource.as_ptr() as usize);
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(DISPATCH_ARGUMENTS, (core::ptr::addr_of_mut!(state) as usize, SELECTION_CHANGE_ACTION, SELECTION_CHANGE_KIND));
        }
        assert_eq!(state.cached_resource_index, 0);
    }

    #[test]
    fn unchanged_index_suppresses_dispatch() {
        let _guard = TEST_LOCK.lock();
        let resource = [0u8; 1];
        let mut state = fixture_state(resource.as_ptr(), 3);
        unsafe {
            RESOURCE_COUNT = 4;
            DISPATCH_COUNT = 0;
            SELECTION_STATE_REFRESH_RESOURCE_COUNT = resource_count_fixture;
            SELECTION_STATE_REFRESH_DISPATCH = dispatch_fixture;
            selection_state_refresh(&mut state);
            SELECTION_STATE_REFRESH_RESOURCE_COUNT = missing_object_resource_count;
            SELECTION_STATE_REFRESH_DISPATCH = missing_selection_change_dispatch;
            assert_eq!(DISPATCH_COUNT, 0);
        }
        assert_eq!(state.cached_resource_index, 3);
    }
}
