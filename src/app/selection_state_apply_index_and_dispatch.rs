//! Applies a selection index to its target and emits two selection notifications.
//!
//! `selection_state_apply_index_and_dispatch` — original: `FUN_0811190c` @
//! `0x0811190c` (92 bytes, `0x0811190c..0x08111967`: 80 instruction bytes
//! plus the 12-byte literal pool at `0x0811195c..0x08111967`). The next real
//! function begins at `0x08111968`. Raw A32 decoding finds no plain or
//! predicated direct `bl` instructions: it calls target vtable slot `+0x84`
//! through `blx`, calls selection-state vtable slot `+0x58` through `blx`,
//! then tail-dispatches that same slot with `bx`. There are three inbound
//! plain `bl` call sites (`0x08112f80`, `0x08113598`, and `0x081169bc`) and
//! no predicated inbound forms.
//!
//! It forwards `index` to the target at state `+0x88c`, then dispatches action
//! `0x2a2a2a2a` with kinds `0x63fb` and `0x63fc` in that order. Deliberate
//! deviations: Rust makes the final tail dispatch an ordinary call; 64-bit
//! host builds use seams because target-width vtable function pointers occupy
//! four bytes.

use core::ptr;

const TARGET_OFFSET: usize = 0x88c;
const TARGET_APPLY_INDEX_SLOT: usize = 0x84;
const SELECTION_DISPATCH_SLOT: usize = 0x58;
const SELECTION_ACTION: u32 = 0x2a2a_2a2a;
const FIRST_SELECTION_KIND: u32 = 0x63fb;
const SECOND_SELECTION_KIND: u32 = 0x63fc;

type TargetApplyIndex = unsafe extern "C" fn(*mut u8, u32);
type SelectionDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_target_apply_index(_: *mut u8, _: u32) {
    panic!("install selection-state apply-index host target seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_selection_dispatch(_: *mut u8, _: u32, _: u32) {
    panic!("install selection-state apply-index host dispatch seam")
}

#[cfg(not(target_os = "none"))]
pub static mut SELECTION_STATE_TARGET_APPLY_INDEX: TargetApplyIndex = missing_target_apply_index;
#[cfg(not(target_os = "none"))]
pub static mut SELECTION_STATE_APPLY_INDEX_DISPATCH: SelectionDispatch = missing_selection_dispatch;

#[inline(always)]
unsafe fn target_apply_index(target: *mut u8, index: u32) {
    #[cfg(target_os = "none")]
    unsafe {
        let vtable = ptr::read_volatile(target.cast::<u32>()) as usize as *const u8;
        let method: TargetApplyIndex = core::mem::transmute(ptr::read_volatile(vtable.add(TARGET_APPLY_INDEX_SLOT).cast::<u32>()) as usize);
        method(target, index);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        ptr::read_volatile(ptr::addr_of!(SELECTION_STATE_TARGET_APPLY_INDEX))(target, index);
    }
}

#[inline(always)]
unsafe fn dispatch_selection(state: *mut u8, kind: u32) {
    #[cfg(target_os = "none")]
    unsafe {
        let vtable = ptr::read_volatile(state.cast::<u32>()) as usize as *const u8;
        let method: SelectionDispatch = core::mem::transmute(ptr::read_volatile(vtable.add(SELECTION_DISPATCH_SLOT).cast::<u32>()) as usize);
        method(state, SELECTION_ACTION, kind);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        ptr::read_volatile(ptr::addr_of!(SELECTION_STATE_APPLY_INDEX_DISPATCH))(state, SELECTION_ACTION, kind);
    }
}

/// # Safety
///
/// `state`, its target pointer at `+0x88c`, and both observed vtable slots
/// must satisfy the unchecked retailOS contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selection_state_apply_index_and_dispatch(state: *mut u8, index: u32) {
    let target = unsafe { ptr::read_volatile(state.add(TARGET_OFFSET).cast::<u32>()) as usize as *mut u8 };
    unsafe { target_apply_index(target, index) };
    unsafe { dispatch_selection(state, FIRST_SELECTION_KIND) };
    unsafe { dispatch_selection(state, SECOND_SELECTION_KIND) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    const FIXTURE_LEN: usize = 0x2000;
    const TARGET_OFFSET_IN_FIXTURE: usize = 0x1000;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut APPLIED: (usize, u32) = (0, 0);
    static mut DISPATCHES: [(usize, u32, u32); 4] = [(0, 0, 0); 4];
    static mut DISPATCH_COUNT: usize = 0;

    unsafe extern "C" fn record_target_apply(target: *mut u8, index: u32) {
        unsafe { APPLIED = (target as usize, index) };
    }
    unsafe extern "C" fn record_dispatch(state: *mut u8, action: u32, kind: u32) {
        unsafe {
            DISPATCHES[DISPATCH_COUNT] = (state as usize, action, kind);
            DISPATCH_COUNT += 1;
        }
    }

    #[test]
    fn forwards_each_index_before_its_ordered_notification_pair() {
        let _lock = TEST_LOCK.lock();
        let Some(state) = try_map_u32_slab(hints::SELECTION_STATE_APPLY_INDEX_DISPATCH, FIXTURE_LEN) else { return };
        unsafe {
            state.write_bytes(0, FIXTURE_LEN);
            let target = state.add(TARGET_OFFSET_IN_FIXTURE);
            state.add(TARGET_OFFSET).cast::<u32>().write(target as usize as u32);
            APPLIED = (0, 0);
            DISPATCH_COUNT = 0;
            SELECTION_STATE_TARGET_APPLY_INDEX = record_target_apply;
            SELECTION_STATE_APPLY_INDEX_DISPATCH = record_dispatch;

            selection_state_apply_index_and_dispatch(state, 0);
            assert_eq!(APPLIED, (target as usize, 0));
            assert_eq!(DISPATCH_COUNT, 2);
            assert_eq!(DISPATCHES[0], (state as usize, SELECTION_ACTION, FIRST_SELECTION_KIND));
            assert_eq!(DISPATCHES[1], (state as usize, SELECTION_ACTION, SECOND_SELECTION_KIND));

            DISPATCH_COUNT = 0;
            selection_state_apply_index_and_dispatch(state, u32::MAX);
            assert_eq!(APPLIED, (target as usize, u32::MAX));
            assert_eq!(DISPATCH_COUNT, 2);
            assert_eq!(DISPATCHES[0], (state as usize, SELECTION_ACTION, FIRST_SELECTION_KIND));
            assert_eq!(DISPATCHES[1], (state as usize, SELECTION_ACTION, SECOND_SELECTION_KIND));

            SELECTION_STATE_TARGET_APPLY_INDEX = missing_target_apply_index;
            SELECTION_STATE_APPLY_INDEX_DISPATCH = missing_selection_dispatch;
        }
    }
}
