//! Resets a callback target and puts its owner into transition mode 5.
//!
//! `reset_callback_target` — original: `FUN_08133bfc` @ `0x08133bfc`.
//! The true extent is 124 bytes (`0x08133bfc..0x08133c78`); raw ARM decoding
//! reaches the next `push` at `0x08133c78`. It contains six unconditional
//! direct `bl` instructions and five unconditional indirect calls (`blx r1`),
//! the final one as a tail dispatch after restoring `r4`/`lr`.
//!
//! It dereferences the owner handle at target `+0x28`, dispatches vtable slots
//! `+0x38`, `+0xf0`, `+0x108`, `+0x10c`, and tail-dispatches `+0x110`, setting
//! the owner's transition mode to 5 between the first and second dispatch.
//! The mode setter remains a fixed-address call to the recovered but unported
//! `FUN_081324f8`; host builds substitute it only to make the ordering testable.

use core::mem;

use crate::cxx::handle::handle_deref_or_null;

const CALLBACK_HANDLE_WORD: usize = 10;
const SLOT_PREPARE: usize = 0x38 / 4;
const SLOT_RESET: usize = 0xf0 / 4;
const SLOT_VALUE: usize = 0x108 / 4;
const SLOT_STATE: usize = 0x10c / 4;
const SLOT_COMPLETE: usize = 0x110 / 4;
const SET_TRANSITION_MODE_ADDRESS: usize = 0x0813_24f8;

type Callback = unsafe extern "C" fn(*mut u8);
type SetTransitionMode = unsafe extern "C" fn(*mut CallbackTargetOwner, u32) -> u32;

/// Target-width prefix of the owning object through its callback handle.
///
/// The first ten words deliberately preserve the target's `+0x28` handle
/// placement even though a host pointer is wider than an ARM pointer.
#[repr(C)]
pub struct CallbackTargetOwner {
    _before_callback_handle: [u32; CALLBACK_HANDLE_WORD],
    callback_handle: *const *mut u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set_transition_mode(_owner: *mut CallbackTargetOwner, _mode: u32) -> u32 {
    panic!("install callback-target reset host mode setter")
}

#[cfg(not(target_os = "none"))]
pub static mut CALLBACK_TARGET_RESET_MODE_SETTER: SetTransitionMode = missing_set_transition_mode;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn set_transition_mode(owner: *mut CallbackTargetOwner) {
    let setter: SetTransitionMode = mem::transmute(SET_TRANSITION_MODE_ADDRESS);
    setter(owner, 5);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn set_transition_mode(owner: *mut CallbackTargetOwner) {
    core::ptr::read_volatile(core::ptr::addr_of!(CALLBACK_TARGET_RESET_MODE_SETTER))(owner, 5);
}

#[inline(always)]
unsafe fn dispatch_slot(target: *mut u8, slot: usize) {
    let vtable = target.cast::<*const usize>().read();
    let callback: Callback = mem::transmute(vtable.add(slot).read());
    callback(target);
}

#[inline(always)]
unsafe fn callback_target(owner: *mut CallbackTargetOwner) -> *mut u8 {
    handle_deref_or_null(core::ptr::addr_of!((*owner).callback_handle))
}

/// reset_callback_target — original: `FUN_08133bfc` @ `0x08133bfc` (124 bytes;
/// six direct `bl` and five indirect `blx` calls, all unconditional).
///
/// Obtains the callback target from the owner's handle, invokes its prepare
/// slot, switches the owner to transition mode 5, then invokes reset, value,
/// state, and completion slots in that order. Completion is a tail dispatch in
/// ARM; Rust uses a normal final call because the result is not observable.
///
/// # Safety
/// `owner`, its handle cell, callback target, and every selected vtable slot
/// must satisfy the original unchecked firmware contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn reset_callback_target(owner: *mut CallbackTargetOwner) {
    dispatch_slot(callback_target(owner), SLOT_PREPARE);
    set_transition_mode(owner);
    dispatch_slot(callback_target(owner), SLOT_RESET);
    dispatch_slot(callback_target(owner), SLOT_VALUE);
    dispatch_slot(callback_target(owner), SLOT_STATE);
    dispatch_slot(callback_target(owner), SLOT_COMPLETE);
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<&'static str> = Vec::new();

    unsafe fn record(call: &'static str) { CALLS.push(call); }
    unsafe extern "C" fn prepare(_target: *mut u8) { record("prepare"); }
    unsafe extern "C" fn reset(_target: *mut u8) { record("reset"); }
    unsafe extern "C" fn value(_target: *mut u8) { record("value"); }
    unsafe extern "C" fn state(_target: *mut u8) { record("state"); }
    unsafe extern "C" fn complete(_target: *mut u8) { record("complete"); }
    unsafe extern "C" fn set_mode(owner: *mut CallbackTargetOwner, mode: u32) -> u32 {
        assert!(!owner.is_null());
        assert_eq!(mode, 5);
        record("mode");
        0
    }

    #[test]
    fn dispatches_every_slot_around_mode_five() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALLS.clear();
            CALLBACK_TARGET_RESET_MODE_SETTER = set_mode;
            let mut vtable = [0usize; SLOT_COMPLETE + 1];
            vtable[SLOT_PREPARE] = prepare as usize;
            vtable[SLOT_RESET] = reset as usize;
            vtable[SLOT_VALUE] = value as usize;
            vtable[SLOT_STATE] = state as usize;
            vtable[SLOT_COMPLETE] = complete as usize;
            let mut target = [vtable.as_ptr() as usize];
            let mut cell = target.as_mut_ptr().cast::<u8>();
            let mut owner = CallbackTargetOwner {
                _before_callback_handle: [0; CALLBACK_HANDLE_WORD],
                callback_handle: &mut cell,
            };
            reset_callback_target(&mut owner);
            assert_eq!(CALLS, ["prepare", "mode", "reset", "value", "state", "complete"]);
            CALLBACK_TARGET_RESET_MODE_SETTER = missing_set_transition_mode;
        }
    }
}
