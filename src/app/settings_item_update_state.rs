//! The settings-item update-state singleton accessor.
//!
//! Port:
//! - [`settings_item_update_state_get`] — original: `FUN_081bbde8` @
//!   0x081bbde8 (88 bytes: 72 instruction bytes plus its four-word literal
//!   pool; **six unconditional plain `bl` call sites, no predicated forms or
//!   tail branches**, verified by decoding every ARM B/BL word in `osos.dec`).
//!
//! The accessor owns the fixed six-byte update state at 0x089ca334: an i32
//! value followed by the `apply_setting` and `notify` flags. The surrounding
//! code routes values above 20 through the settings item and posts a message
//! when `notify` is set, establishing this as the state used to stage a
//! settings-item update.

use core::ffi::c_void;

use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

const DSO_HANDLE: i32 = 0x089ca09c;

/// Fixed state at 0x089ca334, initialized by the original's sibling
/// `FUN_081bbf5c` before the accessor returns it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SettingsItemUpdateState {
    pub value: i32,
    pub apply_setting: u8,
    pub notify: u8,
}

const _: [(); 8] = [(); core::mem::size_of::<SettingsItemUpdateState>()];

/// Original guard word at 0x089ca32c.
pub static mut SETTINGS_ITEM_UPDATE_STATE_GUARD: u32 = 0;

/// Crate-owned replacement for the fixed retailOS storage at 0x089ca334.
pub static mut SETTINGS_ITEM_UPDATE_STATE: SettingsItemUpdateState = SettingsItemUpdateState {
    value: 0,
    apply_setting: 0,
    notify: 0,
};

/// The literal destructor target 0x081b109c is an interior `add r0,r4,#4`
/// instruction, not a function entry. A shutdown callback to it cannot form a
/// valid call frame, so preserve registration with a safe no-op.
unsafe extern "C" fn settings_item_update_state_destructor(_object: *mut c_void) {}

/// settings_item_update_state_get — original: `FUN_081bbde8` @ 0x081bbde8
/// (88 bytes: 72 instruction bytes plus a four-word literal pool; six verified
/// plain `bl` call sites, all unconditional, with no predicated calls or tail
/// branches).
///
/// Returns the fixed settings-item update state. The bit-0 guard fast path
/// avoids all lifecycle work once initialized; otherwise it acquires the ADS
/// guard, initializes the state to `{-1, 0, 0}`, registers its destructor with
/// `cxa_atexit`, releases the guard, and returns the fixed state.
///
/// Deliberate deviations: the fixed firmware addresses are crate statics; the
/// three stores of unported sibling `FUN_081bbf5c` are inlined; and the
/// malformed non-entry destructor literal 0x081b109c is represented by a
/// shutdown-safe no-op callback.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn settings_item_update_state_get() -> *mut SettingsItemUpdateState {
    let guard = core::ptr::addr_of_mut!(SETTINGS_ITEM_UPDATE_STATE_GUARD);
    let state = core::ptr::addr_of_mut!(SETTINGS_ITEM_UPDATE_STATE);
    if core::ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        (*state).value = -1;
        (*state).apply_setting = 0;
        (*state).notify = 0;
        cxa_atexit(state.cast::<c_void>(), settings_item_update_state_destructor, DSO_HANDLE);
        cxa_guard_release(guard);
    }
    state
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn box_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: settings_item_update_state_destructor,
            key: 0,
        }))
        .cast()
    }

    unsafe extern "C" fn box_free(block: *mut u8) {
        drop(Box::from_raw(block.cast::<ShutdownNode>()));
    }

    fn state() -> *mut SettingsItemUpdateState {
        core::ptr::addr_of_mut!(SETTINGS_ITEM_UPDATE_STATE)
    }

    fn reset() -> MutexGuard<'static, ()> {
        let test_lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            SETTINGS_ITEM_UPDATE_STATE_GUARD = 0;
            state().write(SettingsItemUpdateState {
                value: 0x1234_5678,
                apply_setting: 0xa5,
                notify: 0x5a,
            });
            SHUTDOWN_ALLOC = box_alloc;
            SHUTDOWN_FREE = box_free;
            *shutdown_chain_head() = ptr::null_mut();
        }
        test_lock
    }

    fn restore(test_lock: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            SETTINGS_ITEM_UPDATE_STATE_GUARD = 0;
        }
        drop(test_lock);
    }

    #[test]
    fn first_call_initializes_fixed_state_and_registers_shutdown_callback() {
        let test_lock = reset();
        unsafe {
            assert_eq!(settings_item_update_state_get(), state());
            assert_eq!((*state()).value, -1);
            assert_eq!((*state()).apply_setting, 0);
            assert_eq!((*state()).notify, 0);
            assert_eq!(SETTINGS_ITEM_UPDATE_STATE_GUARD, 1);

            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "cxa_atexit receives one node");
            assert_eq!((*node).arg.cast::<SettingsItemUpdateState>(), state());
            assert_eq!(
                (*node).handler as usize,
                settings_item_update_state_destructor as usize,
                "the invalid retail destructor address maps to the safe no-op"
            );
            assert_eq!((*node).key, DSO_HANDLE);
            assert!((*node).next.is_null(), "the singleton registers once");
        }
        restore(test_lock);
    }

    #[test]
    fn initialized_fast_path_preserves_staged_value_and_flags() {
        let test_lock = reset();
        unsafe {
            settings_item_update_state_get();
            (*state()).value = 73;
            (*state()).apply_setting = 1;
            (*state()).notify = 1;

            assert_eq!(settings_item_update_state_get(), state());
            assert_eq!((*state()).value, 73);
            assert_eq!((*state()).apply_setting, 1);
            assert_eq!((*state()).notify, 1);
            assert!((*(*shutdown_chain_head())).next.is_null(), "no second registration");
        }
        restore(test_lock);
    }

    #[test]
    fn bit_zero_clear_nonzero_guard_refuses_initialization() {
        let test_lock = reset();
        unsafe {
            SETTINGS_ITEM_UPDATE_STATE_GUARD = 2;
            assert_eq!(settings_item_update_state_get(), state());
            assert_eq!(SETTINGS_ITEM_UPDATE_STATE_GUARD, 2);
            assert_eq!((*state()).value, 0x1234_5678);
            assert_eq!((*state()).apply_setting, 0xa5);
            assert_eq!((*state()).notify, 0x5a);
            assert!(shutdown_chain_head().read().is_null(), "refused acquire does not register");
        }
        restore(test_lock);
    }

    #[test]
    fn registered_non_entry_destructor_is_shutdown_safe_noop() {
        let test_lock = reset();
        unsafe {
            settings_item_update_state_get();
            lib_shutdown_chain(0);
            assert!(shutdown_chain_head().read().is_null());
        }
        restore(test_lock);
    }
}
