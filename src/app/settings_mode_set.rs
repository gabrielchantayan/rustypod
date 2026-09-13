//! Fixed settings-mode setter.
//!
//! Port:
//! - [`settings_mode_set`] — original: `FUN_0806b880` @ `0x0806b880`
//!   (**136 instruction bytes plus its 4-byte literal pool; 7 direct `bl`
//!   call sites, all unconditional and zero predicated**).
//!
//! Raw ARM starts at `0x0806b880`; its final instruction is `pop {r4, r5,
//! r6, r7, r8, pc}` at `0x0806b904`. The literal `0x089ca5e0` at
//! `0x0806b908` addresses the mode state, and the next independently entered
//! function starts at `0x0806b90c`. Ghidra's 136-byte extent therefore covers
//! the instruction body, not its trailing literal.
//!
//! ## Algorithm
//!
//! Snapshot the active mode byte, obtain selector 1 from the lazy settings
//! item, and leave the state unchanged if that target is null. Otherwise, a
//! changed zero mode writes one to state word +8 and calls vtable slot +32
//! with zero before calling slot +16 with false. A changed nonzero mode writes
//! zero to word +8 and calls only slot +16 with true. It then stores the low
//! byte of the requested mode and returns the original active byte.
//!
//! ## Deliberate deviations
//!
//! Target builds access the fixed mode-state address and retain the unported
//! selector at `0x08153534` through a direct function-pointer boundary. Host
//! builds substitute private state and an overrideable selector so tests can
//! exercise the null and virtual-dispatch paths. The vtable's unrecovered
//! slots remain opaque; only its verified +16 and +32 callbacks are modeled.

#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::app::settings_item::settings_item_get;

const SETTINGS_MODE_STATE_ADDRESS: usize = 0x089c_a5e0;
const SETTINGS_ITEM_TARGET_SELECTOR: u32 = 1;

type SettingsItemSelect = unsafe extern "C" fn(*mut u8, u32) -> *mut SettingsModeTarget;
type SettingsModeCallback = unsafe extern "C" fn(*mut SettingsModeTarget, u32);

/// State words touched by `settings_mode_set`.
#[repr(C)]
struct SettingsModeState {
    active_mode: u8,
    _unknown_01: [u8; 7],
    mode_state_word_08: u32,
}

const _: () = assert!(core::mem::offset_of!(SettingsModeState, active_mode) == 0);
const _: () = assert!(core::mem::offset_of!(SettingsModeState, mode_state_word_08) == 8);

/// Vtable prefix consumed by the mode setter.
#[repr(C)]
struct SettingsModeTargetVtable {
    _slots_00_to_0c: [u32; 4],
    apply_mode: SettingsModeCallback,
    _slots_14_to_1c: [u32; 3],
    prepare_zero_mode: SettingsModeCallback,
}

#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(SettingsModeTargetVtable, apply_mode) == 0x10);
#[cfg(target_os = "none")]
const _: () = assert!(core::mem::offset_of!(SettingsModeTargetVtable, prepare_zero_mode) == 0x20);

/// The selected settings object has a vtable as its first target word.
#[repr(C)]
struct SettingsModeTarget {
    vtable: *const SettingsModeTargetVtable,
}

#[cfg(not(target_os = "none"))]
static mut HOST_SETTINGS_MODE_STATE: SettingsModeState = SettingsModeState {
    active_mode: 0,
    _unknown_01: [0; 7],
    mode_state_word_08: 0,
};

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn settings_mode_state() -> *mut SettingsModeState {
    SETTINGS_MODE_STATE_ADDRESS as *mut SettingsModeState
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn settings_mode_state() -> *mut SettingsModeState {
    ptr::addr_of_mut!(HOST_SETTINGS_MODE_STATE)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn settings_item_select() -> SettingsItemSelect {
    core::mem::transmute(0x0815_3534usize)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_settings_item_select(
    _item: *mut u8,
    _selector: u32,
) -> *mut SettingsModeTarget {
    panic!("settings_mode_set requires settings item selector 0x08153534")
}

/// Host seam for the unported selector at `0x08153534`.
#[cfg(not(target_os = "none"))]
pub static mut SETTINGS_ITEM_SELECT: SettingsItemSelect = missing_settings_item_select;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn settings_item_select() -> SettingsItemSelect {
    ptr::read_volatile(ptr::addr_of!(SETTINGS_ITEM_SELECT))
}

/// `settings_mode_set` — original: `FUN_0806b880` @ `0x0806b880` (136
/// instruction bytes plus a 4-byte literal pool; 7 direct unconditional `bl`
/// call sites, binary-verified by decoding every ARM B/BL word).
///
/// Applies `requested_mode` to the shared settings target when it differs from
/// the current byte, returning the old active byte. Any nonzero request is
/// forwarded to the vtable as canonical `1`, while its low byte becomes the
/// new active value, precisely matching `cmp r5,#0`, `movne r7,#1`, and
/// `strb r5,[r6]` in the ARM body.
///
/// # Safety
///
/// On target, the mode state at `0x089ca5e0`, its settings item, and the
/// selected target's vtable must be valid and writable as required by their
/// respective operations. Callers must serialize access to the shared state.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.settings_mode_set")]
pub unsafe extern "C" fn settings_mode_set(requested_mode: u32) -> u32 {
    let state = settings_mode_state();
    let previous_mode = (*state).active_mode;
    let target = settings_item_select()(settings_item_get(), SETTINGS_ITEM_TARGET_SELECTOR);

    if target.is_null() {
        return (*state).active_mode.into();
    }

    if u32::from((*state).active_mode) != requested_mode {
        if requested_mode == 0 {
            (*state).mode_state_word_08 = 1;
            ((*(*target).vtable).prepare_zero_mode)(target, 0);
        } else {
            (*state).mode_state_word_08 = 0;
        }
        ((*(*target).vtable).apply_mode)(target, u32::from(requested_mode != 0));
        (*state).active_mode = requested_mode as u8;
    }

    previous_mode.into()
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::settings_item::SETTINGS_ITEM_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut APPLY_CALLS: u32 = 0;
    static mut PREPARE_CALLS: u32 = 0;
    static mut SELECT_CALLS: u32 = 0;
    static mut LAST_APPLY_MODE: u32 = u32::MAX;
    static mut LAST_PREPARE_MODE: u32 = u32::MAX;
    static mut TARGET: SettingsModeTarget = SettingsModeTarget { vtable: core::ptr::null() };

    unsafe extern "C" fn record_apply(_target: *mut SettingsModeTarget, mode: u32) {
        APPLY_CALLS += 1;
        LAST_APPLY_MODE = mode;
    }

    unsafe extern "C" fn record_prepare(_target: *mut SettingsModeTarget, mode: u32) {
        PREPARE_CALLS += 1;
        LAST_PREPARE_MODE = mode;
    }

    static VTABLE: SettingsModeTargetVtable = SettingsModeTargetVtable {
        _slots_00_to_0c: [0; 4],
        apply_mode: record_apply,
        _slots_14_to_1c: [0; 3],
        prepare_zero_mode: record_prepare,
    };

    unsafe extern "C" fn record_select(_item: *mut u8, selector: u32) -> *mut SettingsModeTarget {
        SELECT_CALLS += 1;
        assert_eq!(selector, SETTINGS_ITEM_TARGET_SELECTOR);
        ptr::addr_of_mut!(TARGET)
    }

    unsafe extern "C" fn select_null_after_mode_change(
        _item: *mut u8,
        selector: u32,
    ) -> *mut SettingsModeTarget {
        SELECT_CALLS += 1;
        assert_eq!(selector, SETTINGS_ITEM_TARGET_SELECTOR);
        (*settings_mode_state()).active_mode = 0x5a;
        ptr::null_mut()
    }

    struct Seams {
        _settings_item_lock: MutexGuard<'static, ()>,
        _test_lock: MutexGuard<'static, ()>,
        select: SettingsItemSelect,
    }

    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(SETTINGS_ITEM_SELECT).write(self.select) }
        }
    }

    fn install(mode: u8, mode_word: u32) -> Seams {
        let settings_item_lock = SETTINGS_ITEM_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let test_lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ptr::addr_of_mut!(HOST_SETTINGS_MODE_STATE).write(SettingsModeState {
                active_mode: mode,
                _unknown_01: [0; 7],
                mode_state_word_08: mode_word,
            });
            APPLY_CALLS = 0;
            PREPARE_CALLS = 0;
            SELECT_CALLS = 0;
            LAST_APPLY_MODE = u32::MAX;
            LAST_PREPARE_MODE = u32::MAX;
            ptr::addr_of_mut!(TARGET).write(SettingsModeTarget { vtable: &VTABLE });
            let item = settings_item_get().cast::<SettingsModeTarget>();
            item.write(SettingsModeTarget { vtable: &VTABLE });
            let select = ptr::read_volatile(ptr::addr_of!(SETTINGS_ITEM_SELECT));
            ptr::addr_of_mut!(SETTINGS_ITEM_SELECT).write(record_select);
            Seams {
                _settings_item_lock: settings_item_lock,
                _test_lock: test_lock,
                select,
            }
        }
    }

    #[test]
    fn zero_mode_prepares_then_applies_the_selected_target() {
        let _seams = install(1, 0xfeed_beef);

        assert_eq!(unsafe { settings_mode_set(0) }, 1);
        unsafe {
            assert_eq!(HOST_SETTINGS_MODE_STATE.active_mode, 0);
            assert_eq!(HOST_SETTINGS_MODE_STATE.mode_state_word_08, 1);
            assert_eq!(SELECT_CALLS, 1);
            assert_eq!(PREPARE_CALLS, 1);
            assert_eq!(LAST_PREPARE_MODE, 0);
            assert_eq!(APPLY_CALLS, 1);
            assert_eq!(LAST_APPLY_MODE, 0);
        }
    }

    #[test]
    fn nonzero_mode_uses_canonical_callback_flag_and_stores_its_low_byte() {
        let _seams = install(0, 0xfeed_beef);

        assert_eq!(unsafe { settings_mode_set(0x100) }, 0);
        unsafe {
            assert_eq!(HOST_SETTINGS_MODE_STATE.active_mode, 0);
            assert_eq!(HOST_SETTINGS_MODE_STATE.mode_state_word_08, 0);
            assert_eq!(SELECT_CALLS, 1);
            assert_eq!(PREPARE_CALLS, 0);
            assert_eq!(APPLY_CALLS, 1);
            assert_eq!(LAST_APPLY_MODE, 1);
        }
    }

    #[test]
    fn unchanged_mode_still_selects_but_does_not_dispatch() {
        let _seams = install(1, 0x1357_9bdf);

        assert_eq!(unsafe { settings_mode_set(1) }, 1);
        unsafe {
            assert_eq!(HOST_SETTINGS_MODE_STATE.active_mode, 1);
            assert_eq!(HOST_SETTINGS_MODE_STATE.mode_state_word_08, 0x1357_9bdf);
            assert_eq!(SELECT_CALLS, 1);
            assert_eq!(PREPARE_CALLS, 0);
            assert_eq!(APPLY_CALLS, 0);
        }
    }

    #[test]
    fn null_selection_returns_the_live_mode_without_writing_state() {
        let _seams = install(1, 0x2468_ace0);
        unsafe { ptr::addr_of_mut!(SETTINGS_ITEM_SELECT).write(select_null_after_mode_change) };

        assert_eq!(unsafe { settings_mode_set(0) }, 0x5a);
        unsafe {
            assert_eq!(HOST_SETTINGS_MODE_STATE.active_mode, 0x5a);
            assert_eq!(HOST_SETTINGS_MODE_STATE.mode_state_word_08, 0x2468_ace0);
            assert_eq!(SELECT_CALLS, 1);
            assert_eq!(PREPARE_CALLS, 0);
            assert_eq!(APPLY_CALLS, 0);
        }
    }
}
