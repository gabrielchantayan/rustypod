//! `media_player_setting_select` — original: `FUN_081392e8` @ **0x081392e8**
//! (**136-byte true extent**: 132 instruction bytes through `0x0813936c`,
//! followed by the global-state literal `0x089cca20` at `0x08139370`; the
//! next separately linked function begins at `0x08139374`).
//!
//! Raw ARM contains one plain direct `bl` to `settings_get`, one predicated
//! `bleq heap_panic`, and two dynamic vtable `blx` calls (the setter is
//! predicated). Decoding all ARM B/BL immediates in `osos.dec` finds **four
//! plain inbound `bl` sites and no predicated inbound `bl` sites**.
//!
//! # Algorithm
//!
//! Reject signed selectors at least three and requested values above two with
//! status 4. Otherwise obtain the settings store, read its vtable slot +0x108,
//! and, when requested, record the old value and selector in the global
//! change record only while no record is pending. Finally call slot +0x104
//! only if the old and requested values differ. Status is always zero after a
//! valid request.
//!
//! # Deliberate deviations
//!
//! The firmware's RW global at `0x089cca20` is a crate static because the
//! image's corresponding page is runtime initialized. On the 32-bit target,
//! the dynamic slots are read from their recovered byte offsets; host tests
//! use a native-width operation seam. Neither virtual target has a recovered
//! function identity, so this module names only the observed get/set roles.


const INVALID_ARGUMENT: u32 = 4;
const SETTINGS_GET_VALUE_SLOT: usize = 0x108 / 4;
const SETTINGS_SET_VALUE_SLOT: usize = 0x104 / 4;

/// Firmware global at 0x089cca20 as observed by this function.
#[repr(C)]
pub struct MediaPlayerSettingChange {
    /// +0x00: nonzero while a change awaits consumption.
    pub pending: u8,
    /// +0x01: old setting value, narrowed exactly by `strb`.
    pub old_value: u8,
    pub _padding_02: [u8; 2],
    /// +0x04: signed selector preserved as its raw register word.
    pub selector: i32,
}

static mut MEDIA_PLAYER_SETTING_CHANGE: MediaPlayerSettingChange = MediaPlayerSettingChange {
    pending: 0,
    old_value: 0,
    _padding_02: [0; 2],
    selector: 0,
};

/// Host replacement for the settings getter and its two unrecovered vtable slots.
#[derive(Clone, Copy)]
pub struct MediaPlayerSettingSelectOps {
    pub get_settings: unsafe extern "C" fn() -> *mut u8,
    pub get_value: unsafe extern "C" fn(*mut u8) -> u32,
    pub set_value: unsafe extern "C" fn(*mut u8, u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_settings() -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_get_value(_settings: *mut u8) -> u32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_set_value(_settings: *mut u8, _value: u32) {}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_MEDIA_PLAYER_SETTING_SELECT_OPS: MediaPlayerSettingSelectOps = MediaPlayerSettingSelectOps {
    get_settings: missing_settings,
    get_value: missing_get_value,
    set_value: missing_set_value,
};

#[cfg(not(target_os = "none"))]
pub static mut MEDIA_PLAYER_SETTING_SELECT_OPS: MediaPlayerSettingSelectOps = DEFAULT_MEDIA_PLAYER_SETTING_SELECT_OPS;

#[cfg(not(target_os = "none"))]
unsafe fn setting_operations() -> MediaPlayerSettingSelectOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_PLAYER_SETTING_SELECT_OPS)) }
}

#[cfg(target_os = "none")]
unsafe fn setting_operations() -> MediaPlayerSettingSelectOps {
    unsafe extern "C" fn get_settings() -> *mut u8 { unsafe { crate::cxx::settings::settings_get() } }
    unsafe extern "C" fn get_value(settings: *mut u8) -> u32 {
        let vtable = unsafe { *(settings.cast::<u32>()) as *const u32 };
        let target = unsafe { *vtable.add(SETTINGS_GET_VALUE_SLOT) };
        let get: unsafe extern "C" fn(*mut u8) -> u32 = unsafe { core::mem::transmute(target as usize) };
        unsafe { get(settings) }
    }
    unsafe extern "C" fn set_value(settings: *mut u8, value: u32) {
        let vtable = unsafe { *(settings.cast::<u32>()) as *const u32 };
        let target = unsafe { *vtable.add(SETTINGS_SET_VALUE_SLOT) };
        let set: unsafe extern "C" fn(*mut u8, u32) = unsafe { core::mem::transmute(target as usize) };
        unsafe { set(settings, value) };
    }
    MediaPlayerSettingSelectOps { get_settings, get_value, set_value }
}

/// Selects a media-player setting value and conditionally records its old value.
///
/// # Safety
///
/// On target the settings singleton and its +0x104/+0x108 vtable slots must be
/// valid. Host callers must install equivalent operations before a valid call.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_setting_select(
    _unused: *mut u8,
    selector: i32,
    requested_value: u32,
    record_change: u32,
) -> u32 {
    if selector >= 3 || requested_value > 2 {
        return INVALID_ARGUMENT;
    }

    let ops = unsafe { setting_operations() };
    let settings = unsafe { (ops.get_settings)() };
    if settings.is_null() {
        unsafe { crate::heap::veneers::heap_panic() };
    }
    let old_value = unsafe { (ops.get_value)(settings) };

    if record_change != 0 {
        let change = core::ptr::addr_of_mut!(MEDIA_PLAYER_SETTING_CHANGE);
        if unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*change).pending)) } == 0 {
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*change).old_value), old_value as u8) };
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*change).pending), 1) };
            unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*change).selector), selector) };
        }
    }
    if old_value != requested_value {
        unsafe { (ops.set_value)(settings, requested_value) };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use core::sync::atomic::{AtomicU32, Ordering};

    static OLD_VALUE: AtomicU32 = AtomicU32::new(0);
    static SET_VALUE: AtomicU32 = AtomicU32::new(u32::MAX);
    static SET_CALLS: AtomicU32 = AtomicU32::new(0);
    static mut SETTINGS: u8 = 0;
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn settings() -> *mut u8 { core::ptr::addr_of_mut!(SETTINGS) }
    unsafe extern "C" fn get_value(_settings: *mut u8) -> u32 { OLD_VALUE.load(Ordering::Relaxed) }
    unsafe extern "C" fn set_value(_settings: *mut u8, value: u32) {
        SET_VALUE.store(value, Ordering::Relaxed);
        SET_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    fn install(old_value: u32) {
        OLD_VALUE.store(old_value, Ordering::Relaxed);
        SET_VALUE.store(u32::MAX, Ordering::Relaxed);
        SET_CALLS.store(0, Ordering::Relaxed);
        unsafe {
            MEDIA_PLAYER_SETTING_SELECT_OPS = MediaPlayerSettingSelectOps { get_settings: settings, get_value, set_value };
            MEDIA_PLAYER_SETTING_CHANGE = MediaPlayerSettingChange { pending: 0, old_value: 0, _padding_02: [0; 2], selector: 0 };
        }
    }

    #[test]
    fn records_first_change_and_updates_when_value_differs() {
        let _lock = TEST_LOCK.lock();
        install(0x101);
        assert_eq!(unsafe { media_player_setting_select(core::ptr::null_mut(), 2, 1, 1) }, 0);
        assert_eq!(SET_VALUE.load(Ordering::Relaxed), 1);
        assert_eq!(SET_CALLS.load(Ordering::Relaxed), 1);
        let change = unsafe { &*core::ptr::addr_of!(MEDIA_PLAYER_SETTING_CHANGE) };
        assert_eq!((change.pending, change.old_value, change.selector), (1, 1, 2));
    }

    #[test]
    fn preserves_pending_change_and_skips_redundant_set() {
        let _lock = TEST_LOCK.lock();
        install(2);
        unsafe { MEDIA_PLAYER_SETTING_CHANGE = MediaPlayerSettingChange { pending: 1, old_value: 9, _padding_02: [0; 2], selector: 7 } };
        assert_eq!(unsafe { media_player_setting_select(core::ptr::null_mut(), -1, 2, 1) }, 0);
        assert_eq!(SET_CALLS.load(Ordering::Relaxed), 0);
        let change = unsafe { &*core::ptr::addr_of!(MEDIA_PLAYER_SETTING_CHANGE) };
        assert_eq!((change.pending, change.old_value, change.selector), (1, 9, 7));
    }

    #[test]
    fn rejects_only_signed_selectors_at_least_three_and_values_above_two() {
        let _lock = TEST_LOCK.lock();
        install(0);
        assert_eq!(unsafe { media_player_setting_select(core::ptr::null_mut(), 3, 0, 0) }, INVALID_ARGUMENT);
        assert_eq!(unsafe { media_player_setting_select(core::ptr::null_mut(), 0, 3, 0) }, INVALID_ARGUMENT);
        assert_eq!(SET_CALLS.load(Ordering::Relaxed), 0);
    }
}
