//! Construct the UI mode/dimension state in caller-owned storage.
//!
//! `ui_mode_state_construct` — `FUN_080f8168` @ 0x080f8168, 68 bytes,
//! ending at 0x080f81a8; the next real function starts at 0x080f81ac.
//! Raw words contain four plain BLs, zero predicated BLs; whole-image
//! decoding finds two inbound plain BLs and zero predicated inbound BLs.
//!
//! Initialize the binding bytes, select mode/variant zero with both enable
//! bytes set, set byte +0x0e to 1 and byte +0x0d to 3 through the retail
//! setters (each refreshes the binding), then apply mode dimensions. Return
//! the original storage pointer, ignoring the dimension applier's result.
//!
//! Deliberate deviations: inline the four byte writes of 0x080f7e18 (raw
//! code preserves r0, contrary to Ghidra's void/no-argument reconstruction).
//! The unported setters retain their verified raw addresses and byte ABIs;
//! no backend identity is asserted. Reuse the existing dimension port.

use core::ptr;
use super::apply_mode_dimensions::ui_apply_mode_dimensions;

type ByteSetter = unsafe extern "C" fn(*mut u8, u32);
type DimensionsApply = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_set_byte_0e(state: *mut u8, value: u32) {
    core::mem::transmute::<usize, ByteSetter>(0x080f_7e10)(state, value)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_set_byte_0d(state: *mut u8, value: u32) {
    core::mem::transmute::<usize, ByteSetter>(0x080f_7e08)(state, value)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_setter(_: *mut u8, _: u32) {
    panic!("ui_mode_state_construct requires retail binding setters")
}

pub static mut SET_BYTE_0E: ByteSetter = {
    #[cfg(target_os = "none")] { retail_set_byte_0e }
    #[cfg(not(target_os = "none"))] { missing_setter }
};
pub static mut SET_BYTE_0D: ByteSetter = {
    #[cfg(target_os = "none")] { retail_set_byte_0d }
    #[cfg(not(target_os = "none"))] { missing_setter }
};
pub static mut APPLY_DIMENSIONS: DimensionsApply = ui_apply_mode_dimensions;

unsafe fn initialize_defaults(state: *mut u8) {
    state.add(0x0f).write(0);
    state.add(0x10).write(0xff);
    state.add(0x0d).write(0);
    state.add(0x0e).write(0);
    state.add(0x1d).write(0);
    state.add(0x1e).write(0);
    state.add(0x1f).write(1);
    state.add(0x20).write(1);
}

/// # Safety
/// `state` must reference an aligned, writable 0x24-byte retail state object.
/// Installed setters/appliers must obey the retail ABI and storage contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_mode_state_construct(state: *mut u8) -> *mut u8 {
    initialize_defaults(state);
    ptr::read_volatile(ptr::addr_of!(SET_BYTE_0E))(state, 1);
    ptr::read_volatile(ptr::addr_of!(SET_BYTE_0D))(state, 3);
    ptr::read_volatile(ptr::addr_of!(APPLY_DIMENSIONS))(state);
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn defaults_clear_stale_bytes_without_clearing_unrelated_storage() {
        for fill in [0, 0xff, 0xa5] {
            let mut storage = [fill; 0x26];
            let mut expected = storage;
            for (offset, value) in [(0x0d, 0), (0x0e, 0), (0x0f, 0), (0x10, 0xff),
                                    (0x1d, 0), (0x1e, 0), (0x1f, 1), (0x20, 1)] {
                expected[offset + 1] = value;
            }
            unsafe { initialize_defaults(storage.as_mut_ptr().add(1)); }
            assert_eq!(storage, expected);
        }
    }

    unsafe extern "C" fn set_0e(state: *mut u8, value: u32) {
        assert_eq!(state.add(0x0d).read(), 0);
        assert_eq!(state.add(0x0f).read(), 0);
        assert_eq!(state.add(0x10).read(), 0xff);
        state.add(0x0e).write(value as u8);
        // Model a binding-refresh side effect which later initialization must not erase.
        state.add(0x0f).write(7);
    }
    unsafe extern "C" fn set_0d(state: *mut u8, value: u32) {
        assert_eq!(state.add(0x0e).read(), 1);
        assert_eq!(state.add(0x0f).read(), 7);
        state.add(0x0d).write(value as u8);
    }
    unsafe extern "C" fn apply(state: *mut u8) -> u32 {
        assert_eq!(core::slice::from_raw_parts(state.add(0x1d), 4), &[0, 0, 1, 1]);
        assert_eq!(state.add(0x0d).read(), 3);
        assert_eq!(state.add(0x0e).read(), 1);
        (state as *mut u32).write(28);
        (state.add(4) as *mut u32).write(17);
        0xdead_beef
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ptr::addr_of_mut!(SET_BYTE_0E).write(missing_setter);
            ptr::addr_of_mut!(SET_BYTE_0D).write(missing_setter);
            ptr::addr_of_mut!(APPLY_DIMENSIONS).write(ui_apply_mode_dimensions);
        } }
    }
    #[test]
    fn construction_preserves_refresh_effects_and_returns_storage_not_apply_result() {
        let _lock = LOCK.lock();
        let _restore = Restore;
        let mut storage = [0xa5a5_a5a5u32; 9];
        unsafe {
            ptr::addr_of_mut!(SET_BYTE_0E).write(set_0e);
            ptr::addr_of_mut!(SET_BYTE_0D).write(set_0d);
            ptr::addr_of_mut!(APPLY_DIMENSIONS).write(apply);
            let state = storage.as_mut_ptr() as *mut u8;
            assert_eq!(ui_mode_state_construct(state), state);
            assert_eq!(storage[0], 28);
            assert_eq!(storage[1], 17);
            assert_eq!(state.add(0x0f).read(), 7);
            assert_eq!(state.add(0x21).read(), 0xa5);
        }
    }
}
