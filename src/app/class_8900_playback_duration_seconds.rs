//! `class_8900_playback_duration_seconds` — `FUN_081edb98` @ 0x081edb98.
//! True size: 20 bytes; next function is the tail-branch veneer at
//! 0x081edbac. Raw whole-image A32 decoding verifies two incoming plain BLs
//! (0x0810d6e8, 0x082289a8), no predicated BLs, and one outgoing plain BL
//! to `instance_6000_settings_block` @ 0x08171ff8.
//!
//! Load the class-0x6000 store from this+0x378, obtain settings at store+0x60,
//! and return settings[4] sign-extended to i32. Caller 0x0810d6dc treats zero
//! as disabled and multiplies the result by 1000 for a timer; 0x08228968
//! maps 0, 2, 5, 10, and 20 to UI choices. The exact user-facing duration
//! identity is not established; negative bytes are returned unchanged.
//!
//! Deliberate deviations: reuse the existing repr(C) Class8900 layout for
//! native host pointers and the existing Rust settings accessor. No NULL
//! guards, range checks, or normalization are added.

use crate::app::class_8900::Class8900;
use crate::app::registry::instance_6000_settings_block;

/// Returns the signed playback duration setting in seconds.
///
/// # Safety
/// `this` must address a valid Class8900 whose store has a readable byte
/// at +0x64 (settings+4).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_playback_duration_seconds(this: *const Class8900) -> i32 {
    let settings = unsafe { instance_6000_settings_block((*this).store.cast()) };
    unsafe { settings.add(4).cast::<i8>().read() as i32 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn duration_sign_extends_every_byte_without_changing_settings() {
        let mut store = [0xa5a5_a5a5u32; 0x74 / 4];
        let bytes = store.as_mut_ptr().cast::<u8>();
        let object = Class8900 {
            vtable: ptr::null(),
            state_below_cache: [0; 11],
            cached_6031: 0,
            state_below_store: [0; 209],
            store: bytes.cast(),
        };
        for value in 0..=255u8 {
            unsafe { bytes.add(0x64).write(value) };
            let before = store;
            let expected = if value < 128 { i32::from(value) } else { i32::from(value) - 256 };
            assert_eq!(unsafe { class_8900_playback_duration_seconds(&object) }, expected,
                "stored duration={value:#x}");
            assert_eq!(store, before, "getter must not modify settings");
        }
    }
}
