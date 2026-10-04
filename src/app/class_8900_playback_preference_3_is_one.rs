//! `class_8900_playback_preference_3_is_one` — `FUN_081edab4` @ 0x081edab4.
//! True extent: 32 bytes, through 0x081edad0; the next real function begins
//! at 0x081edad4. Whole-image raw A32 decoding verifies two incoming plain
//! BLs (0x0810cdfc, 0x0810d014), zero predicated BLs, and one outgoing plain
//! BL to `instance_6000_settings_block` @ 0x08171ff8.
//!
//! Load the class-0x6000 store from the class-0x8900 object's +0x378 field,
//! obtain its embedded playback settings at +0x60, and return whether the
//! unsigned byte at settings +3 equals exactly 1. The preference's
//! user-facing identity is not established; other nonzero values are false.
//!
//! Deliberate deviations: reuse the existing repr(C) Class8900 layout for
//! wider host pointers and call the existing Rust accessor directly. No
//! validation or NULL guard is added; the boolean result preserves stock's
//! normalized zero/one return.

use crate::app::class_8900::Class8900;
use crate::app::registry::instance_6000_settings_block;

/// Tests whether playback-preference byte +3 is exactly one.
///
/// # Safety
/// `this` must address a valid Class8900 whose store has a readable byte
/// at +0x63 (settings +3).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_playback_preference_3_is_one(this: *const Class8900) -> bool {
    let settings = unsafe { instance_6000_settings_block((*this).store.cast()) };
    unsafe { settings.add(3).read() == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn exactly_one_is_true_for_every_byte_without_mutating_store() {
        let mut store = [0xa5a5_a5a5u32; 0x64 / 4];
        let bytes = store.as_mut_ptr().cast::<u8>();
        let object = Class8900 {
            vtable: ptr::null(),
            state_below_cache: [0; 11],
            cached_6031: 0,
            state_below_store: [0; 209],
            store: bytes.cast(),
        };
        for value in 0..=255u8 {
            unsafe { bytes.add(0x63).write(value); }
            let before = store;
            assert_eq!(unsafe { class_8900_playback_preference_3_is_one(&object) }, value == 1,
                "preference={value:#x}");
            assert_eq!(store, before, "getter must not modify the store");
        }
    }
}
