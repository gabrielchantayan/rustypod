//! `class_8900_playback_preference_byte` — `FUN_081eddbc` @ 0x081eddbc.
//! True extent: 32 bytes, through 0x081eddd8; the next function starts at
//! 0x081edddc. Whole-image raw A32 decoding verifies two incoming plain BLs
//! (0x0810cca8, 0x08233810), zero predicated BLs, and one outgoing plain BL
//! to `instance_6000_settings_block` @ 0x08171ff8.
//!
//! Load the class-0x6000 store from the class-0x8900 object's +0x378 field,
//! obtain its embedded playback settings, and return u32::MAX if byte +6
//! is 0xff. Otherwise return byte +0x10 zero-extended. The adjacent setter
//! writes -1 for unset and -2 for a supplied value; no other flag is rejected.
//! The preference's user-facing identity is not established.
//!
//! Deliberate deviations: reuse the existing repr(C) Class8900 layout for
//! wider host pointers and call the existing Rust accessor directly. No
//! validation or NULL guard is added. Volatile byte reads preserve the
//! original conditional access: the value is not read for an unset flag.

use crate::app::class_8900::Class8900;
use crate::app::registry::instance_6000_settings_block;

/// Returns the stored playback-preference byte, or the unset sentinel.
///
/// # Safety
/// `this` must address a valid Class8900 with a store whose settings byte
/// +6 is readable, and whose byte +0x10 is readable when +6 is not 0xff.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_playback_preference_byte(this: *const Class8900) -> u32 {
    let settings = unsafe { instance_6000_settings_block((*this).store.cast()) };
    if unsafe { settings.add(6).read_volatile() } == 0xff {
        u32::MAX
    } else {
        unsafe { settings.add(0x10).read_volatile() as u32 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn only_ff_is_unset_and_values_are_unsigned() {
        let mut store = [0xa5a5_a5a5u32; 0x74 / 4];
        let bytes = store.as_mut_ptr().cast::<u8>();
        let object = Class8900 {
            vtable: ptr::null(),
            state_below_cache: [0; 11],
            cached_6031: 0,
            state_below_store: [0; 209],
            store: bytes.cast(),
        };
        for flag in 0..=255u8 {
            for value in [0, 1, 25, 127, 128, 254, 255] {
                unsafe {
                    bytes.add(0x66).write(flag);
                    bytes.add(0x70).write(value);
                }
                let before = store;
                let expected = if flag == 255 { u32::MAX } else { u32::from(value) };
                assert_eq!(unsafe { class_8900_playback_preference_byte(&object) }, expected,
                    "flag={flag:#x}, value={value:#x}");
                assert_eq!(store, before, "getter must not modify the store");
            }
        }
    }
}
