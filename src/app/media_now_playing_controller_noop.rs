//! `media_now_playing_controller_noop` — original: `FUN_08289a5c` @
//! 0x08289a5c (4 bytes).
//!
//! Raw ARM confirms the exact extent: the sole instruction is `bx lr` at
//! 0x08289a5c; the preceding function ends at 0x08289a58, and the next one
//! begins at 0x08289a60 with `push {r4, lr}`. This is neither a literal-pool
//! veneer (`ldr pc, [pc, #-4]`) nor a tail branch.
//!
//! Decoding every ARM B/BL word in `osos.dec` finds 8 direct callers, all
//! unconditional plain `bl` (0x08101560, 0x0810176c, 0x08101980,
//! 0x08130a34, 0x081314cc, 0x081314dc, 0x08131528, and 0x08131584); there are
//! no predicated forms or `b` tail calls. No image data word contains
//! 0x08289a5c, so it is statically bound rather than a vtable target. Every
//! caller obtains `r0` from `instance_of_class_3280` — the identified
//! `TMediaNowPlayingCntlr` singleton — and passes a 0 or 1 word in `r1`.
//!
//! Algorithm: ignore the controller and mode words, read and write no memory,
//! and return the controller word unchanged in `r0`. The firmware has no
//! observable mode-setting effect here, hence `noop` rather than an invented
//! setter identity. Deliberate deviations: none. Its distinct text section
//! prevents folding with other empty return exports.

use core::ffi::c_void;

/// Ignores the TMediaNowPlayingCntlr mode word and returns its controller.
///
/// The ARM body dereferences nothing, so `controller` may be NULL, unaligned,
/// or dangling; `mode` is accepted as the full 32-bit register word because
/// the firmware ignores it rather than validating a Boolean.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.media_now_playing_controller_noop")]
#[inline(never)]
pub unsafe extern "C" fn media_now_playing_controller_noop(
    controller: *mut c_void,
    _mode: u32,
) -> *mut c_void {
    controller
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_every_controller_word_for_both_caller_modes() {
        for controller_word in [0usize, 1, 0x0800_0001, 0x08a7_7c3c, usize::MAX] {
            let controller = controller_word as *mut c_void;
            for mode in [0, 1] {
                assert_eq!(
                    unsafe { media_now_playing_controller_noop(controller, mode) },
                    controller,
                    "controller={controller_word:#x}, mode={mode}"
                );
            }
        }
    }

    #[test]
    fn neither_argument_causes_a_memory_access() {
        let mut controller = [0xa5u8; 32];
        let before = controller;

        let returned = unsafe {
            media_now_playing_controller_noop(controller.as_mut_ptr().cast(), u32::MAX)
        };

        assert_eq!(returned, controller.as_mut_ptr().cast::<c_void>());
        assert_eq!(controller, before, "the bare return writes no object byte");
    }
}
