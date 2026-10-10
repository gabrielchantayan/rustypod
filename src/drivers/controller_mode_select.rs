//! Three-state controller mode register selection.
//!
//! `controller_mode_select` — original `FUN_080b1b50` at `0x080b1b50`.
//! Raw extent `0x080b1b50..0x080b1b80`: 48 bytes, 12 A32 instructions;
//! the next function starts with `push {r4,r5,r6,lr}`. Whole-image word
//! decoding verifies two incoming plain BLs (0x0836e158, 0x0836e1cc), zero
//! predicated incoming BLs and zero outgoing BLs of either kind.
//!
//! Modes 0, 1 and 2 overwrite the word at 0x3c400018 with 0x400, 0x600
//! and zero respectively. Every other input returns without accessing it.
//! Callers select 0 during initialization and 0/2 during transitions;
//! the peripheral's precise identity is not assumed.
//!
//! Deliberate deviations: volatile writes express the stock MMIO store;
//! host builds substitute a backing word for the fixed hardware address.

use core::ptr;

#[cfg(target_os = "none")]
const MODE_REGISTER_ADDRESS: usize = 0x3c40_0018;

#[cfg(not(target_os = "none"))]
static mut HOST_MODE_REGISTER: u32 = 0;

#[inline(always)]
fn mode_register() -> *mut u32 {
    #[cfg(target_os = "none")]
    { MODE_REGISTER_ADDRESS as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_MODE_REGISTER) }
}

/// Selects one of three register encodings; invalid modes do nothing.
///
/// # Safety
/// On target the caller must permit a write to MMIO word 0x3c400018.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_mode_select(mode: u32) {
    let value = match mode {
        0 => 0x400,
        1 => 0x600,
        2 => 0,
        _ => return,
    };
    ptr::write_volatile(mode_register(), value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_word_encodings_and_invalid_modes() {
        unsafe {
            // Each valid mode replaces rather than masks the previous word.
            for (mode, expected) in [(0, 0x400), (1, 0x600), (2, 0)] {
                for initial in [0, u32::MAX, 0x1234_5678] {
                    ptr::write_volatile(mode_register(), initial);
                    controller_mode_select(mode);
                    assert_eq!(ptr::read_volatile(mode_register()), expected);
                }
            }
            for mode in (3..=255).chain([0x7fff_ffff, 0x8000_0000, u32::MAX]) {
                ptr::write_volatile(mode_register(), 0xa5a5_5a5a);
                controller_mode_select(mode);
                assert_eq!(ptr::read_volatile(mode_register()), 0xa5a5_5a5a);
            }
            // Invalid transitions must retain the last valid selection.
            for (mode, expected) in [(1, 0x600), (2, 0), (0, 0x400)] {
                controller_mode_select(mode);
                controller_mode_select(u32::MAX);
                assert_eq!(ptr::read_volatile(mode_register()), expected);
            }
        }
    }
}
