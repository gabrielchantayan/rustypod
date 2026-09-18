//! Audio output level register update.
//!
//! `audio_output_set_level` — original: `FUN_081071b8` @ `0x081071b8`
//! (48 bytes, 12 ARM instructions; `0x081071b8..0x081071e8`). The next
//! function begins at `0x081071e8` with `push {r3-r11,lr}`. Raw whole-image
//! decoding finds three plain `bl` callers and one predicated `bl` caller.
//!
//! When `apply` is nonzero, masks the low seven bits of `level` into bits
//! 4..10 of the MMIO word at `0x38400800`, retaining only the stock
//! `0x007c1ff7` register bits before replacing that field. `output` is passed
//! by callers but unused by the ARM body.
//!
//! Deliberate deviation: volatile accesses preserve MMIO semantics, where the
//! retail body used ordinary `ldr` and `str`.

use core::ptr;

const AUDIO_OUTPUT_CONTROL_ADDRESS: usize = 0x3840_0800;
const PRESERVED_BITS: u32 = 0x007c_1ff7;
const LEVEL_BITS: u32 = 0x0000_07f0;

#[cfg(target_os = "none")]
#[inline(always)]
fn audio_output_control() -> *mut u32 {
    AUDIO_OUTPUT_CONTROL_ADDRESS as *mut u32
}

#[cfg(not(target_os = "none"))]
static mut HOST_AUDIO_OUTPUT_CONTROL: u32 = 0;

#[cfg(not(target_os = "none"))]
#[inline(always)]
fn audio_output_control() -> *mut u32 {
    core::ptr::addr_of_mut!(HOST_AUDIO_OUTPUT_CONTROL)
}

/// Applies `level` to the audio output control register when `apply` is nonzero.
///
/// # Safety
///
/// On target, this updates the MMIO register at `0x38400800`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn audio_output_set_level(_output: *mut u8, level: u32, apply: u32) {
    if apply == 0 {
        return;
    }

    let control = audio_output_control();
    let current = ptr::read_volatile(control);
    let updated = (current & PRESERVED_BITS & !LEVEL_BITS) | ((level & 0x7f) << 4);
    ptr::write_volatile(control, updated);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_a_seven_bit_level_only_when_requested() {
        unsafe {
            HOST_AUDIO_OUTPUT_CONTROL = 0xffff_ffff;
            audio_output_set_level(core::ptr::null_mut(), 0x1ff, 0);
            assert_eq!(HOST_AUDIO_OUTPUT_CONTROL, 0xffff_ffff);

            audio_output_set_level(core::ptr::null_mut(), 0x1ff, 1);
            assert_eq!(HOST_AUDIO_OUTPUT_CONTROL, 0x007c_1ff7);

            HOST_AUDIO_OUTPUT_CONTROL = 0x1234_5678;
            audio_output_set_level(core::ptr::null_mut(), 0, u32::MAX);
            assert_eq!(HOST_AUDIO_OUTPUT_CONTROL, 0x0034_1000);
        }
    }
}
