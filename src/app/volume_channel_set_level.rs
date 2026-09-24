//! `volume_channel_set_level` — original: `FUN_081224e8` @ **0x081224e8**.
//!
//! The true extent is **28 bytes**, `0x081224e8..0x08122503`: seven A32 words
//! ending in a branch to the shared level-scaling block at `0x08122254`.
//! `ldr r2,[r0,#0x90]` at `0x08122504` begins the next independently entered
//! function. The body has **0 plain** and **0 predicated `bl`** instructions.
//! Whole-image A32 decoding finds **3 direct plain `bl`** callers
//! (`0x08121ee0`, `0x08122dcc`, and `0x08123510`) and **0 predicated `bl`**
//! callers.
//!
//! # Algorithm
//!
//! Unless the requested level matches the saved level without a forced update,
//! save values below `0x8000`, then derive the two output levels. Each output
//! is Q15-scaled by its signed factor when that factor is below `0x7fff`; a
//! factor at or above `0x7fff` leaves its output at the saved level.
//!
//! # Deliberate deviations
//!
//! The retail entry tail-branches to a shared internal block. Rust inlines that
//! block so a hook at this entry remains self-contained; the observable reads,
//! writes, signed comparisons, and wrapping ARM multiply results are preserved.

const SAVED_LEVEL_WORD: usize = 0x6c / 4;
const PRIMARY_OUTPUT_WORD: usize = 0x70 / 4;
const SECONDARY_OUTPUT_WORD: usize = 0x74 / 4;
const PRIMARY_SCALE_WORD: usize = 0x7c / 4;
const SECONDARY_SCALE_WORD: usize = 0x80 / 4;
const UNITY_SCALE: i32 = 0x7fff;

/// Updates a channel's saved level and its two Q15-scaled output levels.
///
/// # Safety
/// `channel` must point to an aligned, writable retail channel object with
/// valid u32 fields through offset `0x80`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_channel_set_level(channel: *mut u32, requested_level: u32, force: u32) {
    let saved_level = unsafe { channel.add(SAVED_LEVEL_WORD).read() };
    if saved_level == requested_level && force == 0 {
        return;
    }

    if requested_level < 0x8000 {
        unsafe { channel.add(SAVED_LEVEL_WORD).write(requested_level) };
    }

    let saved_level = unsafe { channel.add(SAVED_LEVEL_WORD).read() };
    let primary_scale = unsafe { channel.add(PRIMARY_SCALE_WORD).read() } as i32;
    let primary_output = if primary_scale < UNITY_SCALE {
        (primary_scale as u32).wrapping_mul(saved_level) >> 15
    } else {
        saved_level
    };
    unsafe { channel.add(PRIMARY_OUTPUT_WORD).write(primary_output) };

    let secondary_scale = unsafe { channel.add(SECONDARY_SCALE_WORD).read() } as i32;
    let secondary_output = if secondary_scale < UNITY_SCALE {
        (secondary_scale as u32).wrapping_mul(saved_level) >> 15
    } else {
        saved_level
    };
    unsafe { channel.add(SECONDARY_OUTPUT_WORD).write(secondary_output) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_unforced_level_preserves_outputs() {
        let mut channel = [0_u32; 33];
        channel[SAVED_LEVEL_WORD] = 1234;
        channel[PRIMARY_OUTPUT_WORD] = 55;
        channel[SECONDARY_OUTPUT_WORD] = 66;
        channel[PRIMARY_SCALE_WORD] = 0x4000;
        channel[SECONDARY_SCALE_WORD] = 0x2000;

        unsafe { volume_channel_set_level(channel.as_mut_ptr(), 1234, 0) };

        assert_eq!(channel[PRIMARY_OUTPUT_WORD], 55);
        assert_eq!(channel[SECONDARY_OUTPUT_WORD], 66);
    }

    #[test]
    fn saves_valid_level_and_scales_both_outputs() {
        let mut channel = [0_u32; 33];
        channel[PRIMARY_SCALE_WORD] = 0x4000;
        channel[SECONDARY_SCALE_WORD] = 0x2000;

        unsafe { volume_channel_set_level(channel.as_mut_ptr(), 0x6000, 0) };

        assert_eq!(channel[SAVED_LEVEL_WORD], 0x6000);
        assert_eq!(channel[PRIMARY_OUTPUT_WORD], 0x3000);
        assert_eq!(channel[SECONDARY_OUTPUT_WORD], 0x1800);
    }

    #[test]
    fn forced_out_of_range_level_reuses_saved_level_and_signed_scales() {
        let mut channel = [0_u32; 33];
        channel[SAVED_LEVEL_WORD] = 0x6000;
        channel[PRIMARY_SCALE_WORD] = 0x7fff;
        channel[SECONDARY_SCALE_WORD] = 0xffff_ffff;

        unsafe { volume_channel_set_level(channel.as_mut_ptr(), 0x8000, 1) };

        assert_eq!(channel[SAVED_LEVEL_WORD], 0x6000);
        assert_eq!(channel[PRIMARY_OUTPUT_WORD], 0x6000);
        assert_eq!(channel[SECONDARY_OUTPUT_WORD], 0x0001_ffff);
    }
}
