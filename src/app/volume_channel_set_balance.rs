//! `volume_channel_set_balance` — original: `FUN_08121df8` @ **0x08121df8**.
//!
//! The true extent is **96 bytes**, `0x08121df8..0x08121e57`: 24 A32 words
//! ending in an unconditional branch to the shared level-scaling block at
//! `0x08122254`. The word at `0x08121e58` is the `0x7fff` literal and
//! `0x08121e5c` begins the next independently entered function. The body has
//! **0 plain** and **0 predicated `bl`** instructions. Whole-image A32 decoding
//! finds **3 direct plain `bl`** callers (`0x08121ef0`, `0x08122de0`, and
//! `0x08123520`) and **0 predicated `bl`** callers.
//!
//! # Algorithm
//!
//! Unless the requested balance matches the saved balance without a forced
//! update, reset requests whose wrapping addition of `0x7fff` is at least
//! `0xffff`, save the request, and set the primary or secondary Q15 scale to
//! attenuate the corresponding output.
//! A zero balance leaves both scales at unity. The shared block then applies the
//! signed-less-than Q15 scales to the saved level.
//!
//! # Deliberate deviations
//!
//! The retail entry tail-branches to a shared internal block. Rust inlines that
//! block so a hook at this entry remains self-contained; observable reads,
//! writes, signed comparisons, and wrapping ARM multiply results are preserved.

const SAVED_LEVEL_WORD: usize = 0x6c / 4;
const PRIMARY_OUTPUT_WORD: usize = 0x70 / 4;
const SECONDARY_OUTPUT_WORD: usize = 0x74 / 4;
const SAVED_BALANCE_WORD: usize = 0x78 / 4;
const PRIMARY_SCALE_WORD: usize = 0x7c / 4;
const SECONDARY_SCALE_WORD: usize = 0x80 / 4;
const UNITY_SCALE: u32 = 0x7fff;

/// Updates a channel's balance and its two Q15-scaled output levels.
///
/// # Safety
/// `channel` must point to an aligned, writable retail channel object with
/// valid u32 fields through offset `0x80`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn volume_channel_set_balance(channel: *mut u32, requested_balance: u32, force: u32) {
    let saved_balance = unsafe { channel.add(SAVED_BALANCE_WORD).read() };
    if saved_balance == requested_balance && force == 0 {
        return;
    }

    let balance = if requested_balance.wrapping_add(UNITY_SCALE) >= 0xffff {
        0
    } else {
        requested_balance
    };
    unsafe { channel.add(SAVED_BALANCE_WORD).write(balance) };

    if balance == 0 {
        unsafe { channel.add(PRIMARY_SCALE_WORD).write(UNITY_SCALE) };
        unsafe { channel.add(SECONDARY_SCALE_WORD).write(UNITY_SCALE) };
    } else if (balance as i32) < 0 {
        unsafe { channel.add(SECONDARY_SCALE_WORD).write(balance.wrapping_add(UNITY_SCALE)) };
        unsafe { channel.add(PRIMARY_SCALE_WORD).write(UNITY_SCALE) };
    } else {
        unsafe { channel.add(PRIMARY_SCALE_WORD).write(UNITY_SCALE.wrapping_sub(balance)) };
        unsafe { channel.add(SECONDARY_SCALE_WORD).write(UNITY_SCALE) };
    }

    let saved_level = unsafe { channel.add(SAVED_LEVEL_WORD).read() };
    let primary_scale = unsafe { channel.add(PRIMARY_SCALE_WORD).read() } as i32;
    let primary_output = if primary_scale < UNITY_SCALE as i32 {
        (primary_scale as u32).wrapping_mul(saved_level) >> 15
    } else {
        saved_level
    };
    unsafe { channel.add(PRIMARY_OUTPUT_WORD).write(primary_output) };

    let secondary_scale = unsafe { channel.add(SECONDARY_SCALE_WORD).read() } as i32;
    let secondary_output = if secondary_scale < UNITY_SCALE as i32 {
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
    fn unchanged_unforced_balance_preserves_scales_and_outputs() {
        let mut channel = [0_u32; 33];
        channel[SAVED_BALANCE_WORD] = 0x2000;
        channel[PRIMARY_SCALE_WORD] = 0x5fff;
        channel[SECONDARY_SCALE_WORD] = UNITY_SCALE;
        channel[PRIMARY_OUTPUT_WORD] = 55;
        channel[SECONDARY_OUTPUT_WORD] = 66;

        unsafe { volume_channel_set_balance(channel.as_mut_ptr(), 0x2000, 0) };

        assert_eq!(channel[PRIMARY_SCALE_WORD], 0x5fff);
        assert_eq!(channel[SECONDARY_SCALE_WORD], UNITY_SCALE);
        assert_eq!(channel[PRIMARY_OUTPUT_WORD], 55);
        assert_eq!(channel[SECONDARY_OUTPUT_WORD], 66);
    }

    #[test]
    fn positive_and_negative_balance_attenuate_opposite_outputs() {
        let mut channel = [0_u32; 33];
        channel[SAVED_LEVEL_WORD] = 0x6000;

        unsafe { volume_channel_set_balance(channel.as_mut_ptr(), 0x4000, 0) };
        assert_eq!(channel[PRIMARY_SCALE_WORD], 0x3fff);
        assert_eq!(channel[SECONDARY_SCALE_WORD], UNITY_SCALE);
        assert_eq!(channel[PRIMARY_OUTPUT_WORD], 0x2fff);
        assert_eq!(channel[SECONDARY_OUTPUT_WORD], 0x6000);

        unsafe { volume_channel_set_balance(channel.as_mut_ptr(), 0xffff_c000, 0) };
        assert_eq!(channel[PRIMARY_SCALE_WORD], UNITY_SCALE);
        assert_eq!(channel[SECONDARY_SCALE_WORD], 0x3fff);
        assert_eq!(channel[PRIMARY_OUTPUT_WORD], 0x6000);
        assert_eq!(channel[SECONDARY_OUTPUT_WORD], 0x2fff);
    }

    #[test]
    fn invalid_low_halfword_resets_balance_to_center() {
        let mut channel = [0_u32; 33];
        channel[SAVED_LEVEL_WORD] = 0x6000;

        unsafe { volume_channel_set_balance(channel.as_mut_ptr(), 0x1234_8000, 1) };

        assert_eq!(channel[SAVED_BALANCE_WORD], 0);
        assert_eq!(channel[PRIMARY_SCALE_WORD], UNITY_SCALE);
        assert_eq!(channel[SECONDARY_SCALE_WORD], UNITY_SCALE);
        assert_eq!(channel[PRIMARY_OUTPUT_WORD], 0x6000);
        assert_eq!(channel[SECONDARY_OUTPUT_WORD], 0x6000);
    }
}
