//! Cached codec register-pair level update.
//!
//! Original `FUN_080d5244` at `0x080d5244`: true extent 72 bytes through
//! `0x080d528c` (68 executable bytes and literal `0x089d0ef4`). Raw aligned
//! A32 decoding verifies two inbound plain BLs, zero predicated inbound BLs,
//! and one outbound plain BL, zero predicated outbound BLs.
//!
//! Compare the full input word against cached byte +2. Skip an unchanged
//! value only when refresh byte +0 is zero; otherwise cache the low byte
//! before calling `codec_level_scale` with register pair
//! 0x1a/0x1b, the full level word, upper margin 9 and lower margin 7.
//! Both stock paths return zero. The scaler writes duplicate seven-bit
//! gain bytes to the codec at I2C address 0x4a via `0x080da644`.
//!
//! Deliberate deviations: volatile cache access preserves firmware-visible
//! ordering; host builds replace firmware storage and the unported codec
//! writer with a test seam.

use core::ptr;

type WriteGain = unsafe extern "C" fn(u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
static mut HOST_CODEC_LEVEL_STATE: [u8; 4] = [0; 4];

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_host_writer(_: u32, _: u32) -> u32 {
    panic!("codec gain writer 0x080da644 requires a host implementation")
}

#[cfg(not(target_os = "none"))]
static mut HOST_WRITE_GAIN: WriteGain = missing_host_writer;

#[inline(always)]
fn level_state() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x089d_0ef4 as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_CODEC_LEVEL_STATE).cast::<u8>() }
}

#[inline(always)]
fn encoded_gain(level: u32, upper_margin: u32, lower_margin: u32, calibration: u8) -> u32 {
    let floor = 0u32.wrapping_sub(60).wrapping_sub(lower_margin);
    let span = 12u32.wrapping_sub(floor).wrapping_sub(upper_margin) as i16 as i32;
    let product = span * (level as i16 as i32);
    let gain = floor.wrapping_add((product >> 8) as u32)
        .wrapping_add(calibration as u32) as i8 as i32;
    gain.clamp(-60, 12) as u32 & 0x7f
}

/// Codec level scaler, original `FUN_08093a9c` at `0x08093a9c`.
///
/// True extent [0x08093a9c,0x08093af8): 92 bytes (88 code, 4 literal).
/// Raw A32 words verify two plain inbound BLs, zero predicated inbound BLs,
/// one plain outbound BL and zero predicated outbound BLs.
/// Compute floor = -60 - lower_margin with word wrapping; multiply the
/// signed low halfwords of (12 - floor - upper_margin) and level, shift
/// arithmetically by eight, add floor and calibration byte at 0x089d0ef5.
/// Wrap to signed byte BEFORE clamping to [-60,12], encode in seven bits,
/// and write duplicate gain bytes starting at first_reg. Return zero.
/// Deliberate deviations: volatile calibration read; the unported writer
/// at 0x080da644 uses an indirect BLX on target and a host recording seam.
/// second_reg is unused in the original, which writes consecutive registers.
///
/// # Safety
/// Requires serialized codec state access and callable stock codec writer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codec_level_scale(
    first_reg: u32, _second_reg: u32, level: u32, upper_margin: u32, lower_margin: u32,
) -> u32 {
    let calibration = ptr::read_volatile(level_state().add(1));
    let gain = encoded_gain(level, upper_margin, lower_margin, calibration);
    #[cfg(target_os = "none")]
    let write: WriteGain = core::mem::transmute(0x080d_a644usize);
    #[cfg(not(target_os = "none"))]
    let write = ptr::read_volatile(ptr::addr_of!(HOST_WRITE_GAIN));
    write(first_reg, gain);
    0
}

/// Updates the cached codec level and reapplies changed or forced values.
///
/// # Safety
/// Requires serialized access to firmware codec state and the stock scaler.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codec_cached_level_set(level: u32) -> u32 {
    let state = level_state();
    if ptr::read_volatile(state.add(2)) as u32 == level
        && ptr::read_volatile(state) == 0
    {
        return 0;
    }
    ptr::write_volatile(state.add(2), level as u8);
    codec_level_scale(0x1a, 0x1b, level, 9, 7)
}

/// Cached auxiliary codec level update, `FUN_080ca12c` at `0x080ca12c`.
///
/// True extent: 72 bytes, [0x080ca12c,0x080ca174), comprising 68
/// executable bytes and the literal 0x089d0ef4. Raw aligned A32 decoding
/// verifies two plain inbound BLs (0x080b2874, 0x080ce674), no predicated
/// inbound BLs, and one plain outbound BL (0x080ca168), no predicated BLs.
/// Compare the full level word with byte +3; skip only if equal and refresh
/// byte +0 is zero. Otherwise store the low byte before calling the Rust
/// scaler with registers 0x1c/0x1d, the full level, and margins 11/0.
/// Both paths return zero, correcting Ghidra's void signature.
/// Deliberate deviations: volatile cache access and host storage/writer seam.
///
/// # Safety
/// Requires serialized access to firmware codec state and the stock scaler.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codec_cached_aux_level_set(level: u32) -> u32 {
    let state = level_state();
    if ptr::read_volatile(state.add(3)) as u32 == level
        && ptr::read_volatile(state) == 0
    {
        return 0;
    }
    ptr::write_volatile(state.add(3), level as u8);
    codec_level_scale(0x1c, 0x1d, level, 11, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static APPLIED: AtomicU32 = AtomicU32::new(0);
    static LAST_LEVEL: AtomicU32 = AtomicU32::new(0);
    static CACHE_OFFSET: AtomicU32 = AtomicU32::new(2);

    unsafe extern "C" fn observe_apply(first: u32, gain: u32) -> u32 {
        let offset = CACHE_OFFSET.load(Ordering::Relaxed) as usize;
        assert_eq!(first, if offset == 2 { 0x1a } else { 0x1c });
        let level = LAST_LEVEL.load(Ordering::Relaxed);
        assert_eq!(ptr::read_volatile(level_state().add(offset)), level as u8);
        let (upper, lower) = if offset == 2 { (9, 7) } else { (11, 0) };
        assert_eq!(gain, encoded_gain(level, upper, lower, 0x5a));
        APPLIED.fetch_add(1, Ordering::Relaxed);
        0xdeadbeef
    }

    #[test]
    fn unchanged_changed_forced_and_wide_levels_follow_raw_comparison() {
        unsafe {
            HOST_WRITE_GAIN = observe_apply;
            for (offset, set) in [
                (2, codec_cached_level_set as unsafe extern "C" fn(u32) -> u32),
                (3, codec_cached_aux_level_set as unsafe extern "C" fn(u32) -> u32),
            ] {
            CACHE_OFFSET.store(offset as u32, Ordering::Relaxed);
            for refresh in [0, 1, 255] {
                for cached in [0, 1, 127, 255] {
                    for level in [0, 1, 127, 255, 256, 257, u32::MAX] {
                        HOST_CODEC_LEVEL_STATE = [refresh, 0x5a, 0xa5, 0xa5];
                        HOST_CODEC_LEVEL_STATE[offset] = cached;
                        APPLIED.store(0, Ordering::Relaxed);
                        LAST_LEVEL.store(level, Ordering::Relaxed);
                        assert_eq!(set(level), 0);
                        let applies = level != cached as u32 || refresh != 0;
                        assert_eq!(APPLIED.load(Ordering::Relaxed), applies as u32);
                        let state = ptr::read(ptr::addr_of!(HOST_CODEC_LEVEL_STATE));
                        let mut expected = [refresh, 0x5a, 0xa5, 0xa5];
                        expected[offset] = if applies { level as u8 } else { cached };
                        assert_eq!(state, expected);
                        if applies {
                            assert_eq!(LAST_LEVEL.load(Ordering::Relaxed), level);
                        }
                        // A wide input remains unequal to its cached low byte.
                        assert_eq!(set(level), 0);
                        let repeats = refresh != 0 || level > 255;
                        assert_eq!(APPLIED.load(Ordering::Relaxed), applies as u32 + repeats as u32);
                    }
                }
            }
            }
            HOST_WRITE_GAIN = missing_host_writer;
        }
    }

    #[test]
    fn signed_halfwords_byte_wrap_and_clamp_match_word_reference() {
        for level in [0, 1, 255, 256, 257, 0x7fff, 0x8000, 0xffff, 0x10000, u32::MAX] {
            for upper in [0, 9, 11, 72, 0x8000, u32::MAX] {
                for lower in [0, 7, 0x7fff, 0x8000, u32::MAX] {
                    for calibration in [0, 1, 127, 128, 255] {
                        let floor = (-60i64 - lower as i64).rem_euclid(1i64 << 32);
                        let span = (12 - floor - upper as i64).rem_euclid(65536);
                        let span = if span >= 32768 { span - 65536 } else { span };
                        let input = (level & 65535) as i64;
                        let input = if input >= 32768 { input - 65536 } else { input };
                        let byte = (floor + (span * input).div_euclid(256)
                            + calibration as i64).rem_euclid(256);
                        let signed = if byte >= 128 { byte - 256 } else { byte };
                        let expected = signed.max(-60).min(12) as u32 & 127;
                        assert_eq!(encoded_gain(level, upper, lower, calibration), expected);
                    }
                }
            }
        }
        assert_eq!(encoded_gain(0, 11, 0, 0), 68);
        assert_eq!(encoded_gain(256, 11, 0, 0), 1);
        assert_eq!(encoded_gain(256, 9, 7, 0), 3);
        assert_eq!(encoded_gain(0, 11, 0, 188), 68); // +128 wraps to -128.
        assert_eq!(encoded_gain(0, 11, 0, 187), 12);
    }
}
