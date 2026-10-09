//! Cached codec register-pair level update.
//!
//! Original `FUN_080d5244` at `0x080d5244`: true extent 72 bytes through
//! `0x080d528c` (68 executable bytes and literal `0x089d0ef4`). Raw aligned
//! A32 decoding verifies two inbound plain BLs, zero predicated inbound BLs,
//! and one outbound plain BL, zero predicated outbound BLs.
//!
//! Compare the full input word against cached byte +2. Skip an unchanged
//! value only when refresh byte +0 is zero; otherwise cache the low byte
//! before calling the stock level scaler at `0x08093a9c` with register pair
//! 0x1a/0x1b, the full level word, upper margin 9 and lower margin 7.
//! Both stock paths return zero. The scaler writes duplicate seven-bit
//! gain bytes to the codec at I2C address 0x4a via `0x080da644`.
//!
//! Deliberate deviations: volatile cache access preserves firmware-visible
//! ordering; host builds replace firmware storage and the unported scaler
//! with a test seam. No scaler algorithm is ported here.

use core::ptr;

type ScaleLevel = unsafe extern "C" fn(u32, u32, u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
static mut HOST_CODEC_LEVEL_STATE: [u8; 4] = [0; 4];

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_host_scaler(_: u32, _: u32, _: u32, _: u32, _: u32) -> u32 {
    panic!("stock codec level scaler requires a host implementation")
}

#[cfg(not(target_os = "none"))]
static mut HOST_SCALE_LEVEL: ScaleLevel = missing_host_scaler;

#[inline(always)]
fn level_state() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x089d_0ef4 as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_CODEC_LEVEL_STATE).cast::<u8>() }
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
    #[cfg(target_os = "none")]
    let scale: ScaleLevel = core::mem::transmute(0x0809_3a9cusize);
    #[cfg(not(target_os = "none"))]
    let scale = ptr::read_volatile(ptr::addr_of!(HOST_SCALE_LEVEL));
    scale(0x1a, 0x1b, level, 9, 7)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static APPLIED: AtomicU32 = AtomicU32::new(0);
    static LAST_LEVEL: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn observe_apply(first: u32, second: u32, level: u32, upper: u32, lower: u32) -> u32 {
        assert_eq!((first, second, upper, lower), (0x1a, 0x1b, 9, 7));
        assert_eq!(ptr::read_volatile(level_state().add(2)), level as u8);
        LAST_LEVEL.store(level, Ordering::Relaxed);
        APPLIED.fetch_add(1, Ordering::Relaxed);
        0
    }

    #[test]
    fn unchanged_changed_forced_and_wide_levels_follow_raw_comparison() {
        unsafe {
            HOST_SCALE_LEVEL = observe_apply;
            for refresh in [0, 1, 255] {
                for cached in [0, 1, 127, 255] {
                    for level in [0, 1, 127, 255, 256, 257, u32::MAX] {
                        HOST_CODEC_LEVEL_STATE = [refresh, 0x5a, cached, 0xa5];
                        APPLIED.store(0, Ordering::Relaxed);
                        assert_eq!(codec_cached_level_set(level), 0);
                        let applies = level != cached as u32 || refresh != 0;
                        assert_eq!(APPLIED.load(Ordering::Relaxed), applies as u32);
                        let state = ptr::read(ptr::addr_of!(HOST_CODEC_LEVEL_STATE));
                        assert_eq!(state,
                            [refresh, 0x5a, if applies { level as u8 } else { cached }, 0xa5]);
                        if applies {
                            assert_eq!(LAST_LEVEL.load(Ordering::Relaxed), level);
                        }
                        // A wide input remains unequal to its cached low byte.
                        assert_eq!(codec_cached_level_set(level), 0);
                        let repeats = refresh != 0 || level > 255;
                        assert_eq!(APPLIED.load(Ordering::Relaxed), applies as u32 + repeats as u32);
                    }
                }
            }
            HOST_SCALE_LEVEL = missing_host_scaler;
        }
    }
}
