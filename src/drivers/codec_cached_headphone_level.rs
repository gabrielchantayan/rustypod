//! Cached headphone codec level update, `FUN_080d36e4` at `0x080d36e4`.
//!
//! True extent: 52 bytes, [0x080d36e4,0x080d3718): 48 executable bytes
//! and the state-address literal 0x089d0f04. The next function starts PUSH.
//! Raw whole-image decoding verifies two plain inbound BLs (0x080ad4a4,
//! 0x080cc284), no predicated inbound BLs, and no outbound BLs. One BNE
//! tail-calls the register-pair scaler at 0x0808f9c8 with registers 2/3.
//! Compare the full requested word to cached byte +2; skip only when equal
//! and refresh byte +0 is zero. Otherwise cache the low byte before scaling.
//! The stock scaler applies signed-low-halfword multiplication, unsigned
//! division, calibration byte +1, byte wrapping and gain clamping, then
//! writes codec registers 2/3. Ghidra incorrectly inlines that shared body
//! and reports 160 bytes. Deliberate deviations: volatile state access;
//! host-only storage and scaler seam, following codec_cached_level.rs.

use core::ptr;

type ScaleLevel = unsafe extern "C" fn(u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
static mut HOST_STATE: [u8; 4] = [0; 4];
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_scaler(_: u32, _: u32, _: u32) -> u32 {
    panic!("stock headphone level scaler requires a host implementation")
}
#[cfg(not(target_os = "none"))]
static mut HOST_SCALER: ScaleLevel = missing_scaler;

#[inline(always)]
fn level_state() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x089d_0f04 as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(HOST_STATE).cast() }
}

/// Requires serialized access to codec state and the stock level scaler.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn codec_cached_headphone_level_set(level: u32) -> u32 {
    let state = level_state();
    if ptr::read_volatile(state.add(2)) as u32 == level
        && ptr::read_volatile(state) == 0
    {
        return 0;
    }
    ptr::write_volatile(state.add(2), level as u8);
    #[cfg(target_os = "none")]
    let scale: ScaleLevel = core::mem::transmute(0x0808_f9c8usize);
    #[cfg(not(target_os = "none"))]
    let scale = ptr::read_volatile(ptr::addr_of!(HOST_SCALER));
    scale(2, 3, level)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static LEVEL: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn observe(_: u32, _: u32, level: u32) -> u32 {
        // The hardware sees the new cache before the update begins.
        assert_eq!(ptr::read_volatile(level_state().add(2)), level as u8);
        LEVEL.store(level, Ordering::Relaxed);
        CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }

    #[test]
    fn cache_suppression_refresh_and_full_word_comparison() {
        unsafe {
            HOST_SCALER = observe;
            for refresh in [0, 1, 255] {
                for cached in [0, 1, 127, 255] {
                    for level in [0, 1, 127, 255, 256, 257, 0xffff8000, u32::MAX] {
                        HOST_STATE = [refresh, 0x5a, cached, 0xa5];
                        CALLS.store(0, Ordering::Relaxed);
                        let changed = level != cached as u32 || refresh != 0;
                        assert_eq!(codec_cached_headphone_level_set(level), 0);
                        assert_eq!(CALLS.load(Ordering::Relaxed), changed as u32);
                        assert_eq!(ptr::read(ptr::addr_of!(HOST_STATE)),
                            [refresh, 0x5a, if changed { level as u8 } else { cached }, 0xa5]);
                        if changed { assert_eq!(LEVEL.load(Ordering::Relaxed), level); }
                        assert_eq!(codec_cached_headphone_level_set(level), 0);
                        assert_eq!(CALLS.load(Ordering::Relaxed),
                            changed as u32 + (refresh != 0 || level > 255) as u32);
                    }
                }
            }
            HOST_SCALER = missing_scaler;
        }
    }
}
