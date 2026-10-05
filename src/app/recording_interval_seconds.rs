//! Recording interval — `FUN_081a41ac` @ **0x081a41ac**.
//!
//! True extent: **28 bytes**, 0x081a41ac..0x081a41c8: six A32
//! instructions (24 bytes) and the pointer literal at 0x081a41c4.
//! Independent whole-image raw decoding finds two inbound plain BLs
//! (0x081a2f30, 0x081a4bc4), zero predicated inbound BLs, and zero
//! outgoing BLs of either kind. The next function starts with PUSH.
//! Read the byte at 0x089caf73; return 120 when zero, otherwise 2.
//! Callers multiply this interval by 60 to obtain elapsed seconds.
//!
//! Deviations: explicitly carry the preserved r1 word in a u64 return,
//! rather than rely on incidental LLVM register allocation. The context
//! argument is ignored, as in retailOS. A volatile read observes mutable
//! global state; hosts substitute a byte for the firmware global. The
//! flag's broader meaning is unrecovered, so it is not named as a mode.

#[cfg(not(target_os = "none"))]
pub(crate) static mut HOST_RECORDING_INTERVAL_FLAG: u8 = 0;

#[inline(always)]
fn interval_flag() -> *const u8 {
    #[cfg(target_os = "none")]
    { 0x089c_af73usize as *const u8 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of!(HOST_RECORDING_INTERVAL_FLAG) }
}

/// Return the interval in r0 and preserve the caller's seconds word in r1.
///
/// # Safety
/// The firmware flag must be readable; host flag access must be serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn recording_interval_seconds(_context: *mut u8, seconds: u32) -> u64 {
    let interval = if interval_flag().read_volatile() == 0 { 120u32 } else { 2u32 };
    ((seconds as u64) << 32) | interval as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_flag_value_preserves_seconds_and_observes_transitions() {
        let _lock = super::super::voice_memo_duration::tests::LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        unsafe {
            let old = core::ptr::addr_of!(HOST_RECORDING_INTERVAL_FLAG).read();
            for flag in (0..=u8::MAX).chain(core::iter::once(0)) {
                core::ptr::addr_of_mut!(HOST_RECORDING_INTERVAL_FLAG).write_volatile(flag);
                for seconds in [0, 1, 0x8000_0000, u32::MAX] {
                    let result = recording_interval_seconds(core::ptr::null_mut(), seconds);
                    assert_eq!(result as u32, if flag == 0 { 120 } else { 2 });
                    assert_eq!((result >> 32) as u32, seconds);
                }
                assert_eq!(core::ptr::addr_of!(HOST_RECORDING_INTERVAL_FLAG).read(), flag);
            }
            core::ptr::addr_of_mut!(HOST_RECORDING_INTERVAL_FLAG).write(old);
        }
    }
}
