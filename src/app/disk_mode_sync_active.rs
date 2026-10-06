//! Disk-mode sync activity getter — FUN_081594e4 @ 0x081594e4.
//! True extent: 40 bytes, ending at the next prologue at 0x0815950c.
//! Raw A32 words verify two incoming plain BLs (0x08159360, 0x08159398),
//! zero incoming predicated BLs, one outgoing plain BL, and no predicated BLs.
//! Read the clock, subtract the stored timestamp modulo 2^32, clear the
//! activity byte when the unsigned difference is >= 4, then return that byte.
//! The ported drivers::timer::sync_clock reads the microsecond timer and
//! divides by 1000 twice; host tests can substitute the clock.
//! Deliberate deviations: none in behavior; opaque prefix words retain the
//! target layout without introducing host-width pointers.

/// Only the prefix touched by the getter is modeled.
#[repr(C)]
pub struct DiskModeSyncState {
    pub opaque: [u32; 7],
    pub active: u8,
    pub padding: [u8; 3],
    pub timestamp: u32,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn sync_clock() -> u32 {
    crate::drivers::timer::sync_clock()
}

#[cfg(not(target_os = "none"))]
pub static mut DISK_MODE_SYNC_CLOCK: unsafe extern "C" fn() -> u32 = crate::drivers::timer::sync_clock;


#[cfg(not(target_os = "none"))]
unsafe fn sync_clock() -> u32 {
    (core::ptr::addr_of!(DISK_MODE_SYNC_CLOCK).read_volatile())()
}

/// Return the stored activity byte, expiring it after four clock units.
///
/// # Safety
/// `state` must be aligned, readable through +0x23, and writable at +0x1c.
/// Host clock installation and calls must be serialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn disk_mode_sync_active(state: *mut DiskModeSyncState) -> u8 {
    let now = sync_clock();
    if now.wrapping_sub((*state).timestamp) >= 4 {
        (*state).active = 0;
    }
    (*state).active
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    static NOW: AtomicU32 = AtomicU32::new(0);
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe extern "C" fn clock() -> u32 { NOW.load(Ordering::Relaxed) }

    #[test]
    fn expiry_boundary_wraparound_and_nonboolean_activity() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = DISK_MODE_SYNC_CLOCK;
            DISK_MODE_SYNC_CLOCK = clock;
            for timestamp in [0u32, 10, 0x8000_0000, u32::MAX - 1, u32::MAX] {
                for delta in [0u32, 1, 3, 4, 5, 0x8000_0000, u32::MAX] {
                    for active in [0u8, 1, 0x80, 0xff] {
                        let mut state = DiskModeSyncState {
                            opaque: [0xdead_beef; 7], active, padding: [0xa5; 3], timestamp,
                        };
                        assert_eq!(core::ptr::addr_of!(state.active) as usize - &state as *const _ as usize, 0x1c);
                        assert_eq!(core::ptr::addr_of!(state.timestamp) as usize - &state as *const _ as usize, 0x20);
                        NOW.store(timestamp.wrapping_add(delta), Ordering::Relaxed);
                        let expected = if delta < 4 { active } else { 0 };
                        assert_eq!(disk_mode_sync_active(&mut state), expected);
                        assert_eq!(state.active, expected);
                        assert_eq!(state.timestamp, timestamp);
                        assert_eq!(state.opaque, [0xdead_beef; 7]);
                        assert_eq!(state.padding, [0xa5; 3]);
                        NOW.store(timestamp, Ordering::Relaxed);
                        assert_eq!(disk_mode_sync_active(&mut state), expected, "expiry stays cleared");
                    }
                }
            }
            DISK_MODE_SYNC_CLOCK = saved;
        }
    }
}
