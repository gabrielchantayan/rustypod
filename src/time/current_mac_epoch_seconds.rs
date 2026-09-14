//! Current Macintosh-epoch timestamp with UTC correction: `FUN_08054fc4` @
//! **0x08054fc4**.
//!
//! # Raw extent and call sites
//!
//! The executable extent is exactly **8 bytes**
//! (`0x08054fc4..0x08054fcc`): `mov r0,#1; b 0x08051d98`; the independently
//! linked next function begins with `push {r2,r3,r4,lr}` at `0x08054fcc`.
//! Decoding every immediate ARM B/BL word in `work/firmware/osos.dec` (load
//! base `0x08000000`) finds **6 unconditional `bl` callers** at
//! `0x0803c120`, `0x08050ef0`, `0x08057f90`, `0x0805d9d8`, `0x0806c8c0`, and
//! `0x0806caac`; there are no predicated `bl` or direct `b` tail callers.
//!
//! # Algorithm
//!
//! The tail target obtains the current normalized calendar record and converts
//! it to signed Macintosh-epoch seconds with its nonzero UTC-offset flag. The
//! two operations are already ported as
//! [`super::current_datetime::current_datetime_to_normalized_record`] and
//! [`super::datetime_to_mac_epoch::datetime_to_mac_epoch_seconds`].
//!
//! # Deliberate deviations
//!
//! The unported tail target `0x08051d98` is represented inline by its exact
//! two already-ported operations, rather than a fixed-address call. Its raw
//! stack record contains caller-saved register residue; this port zeroes that
//! record because the downstream conversion reads only the calendar fields
//! populated by the current-calendar query.

use super::datetime::DateTime;

#[cfg(test)]
type CurrentMacEpochSecondsFn = unsafe extern "C" fn(i32) -> i32;

#[cfg(test)]
unsafe extern "C" fn missing_current_mac_epoch_seconds(_apply_utc_offset: i32) -> i32 {
    panic!("install a current-Mac-epoch-seconds handler before testing current_mac_epoch_seconds_with_utc_offset")
}

/// Tests replace the complete already-ported composition at this boundary;
/// firmware builds call both Rust ports directly.
#[cfg(test)]
static mut CURRENT_MAC_EPOCH_SECONDS: CurrentMacEpochSecondsFn = missing_current_mac_epoch_seconds;

#[inline(always)]
unsafe fn current_mac_epoch_seconds(apply_utc_offset: i32) -> i32 {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(CURRENT_MAC_EPOCH_SECONDS))(apply_utc_offset)
    }

    #[cfg(not(test))]
    {
        let mut datetime: DateTime = core::mem::zeroed();
        super::current_datetime::current_datetime_to_normalized_record(&mut datetime);
        super::datetime_to_mac_epoch::datetime_to_mac_epoch_seconds(&mut datetime, apply_utc_offset)
    }
}

/// current_mac_epoch_seconds_with_utc_offset — original: `FUN_08054fc4` @
/// `0x08054fc4` (**8 bytes, 6 unconditional `bl` callers; no predicated `bl`
/// or direct `b` tail callers**).
///
/// Returns the current signed 32-bit Macintosh-epoch timestamp after applying
/// the current UTC and daylight-saving offsets. All arithmetic and offset
/// validity behavior belongs to the already-ported conversion routine.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.current_mac_epoch_seconds_with_utc_offset")]
pub unsafe extern "C" fn current_mac_epoch_seconds_with_utc_offset() -> i32 {
    current_mac_epoch_seconds(1)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: AtomicU32 = AtomicU32::new(0);
    static OFFSET_FLAG: AtomicI32 = AtomicI32::new(0);
    static RESULT: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn recording_current_mac_epoch_seconds(apply_utc_offset: i32) -> i32 {
        CALLS.fetch_add(1, Ordering::Relaxed);
        OFFSET_FLAG.store(apply_utc_offset, Ordering::Relaxed);
        RESULT.load(Ordering::Relaxed)
    }

    struct Mock {
        previous: CurrentMacEpochSecondsFn,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(CURRENT_MAC_EPOCH_SECONDS), self.previous);
            }
        }
    }

    fn install(result: i32) -> Mock {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { ptr::read_volatile(ptr::addr_of!(CURRENT_MAC_EPOCH_SECONDS)) };
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(CURRENT_MAC_EPOCH_SECONDS),
                recording_current_mac_epoch_seconds,
            );
        }
        CALLS.store(0, Ordering::Relaxed);
        OFFSET_FLAG.store(0, Ordering::Relaxed);
        RESULT.store(result, Ordering::Relaxed);
        Mock { previous, _lock: lock }
    }

    #[test]
    fn always_requests_utc_correction_and_preserves_negative_timestamp() {
        let _mock = install(-1_234_567_890);

        assert_eq!(unsafe { current_mac_epoch_seconds_with_utc_offset() }, -1_234_567_890);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(OFFSET_FLAG.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn preserves_wrapping_timestamp_bit_pattern() {
        let _mock = install(i32::MIN);

        assert_eq!(unsafe { current_mac_epoch_seconds_with_utc_offset() }, i32::MIN);
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(OFFSET_FLAG.load(Ordering::Relaxed), 1);
    }
}
