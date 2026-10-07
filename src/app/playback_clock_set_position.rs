//! Playback clock baseline setter.
//!
//! `FUN_0814d0d0` @ `0x0814d0d0`, true extent
//! `[0x0814d0d0, 0x0814d100)` (48 bytes, no literals). Raw aligned
//! ARM decoding finds two incoming plain BLs (0x080f5a08, 0x080f5a28),
//! zero predicated BLs; the body has three plain BLs, no predicated BLs,
//! and a tail branch to mutex_unlock. The next function starts with PUSH.
//!
//! Lock the embedded mutex, replace the position baseline, sample Timer E,
//! divide its unsigned counter by 1000, replace the baseline timestamp,
//! then unlock. The companion getter adds elapsed milliseconds to position.
//! No semantic deviations. A repr(C) embedded mutex keeps host pointer-width
//! changes out of field addressing; volatile stores preserve update order.

use crate::drivers::timer::timer_e_counter_read;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};
use crate::runtime::rt_div::__rt_udiv;

#[repr(C)]
pub struct PlaybackClock {
    pub mutex: Mutex,
    pub position: u32,
    pub timestamp_ms: u32,
    pub previous_timestamp_ms: u32,
    pub mode: u32,
}

/// Replace the clock's position and time origin under its embedded mutex.
///
/// # Safety
/// `clock` must point to a live, writable PlaybackClock with a valid mutex.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn playback_clock_set_position(clock: *mut PlaybackClock, position: u32) {
    let mutex = core::ptr::addr_of_mut!((*clock).mutex);
    mutex_lock(mutex);
    core::ptr::addr_of_mut!((*clock).position).write_volatile(position);
    let now = __rt_udiv(timer_e_counter_read(), 1000);
    core::ptr::addr_of_mut!((*clock).timestamp_ms).write_volatile(now);
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_baseline_with_truncated_unsigned_time_without_changing_getter_state() {
        for counter in [0, 999, 1000, 1001, 1_234_999, 0x8000_0000, u32::MAX] {
            let _timer = crate::drivers::timer::configure_usec_timer_for_test(counter, 0);
            let mut clock = PlaybackClock {
                mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0xa5a5_1234 },
                position: 17,
                timestamp_ms: u32::MAX,
                previous_timestamp_ms: 0x1234_5678,
                mode: 2,
            };
            for position in [0, 0x8000_0000, u32::MAX, 42] {
                unsafe { playback_clock_set_position(&mut clock, position) };
                assert_eq!(clock.position, position);
                assert_eq!(clock.timestamp_ms, counter / 1000);
                assert_eq!(clock.previous_timestamp_ms, 0x1234_5678);
                assert_eq!(clock.mode, 2);
                assert!(clock.mutex.sem_cell.is_null());
                assert_eq!(clock.mutex.unused, 0xa5a5_1234);
            }
        }
    }
}
