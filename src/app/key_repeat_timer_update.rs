//! Key-event repeat timer update.
//!
//! Original: FUN_0819ca5c @ 0x0819ca5c, true size 184 bytes:
//! 164 instruction bytes and 20 literal bytes, next function at 0x0819cb14.
//! Whole-image A32 decoding finds two inbound BL sites: one plain BL at
//! 0x0819cc94 and one BLEQ at 0x0812c50c. Body: five plain BLs, one BLNE,
//! and a tail B to mutex_unlock.
//!
//! Extract the key from event word +0x14 bits 16..23 before locking. On
//! 'kDwn', ignore keys 0x71..=0x77; otherwise trace the previous active
//! timer, set the active key, select the delay at state +0x0c or +0x1c
//! using the per-key byte table, set its delay and arm it. Any other event
//! clears the active key after tracing if its key matches, including zero.
//! Always unlock. Trace is not timer_stop: preserve the verified callee.
//!
//! Deviations: inline the raw-verified 0x0819c77c key-range predicate rather
//! than adding a second port or unported seam. Host globals are isolated
//! storage; timer and mutex operations reuse the existing implementations.

use crate::drivers::timer::{timer_arm, timer_set_delay, timer_trace_assert};
use crate::kernel::sync_mutex::{Mutex, mutex_lock, mutex_unlock};

const KEY_DOWN: u32 = 0x6b44_776e;

#[cfg(not(target_os = "none"))]
#[repr(align(4))]
struct HostGlobals {
    state: [u8; 32],
    timer: [u32; 11],
    alternate_delay: [u8; 256],
    mutex: Mutex,
}
#[cfg(not(target_os = "none"))]
static mut HOST: HostGlobals = HostGlobals {
    state: [0; 32], timer: [0; 11], alternate_delay: [0; 256],
    mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
};

#[inline(always)]
unsafe fn update(
    event: *const u32, state: *mut u8, timer: *mut u8, table: *const u8,
    trace: unsafe extern "C" fn(*mut u8),
    delay: unsafe extern "C" fn(*mut u8, u32),
    arm: unsafe extern "C" fn(*mut u8),
) {
    let key = ((event.add(5).read() >> 16) & 0xff) as u8;
    if event.read() == KEY_DOWN {
        if (0x71..=0x77).contains(&key) { return; }
        if state.add(2).read_volatile() != 0 { trace(timer); }
        state.add(2).write_volatile(key);
        let alternate = table.add(key as usize).read_volatile() != 0;
        let mut period = state.add(12).cast::<u32>().read_volatile();
        if alternate { period = state.add(28).cast::<u32>().read_volatile(); }
        delay(timer, period);
        arm(timer);
    } else if key == state.add(2).read_volatile() {
        trace(timer);
        state.add(2).write_volatile(0);
    }
}

/// # Safety
/// `event` provides six aligned readable words. Firmware globals and the
/// existing timer service must be initialized, as required by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn key_repeat_timer_update(event: *const u32) {
    // The packed key is captured before mutex_lock in the original.
    let packed_key = event.add(5).read();
    #[cfg(target_os = "none")]
    let (state, timer, table, mutex) = (
        0x089c_b29c as *mut u8, 0x08a7_79d0 as *mut u8,
        0x08a7_7a8f as *const u8, 0x089c_b2bc as *mut Mutex,
    );
    #[cfg(not(target_os = "none"))]
    let (state, timer, table, mutex) = (
        core::ptr::addr_of_mut!(HOST.state).cast::<u8>(),
        core::ptr::addr_of_mut!(HOST.timer).cast::<u8>(),
        core::ptr::addr_of!(HOST.alternate_delay).cast::<u8>(),
        core::ptr::addr_of_mut!(HOST.mutex),
    );
    mutex_lock(mutex);
    let captured = [event.read(), 0, 0, 0, 0, packed_key];
    update(captured.as_ptr(), state, timer, table, timer_trace_assert, timer_set_delay, timer_arm);
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn trace(timer: *mut u8) {
        let t = timer.cast::<u32>();
        t.add(2).write(t.add(2).read() + 1);
    }
    unsafe extern "C" fn delay(timer: *mut u8, period: u32) {
        timer.cast::<u32>().add(1).write(period);
    }
    unsafe extern "C" fn arm(timer: *mut u8) {
        timer.cast::<u32>().write(1);
    }

    #[test]
    fn all_key_codes_select_delay_and_preserve_excluded_keys() {
        for key in 0..=255u32 {
            for alternate in [0, 7] {
                let mut state = [0xa5a5_a5a5u32; 8];
                state[3] = 123; state[7] = u32::MAX;
                let mut timer = [0, 42, 0];
                let mut table = [0; 256]; table[key as usize] = alternate;
                let event = [KEY_DOWN, 0, 0, 0, 0, 0x8000_ffff | (key << 16)];
                unsafe { update(event.as_ptr(), state.as_mut_ptr().cast(), timer.as_mut_ptr().cast(), table.as_ptr(), trace, delay, arm); }
                if (0x71..=0x77).contains(&key) {
                    assert_eq!(state[0], 0xa5a5_a5a5); assert_eq!(timer, [0, 42, 0]);
                } else {
                    assert_eq!(state[0], 0xa500_a5a5 | (key << 16));
                    assert_eq!(timer, [1, if alternate == 0 { 123 } else { u32::MAX }, 1]);
                }
                assert_eq!(state[3], 123); assert_eq!(state[7], u32::MAX);
            }
        }
    }

    #[test]
    fn release_matches_active_key_even_when_zero_and_down_zero_does_not_trace() {
        for active in [0u32, 1, 0x71, 255] {
            for key in [0u32, 1, 0x71, 255] {
                let mut state = [0u32; 8]; state[0] = active << 16;
                let mut timer = [0, 42, 0];
                let event = [0xdead_beef, 0, 0, 0, 0, key << 16];
                unsafe { update(event.as_ptr(), state.as_mut_ptr().cast(), timer.as_mut_ptr().cast(), [0; 256].as_ptr(), trace, delay, arm); }
                assert_eq!(state[0], if key == active { 0 } else { active << 16 });
                assert_eq!(timer, [0, 42, u32::from(key == active)]);
            }
        }
        let mut state = [0u32; 8]; let mut timer = [0, 42, 0];
        unsafe { update([KEY_DOWN, 0, 0, 0, 0, 0].as_ptr(), state.as_mut_ptr().cast(), timer.as_mut_ptr().cast(), [0; 256].as_ptr(), trace, delay, arm); }
        assert_eq!(timer, [1, 0, 0]);
    }
}
