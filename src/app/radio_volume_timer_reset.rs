//! Radio volume timer reset — FUN_0811add4 @ 0x0811add4.
//!
//! Raw extent [0x0811add4, 0x0811ae00): 40 bytes (36 code, 4 literal).
//! The next real function is `bx lr` at 0x0811ae00. Full aligned raw ARM
//! scan verifies two inbound BLs: plain BL at 0x0811ab38 and BLNE at
//! 0x0811a6ac. The body has two plain BLs and a tail B to timer_restart.
//!
//! Stop the radio controller's timer at +0xb0, set its delay to 3000 ms,
//! and restart it. Reload the pointer before every helper. Callers handle
//! volume changes and the volume wheel (SwitchLayout_RadioVolume).
//! Ghidra incorrectly folds the tail callee and its dependencies into this
//! function. Deliberate deviations: Rust expresses the final tail B as a
//! return-position call; existing timer ports may inline. Volatile u32
//! pointer loads preserve reloads and target layout on 64-bit hosts. The
//! callers discard the timer helper's residual r0, so the signature is void.

use crate::drivers::timer::{timer_stop, timer_start_after, timer_restart};

#[inline(always)]
unsafe fn volume_timer(controller: *mut u8) -> *mut u8 {
    controller.add(0xb0).cast::<u32>().read_volatile() as usize as *mut u8
}

/// # Safety
/// `controller` must be aligned and readable through +0xb4. Each +0xb0
/// pointer loaded must designate a valid non-null timer object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn radio_volume_timer_reset(controller: *mut u8) {
    timer_stop(volume_timer(controller));
    timer_start_after(volume_timer(controller), 3000);
    timer_restart(volume_timer(controller));
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::timer::{TimerOps, TIMER_OPS, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture, TIMER_OPS_TEST_LOCK};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::RADIO_VOLUME_TIMER_RESET, 0x1000).map(|p| p as usize)
    });
    static mut OWNER: *mut u8 = core::ptr::null_mut();
    static mut REPLACEMENT: *mut u8 = core::ptr::null_mut();
    static mut SWAP_AT: u32 = 0;
    static mut TRACES: u32 = 0;
    static mut ARMED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn trace(_timer: *mut u8) {
        TRACES += 1;
        if TRACES == SWAP_AT {
            OWNER.add(0xb0).cast::<u32>().write(REPLACEMENT as u32);
        }
    }
    unsafe extern "C" fn arm(timer: *mut u8) { ARMED = timer; }
    struct Restore(TimerOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { addr_of_mut!(TIMER_OPS).write_volatile(self.0) }; }
    }

    #[test]
    fn resets_stopped_and_running_timers_and_honors_both_reloads() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("app::radio_volume_timer_reset"));
            return;
        };
        unsafe {
            let saved = addr_of!(TIMER_OPS).read_volatile();
            let _restore = Restore(saved);
            let mut ops = saved;
            ops.trace_assert = trace;
            ops.arm_timer = arm;
            addr_of_mut!(TIMER_OPS).write_volatile(ops);
            OWNER = base as *mut u8;
            let first = OWNER.add(0x100);
            REPLACEMENT = OWNER.add(0x200);
            for state in [TIMER_STATE_STOPPED, TIMER_STATE_RUNNING] {
                for swap_at in [0, 1, 2] {
                    OWNER.write_bytes(0, 0x1000);
                    OWNER.add(0xb0).cast::<u32>().write(first as u32);
                    first.add(4).cast::<u32>().write(17);
                    first.add(0x20).cast::<u32>().write(state);
                    REPLACEMENT.add(4).cast::<u32>().write(29);
                    SWAP_AT = swap_at;
                    TRACES = 0;
                    ARMED = core::ptr::null_mut();
                    radio_volume_timer_reset(OWNER);
                    let programmed = if swap_at == 1 { REPLACEMENT } else { first };
                    let restarted = if swap_at == 0 { first } else { REPLACEMENT };
                    assert_eq!(programmed.add(4).cast::<u32>().read(), 3000);
                    assert_eq!(restarted.add(0x20).cast::<u32>().read(), TIMER_STATE_RUNNING);
                    assert_eq!(addr_of!(ARMED).read(), restarted);
                    if swap_at != 0 {
                        assert_eq!(first.add(0x20).cast::<u32>().read(), TIMER_STATE_STOPPED);
                    }
                    if swap_at == 1 { assert_eq!(first.add(4).cast::<u32>().read(), 17); }
                    if swap_at == 2 { assert_eq!(REPLACEMENT.add(4).cast::<u32>().read(), 29); }
                }
            }
        }
    }
}
