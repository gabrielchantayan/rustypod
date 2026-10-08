//! Optional owner timer stop, retailOS `FUN_081325d0` @ **0x081325d0**.
//!
//! True extent: 16 bytes (`0x081325d0..0x081325e0`); the next function
//! begins `push {r4,r5,r6,lr}`. Raw words: e5900080 e3500000 1affe834
//! e12fff1e. Whole-image A32 decoding finds two inbound plain BL calls
//! (0x08132ca8, 0x08134000), zero predicated BL calls, and no inbound
//! tail branches. The body has zero BL calls and one conditional tail B
//! to the already-ported `timer_stop` @ 0x0812c6b0.
//!
//! Load the four-byte timer pointer at owner +0x80, stop it if non-NULL,
//! otherwise return. Callers ignore r0; this is a void operation. Ghidra
//! incorrectly incorporates the tail callee into this wrapper. The owner
//! class identity is not established. Deliberate deviation: Rust expresses
//! the conditional tail branch as a return-position call. No new seams.

use crate::drivers::timer::timer_stop;

/// # Safety
/// `owner` must be aligned and readable through +0x84. Its nonzero +0x80
/// target-width pointer must designate a valid timer accepted by `timer_stop`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owner_timer_stop(owner: *mut u8) {
    let timer = unsafe { owner.add(0x80).cast::<u32>().read() } as usize as *mut u8;
    if !timer.is_null() {
        unsafe { timer_stop(timer) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::timer::{TIMER_OPS, TIMER_STATE_EXPIRED, TIMER_STATE_RUNNING, TIMER_STATE_STOPPED};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, TIMER_OPS_TEST_LOCK};
    use core::ptr::{addr_of, addr_of_mut};

    unsafe extern "C" fn trace(_timer: *mut u8) {}
    unsafe extern "C" fn cancel(handle: usize, callback: usize, timer: *mut u8) -> u32 {
        assert_eq!(handle, 0x1234);
        assert_eq!(callback, addr_of!(crate::drivers::timer::TIMER_EXPIRY_CALLBACK).read_volatile());
        assert_eq!(timer.add(0x20).cast::<u32>().read(), TIMER_STATE_EXPIRED);
        timer.add(0x24).cast::<u32>().write(0xfeed);
        1
    }

    #[test]
    fn null_timer_leaves_owner_untouched() {
        let mut owner = [0xa5a5_a5a5u32; 34];
        owner[32] = 0;
        let before = owner;
        unsafe { owner_timer_stop(owner.as_mut_ptr().cast()) };
        assert_eq!(owner, before);
    }

    #[test]
    fn stops_running_and_expired_timers_without_changing_owner() {
        let _lock = TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(owner) = try_map_u32_slab(hints::OWNER_TIMER_STOP, 0x400) else {
            assert!(note_missing_u32_fixture("app/owner_timer_stop"));
            return;
        };
        unsafe {
            let saved = addr_of!(TIMER_OPS).read_volatile();
            let mut ops = saved;
            ops.trace_assert = trace;
            ops.cancel_callback = cancel;
            addr_of_mut!(TIMER_OPS).write_volatile(ops);
            for state in [TIMER_STATE_RUNNING, TIMER_STATE_EXPIRED, TIMER_STATE_STOPPED] {
                owner.write_bytes(0xa5, 0x84);
                let timer = owner.add(0x200);
                timer.write_bytes(0, 0x2c);
                owner.add(0x80).cast::<u32>().write(timer as usize as u32);
                timer.add(0x20).cast::<u32>().write(state);
                timer.add(0x28).cast::<u32>().write(0x1234);
                let before = core::slice::from_raw_parts(owner.cast::<u32>(), 33).to_vec();
                owner_timer_stop(owner);
                assert_eq!(timer.add(0x20).cast::<u32>().read(), TIMER_STATE_STOPPED);
                assert_eq!(timer.add(0x24).cast::<u32>().read(), if state == TIMER_STATE_EXPIRED { 0xfeed } else { 0 });
                assert_eq!(core::slice::from_raw_parts(owner.cast::<u32>(), 33), before);
            }
            addr_of_mut!(TIMER_OPS).write_volatile(saved);
        }
    }
}
