//! Queue-wait status normalization wrapper.
//!
//! - `queue_wait_status` — original: `FUN_080e430c` @ 0x080e430c
//!   (20 bytes, 0x080e430c..0x080e4320; 5 direct unconditional `bl`
//!   callers at 0x080af6a0, 0x081b08c4, 0x081bbc4c, 0x081bbc68, and
//!   0x081c0df4; no predicated callers). Its body has one unconditional
//!   `bl` to `queue_wait` @ 0x080b4adc and no predicated calls.
//!
//! Forwards the mailbox slot and timeout to [`super::queue_wait::queue_wait`].
//! Its `movs r0, r0; mvnne r0, #0` normalizes any nonzero wait verdict to
//! `-1`, leaving zero unchanged.
//!
//! # Deviation
//!
//! None. The Rust comparison has the same 0/-1 result mapping; the ported
//! `queue_wait` is called directly rather than through a new seam.

use crate::heap::queue_wait::queue_wait;
use crate::kernel::kobj::Mailbox;

/// queue_wait_status — original: `FUN_080e430c` @ 0x080e430c (20 bytes).
///
/// Returns zero when [`queue_wait`] succeeds and `-1` for every nonzero
/// queue-wait verdict.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn queue_wait_status(slot: *mut *mut Mailbox, timeout: u32) -> i32 {
    if queue_wait(slot, timeout) != 0 {
        -1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::kobj::{KobjHooks, DEFAULT_KOBJ_HOOKS, KOBJ_HOOKS};
    use core::ptr::addr_of_mut;

    unsafe extern "C" fn timeout_wait(_: u32, _: u32) -> u32 {
        5
    }

    #[test]
    fn successful_wait_stays_zero() {
        let mut mailbox = Mailbox { state: 1, id: 0x42 };
        let mut slot = core::ptr::addr_of_mut!(mailbox);
        unsafe {
            assert_eq!(queue_wait_status(core::ptr::addr_of_mut!(slot), 0x1234), 0);
        }
        assert_eq!(mailbox.state, 0, "queue_wait consumed one token");
    }

    #[test]
    fn timed_out_wait_becomes_minus_one() {
        let guard = crate::kernel::kobj::tests::HOOKS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            addr_of_mut!(KOBJ_HOOKS).write(KobjHooks {
                rom_waiter_wait: timeout_wait,
                ..DEFAULT_KOBJ_HOOKS
            });
            let mut mailbox = Mailbox { state: 0, id: 0x42 };
            let mut slot = core::ptr::addr_of_mut!(mailbox);
            assert_eq!(queue_wait_status(core::ptr::addr_of_mut!(slot), 0), -1);
            assert_eq!(mailbox.state, 0, "timed-out wait undoes its decrement");
            addr_of_mut!(KOBJ_HOOKS).write(DEFAULT_KOBJ_HOOKS);
        }
        drop(guard);
    }
}
