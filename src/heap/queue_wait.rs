//! Port of the mailbox queue-get wait wrapper of the block-manager
//! client machinery — the leaf the pool base's fill loop
//! (heap/block_deque.rs) blocks on when the client is short of
//! headroom, and that half a dozen kernel/USB-era callers share:
//!
//! - `queue_wait` — original: `FUN_080b4adc` @ 0x080b4adc (44 bytes; 9
//!   `bl` call sites, binary-verified: 0x080e2ee4, 0x080e4310,
//!   0x0813b1a8, 0x0814b9f0, 0x08160cd8, 0x081effa4, 0x08214068
//!   (`block_deque_fill`), 0x0822356c, 0x08223684). Dereferences the
//!   caller's mailbox slot once (`ldr r0, [r0]`) and waits on the block
//!   as a counting semaphore — `csem_wait` @ 0x08056904
//!   (kernel/csem.rs, real port; the 8-byte mailbox block and
//!   `CountingSem` share the state+id layout) — with the timeout
//!   arriving untouched in r1 (Ghidra's one-parameter decompile is the
//!   ABI telling the truth: r1 passes straight through). The verdict is
//!   then remapped: acquired (0) stays 0, timeout (1) becomes 3, and
//!   any other code folds to 0 (`cmp #0 / bne` past the zero return,
//!   then `cmp #1 / bne` back to it, else `mov r0, #3`). The other
//!   codes are unreachable from the ported `csem_wait`, which only ever
//!   returns 0/1; the fold is kept anyway because it is what the
//!   original's branch structure does. Callers test for exactly 3
//!   (`cmp r0, #0x3` at 0x0813b1ac/0x0814b9f4), map nonzero to -1
//!   (0x080e2ee8/0x080e4314), or discard the result (the fill loop).
//!
//! The port is the shipped default of `POOL_BASE_OPS.queue_wait`
//! (heap/block_deque.rs), replacing the no-op stub — with the stock
//! kernel hooks an empty mailbox times out, which is the verdict the
//! stub faked, so the wiring changes nothing for the result-discarding
//! fill loop.
//!
//! # Deviation
//!
//! The original's `bl` @ 0x080b4ae4 to `csem_wait` is kept as an
//! indirect call through [`QUEUE_WAIT_SEM`] (house ops-slot pattern):
//! a direct call lets LLVM inline the whole 88-byte semaphore into
//! this 44-byte wrapper, erasing the structure match.py verifies.
//! The slot defaults to the real port and is `blx` in place of `bl` —
//! the accepted deviation throughout the heap cluster.

use crate::kernel::csem::{csem_wait, CountingSem};
use crate::kernel::kobj::Mailbox;

/// The wrapper's timeout verdict (original: `mov r0, #0x3`) — the value
/// every waiting caller's `cmp r0, #0x3` tests for.
pub const QUEUE_WAIT_TIMEOUT: u32 = 3;

/// The `csem_wait` boundary (see the module-header deviation). Default:
/// the real port @ 0x08056904 (kernel/csem.rs); host tests swap in
/// recorders and restore the default.
pub static mut QUEUE_WAIT_SEM: unsafe extern "C" fn(csem: *mut CountingSem, timeout: u32) -> u32 =
    csem_wait;

/// Reads the wait slot (volatile — same rationale as every dispatch
/// table: a build in which nothing swaps it must not constant-fold the
/// default in, or the inlining this slot exists to prevent comes back).
#[inline(always)]
fn sem_wait() -> unsafe extern "C" fn(csem: *mut CountingSem, timeout: u32) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(QUEUE_WAIT_SEM)) }
}

/// queue_wait — original: `FUN_080b4adc` @ 0x080b4adc (44 bytes).
///
/// Waits on the mailbox installed in `slot` for up to `timeout` ticks.
/// Returns 0 when the wait acquired (and for any non-timeout verdict,
/// faithfully) or [`QUEUE_WAIT_TIMEOUT`] when it expired.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queue_wait(slot: *mut *mut Mailbox, timeout: u32) -> u32 {
    let mailbox = slot.read();
    let rc = (sem_wait())(mailbox as *mut CountingSem, timeout);
    if rc == 1 {
        QUEUE_WAIT_TIMEOUT
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::kobj::{KobjHooks, DEFAULT_KOBJ_HOOKS, KOBJ_HOOKS};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the QUEUE_WAIT_SEM swap across this module's tests.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Recorded ROM sleeps: (waiter id, ticks) pairs.
    static mut SLEEP_LOG: Vec<(u32, u32)> = Vec::new();
    /// Return code the mock ROM sleep hands back.
    static mut SLEEP_RC: u32 = 0;
    /// Verdicts the mock csem_wait hands out, and the calls it saw.
    static mut SEM_RC: u32 = 0;
    static mut SEM_CALLS: Vec<(usize, u32)> = Vec::new();

    /// RTXC return code 5 — the ROM sleep expired (kobj.rs's
    /// RTXC_RC_TIMEOUT).
    const RC_TIMEOUT: u32 = 5;
    /// Any non-5 code — the sleeper was woken.
    const RC_WOKEN: u32 = 0;

    unsafe extern "C" fn mock_rom_sleep(id: u32, timeout: u32) -> u32 {
        (*addr_of_mut!(SLEEP_LOG)).push((id, timeout));
        *addr_of!(SLEEP_RC)
    }

    unsafe extern "C" fn mock_sem_wait(csem: *mut CountingSem, timeout: u32) -> u32 {
        (*addr_of_mut!(SEM_CALLS)).push((csem as usize, timeout));
        *addr_of!(SEM_RC)
    }

    /// Installs the recording ROM sleep and resets the wait slot to the
    /// real port. Takes this module's lock, then kobj's hook lock (the
    /// csem.rs order; no other module takes both, so no cycle).
    fn install(sleep_rc: u32) -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let hooks_guard = crate::kernel::kobj::tests::HOOKS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(SLEEP_LOG)).clear();
            *addr_of_mut!(SLEEP_RC) = sleep_rc;
            addr_of_mut!(QUEUE_WAIT_SEM).write(csem_wait);
            addr_of_mut!(KOBJ_HOOKS).write(KobjHooks {
                rom_waiter_wait: mock_rom_sleep,
                ..DEFAULT_KOBJ_HOOKS
            });
        }
        (guard, hooks_guard)
    }

    /// Restores the defaults; takes the guards by value so they drop
    /// last (house pattern, see kernel/csem.rs).
    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe {
            addr_of_mut!(QUEUE_WAIT_SEM).write(csem_wait);
            addr_of_mut!(KOBJ_HOOKS).write(DEFAULT_KOBJ_HOOKS);
        }
        drop(guards);
    }

    fn sleeps() -> Vec<(u32, u32)> {
        unsafe { (*addr_of!(SLEEP_LOG)).clone() }
    }

    /// A mailbox block in a caller-owned slot, like the pool base's
    /// +0x78 field after `mailbox_slot_create`.
    struct MailboxCell {
        slot: *mut Mailbox,
        block: Mailbox,
    }

    impl MailboxCell {
        fn new(state: u32, id: u32) -> Self {
            MailboxCell {
                slot: core::ptr::null_mut(),
                block: Mailbox { state, id },
            }
        }
        unsafe fn anchor(&mut self) -> *mut *mut Mailbox {
            self.slot = core::ptr::addr_of_mut!(self.block);
            core::ptr::addr_of_mut!(self.slot)
        }
    }

    // ---- verdict mapping (through the recording wait slot) --------------

    /// Drives one verdict through the mock wait and returns the
    /// wrapper's result.
    unsafe fn mapped(rc: u32) -> u32 {
        *addr_of_mut!(SEM_RC) = rc;
        (*addr_of_mut!(SEM_CALLS)).clear();
        addr_of_mut!(QUEUE_WAIT_SEM).write(mock_sem_wait);
        let mut cell = MailboxCell::new(0, 0x42);
        let block = core::ptr::addr_of_mut!(cell.block) as usize;
        let slot = cell.anchor();
        let ret = queue_wait(slot, 0x1234);
        assert_eq!(
            (*addr_of!(SEM_CALLS)).clone(),
            std::vec![(block, 0x1234)],
            "slot dereferenced once, mailbox and timeout forwarded"
        );
        ret
    }

    #[test]
    fn the_verdict_mapping_matches_the_originals_branch_structure() {
        let guards = install(RC_TIMEOUT);
        unsafe {
            assert_eq!(mapped(0), 0, "acquired stays 0");
            assert_eq!(mapped(1), QUEUE_WAIT_TIMEOUT, "timeout becomes 3");
            assert_eq!(mapped(2), 0, "any other code folds to 0");
            assert_eq!(mapped(u32::MAX), 0, "even all-ones");
        }
        restore(guards);
    }

    // ---- end-to-end through the real csem_wait --------------------------

    #[test]
    fn an_available_token_returns_zero_without_sleeping() {
        let guards = install(RC_TIMEOUT);
        unsafe {
            let mut cell = MailboxCell::new(1, 0x42);
            let slot = cell.anchor();
            assert_eq!(queue_wait(slot, 2000), 0);
            assert_eq!(cell.block.state, 0, "the token was taken");
            assert!(sleeps().is_empty(), "no ROM sleep on the fast path");
        }
        restore(guards);
    }

    #[test]
    fn an_expired_wait_returns_three_and_restores_the_count() {
        let guards = install(RC_TIMEOUT);
        unsafe {
            let mut cell = MailboxCell::new(0, 0x42);
            let slot = cell.anchor();
            assert_eq!(queue_wait(slot, 2000), QUEUE_WAIT_TIMEOUT);
            assert_eq!(
                sleeps(),
                std::vec![(0x42, 2000)],
                "the timeout passes through untouched in r1"
            );
            assert_eq!(cell.block.state, 0, "csem_wait undid the decrement");
        }
        restore(guards);
    }

    #[test]
    fn a_woken_wait_returns_zero_and_keeps_the_decrement() {
        let guards = install(RC_WOKEN);
        unsafe {
            let mut cell = MailboxCell::new(0, 0x42);
            let slot = cell.anchor();
            assert_eq!(queue_wait(slot, 2000), 0);
            assert_eq!(sleeps(), std::vec![(0x42, 2000)]);
            assert_eq!(
                cell.block.state, 0xffff_ffff,
                "the wakeup leaves the decrement in place (count -1)"
            );
        }
        restore(guards);
    }

    #[test]
    fn a_zero_timeout_is_clamped_to_one_tick_underneath() {
        let guards = install(RC_TIMEOUT);
        unsafe {
            let mut cell = MailboxCell::new(0, 0x42);
            let slot = cell.anchor();
            assert_eq!(queue_wait(slot, 0), QUEUE_WAIT_TIMEOUT);
            assert_eq!(
                sleeps(),
                std::vec![(0x42, 1)],
                "the csem_wait/waiter_wait clamp, seen through the wrapper"
            );
        }
        restore(guards);
    }
}
