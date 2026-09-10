//! Port of the blocking kernel-gateway request helper @ 0x08048000 (100 bytes,
//! 64 `bl` call sites in osos 2.0.4) — the tag-0 member of the four-helper
//! request family @ 0x08047edc..0x0804805c (tags 3/2/4/0), sibling of
//! kernel/gateway_request.rs's gateway_request_timed. Like the rest of the
//! family it posts a 5-word request frame through the ported mode-1
//! mailbox-send gateway body (`mailbox_send_gateway_mode1`, thunk
//! 0x08037e18 -> ROM 0x2200418c) serialized by kernel semaphore 9
//! (`rom_sem_wait`/`rom_sem_signal`, thunks 0x08037e08 / 0x08037e10 ->
//! ROM 0x22003fd0 / 0x220042b4 — the ported veneer family in
//! kernel/task_lock.rs).
//!
//! Algorithm (verified against osos.asm @ 0x08048000..0x08048064): first call
//! the gateway-ready wait FUN_080c8304 (see GATEWAY_READY_WAIT below), then
//! build a 9-word stack frame — words 0..3 zeroed (the original's two
//! `stmia` pairs), tag byte 0 stored at word 4 (frame layout matches Ghidra's
//! {local_30..local_10}), word 5 = the payload argument, words 6 and 7
//! untouched padding, word 8 = the flag argument. Then, holding kernel
//! semaphore 9, call the mode-1 mailbox-send gateway body with (mailbox = 1,
//! message = &frame, priority = 5, semaphore = 6) and release the semaphore.
//! The body preserves the fourth argument as the RTXC request's semaphore
//! word. The payload/flag words sit immediately past the declared frame — the
//! ROM service reads them through the same pointer beyond the announced count.
//! Call-site survey (all 64 `bl` sites):
//! r0 (payload) is a small id (0x1, 0x8, 0x10, 0x23, 0x30, 0x33, 0x37
//! observed) or an object pointer; r1 (flag) is an immediate 0 or 1 at every
//! immediate site (a handful pass a register).
//!
//! Deviations from the original:
//! - The leading ready wait FUN_080c8304 is ported below as
//!   gateway_wait_ready, but the call still dispatches through the
//!   GATEWAY_READY_WAIT slot below, whose documented spin default stays
//!   installed until gateway_wait_ready (or the stock function) is wired
//!   in — the observable_set_observer dispatch-boundary precedent.
//! - The semaphore calls dispatch indirectly through task_lock::ROM_KERNEL
//!   instead of `bl` to the 8-byte thunk veneers; match.py diffs are
//!   structural, as with the rest of the family.
//! - The ported mode-1 mailbox-send body calls the existing
//!   message_dispatch_veneer seam rather than the original direct PC-relative
//!   `bl`; unlike the stale task_lock veneer, it preserves the raw `r3 = 6`
//!   as its fourth argument.
//! - The padding words 6 and 7 (sp+0x18/sp+0x1c in the original) are zeroed
//!   rather than left uninitialized; nothing declared reads them.
//! - The original leaves the semaphore-signal result in r0; no caller
//!   consumes it, so the port returns nothing.

use crate::kernel::mailbox_send_gateway_mode1::mailbox_send_gateway_mode1;
use crate::kernel::task;
use crate::kernel::task_lock;

/// Kernel semaphore serializing the whole request family (r0 = 9 at all
/// four helpers' wait/signal call sites).
const REQUEST_LOCK: usize = 9;

/// Tag byte identifying this helper's request flavor (frame word 4).
const REQUEST_TAG: usize = 0;

/// Mailbox passed to the mode-1 mailbox-send gateway body (`mov r0, #1`).
const GATEWAY_MAILBOX: u32 = 1;

/// Priority passed to the mode-1 mailbox-send gateway body (`mov r2, #5`).
const GATEWAY_PRIORITY: u32 = 5;

/// Semaphore passed to the mode-1 mailbox-send gateway body (`mov r3, #6`).
const GATEWAY_SEMAPHORE: u32 = 6;

/// Total stack words the original writes/addresses: the declared frame,
/// the payload word past it, two padding words, and the trailing flag.
const FRAME_SLOTS: usize = 9;

/// Dispatch slot for the gateway-ready wait FUN_080c8304 @ 0x080c8304
/// (36 bytes): spins calling FUN_081a5500 (the lazily-created gateway state
/// object) until its byte at +0x6a reads 1, sleeping one tick via thunk
/// 0x080e9eb0 (`b 0x080568e8`) between polls. Also called at the head of
/// the request helper @ 0x08048064. Ported below as gateway_wait_ready;
/// it rides this slot because its own state-getter callee is unported.
/// Default spins: the wait produces no value and its only effect is
/// blocking, and a request posted before the ROM gateway reports ready
/// would fail silently — hanging surfaces the missing install (the
/// task_lock.rs missing-stub philosophy).
pub static mut GATEWAY_READY_WAIT: unsafe extern "C" fn() = missing_gateway_ready_wait;

/// Default stub: without an installed ready-wait there is no way to know
/// the gateway is up — spin, so a missing install hangs loudly.
unsafe extern "C" fn missing_gateway_ready_wait() {
    loop {}
}

/// Reads the ready-wait slot (volatile, so LLVM cannot constant-fold the
/// default stub and inline its `loop {}` — the task_lock.rs hook!
/// rationale).
#[inline(always)]
fn ready_wait() -> unsafe extern "C" fn() {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GATEWAY_READY_WAIT)) }
}

/// Offset of the ready byte in the gateway state object (`ldrb r0,
/// [r0, #0x6a]`).
const READY_FLAG_OFFSET: usize = 0x6a;

/// Value the ready byte reads once the ROM gateway is up (`cmp r0, #0x1`).
const READY: u8 = 1;

/// Ticks slept between polls (`mov r0, #0x1` before the sleep thunk).
const POLL_SLEEP_TICKS: u32 = 1;

/// Dispatch slot for the gateway state getter FUN_081a5500 @ 0x081a5500
/// (gateway_wait_ready's poll callee): returns the lazily-created gateway
/// state object whose byte at +0x6a reports readiness. Not ported — the
/// lazy init allocates and is far from self-contained. Default hands back
/// a never-ready static: with no real getter there is no object, so the
/// wait spins loudly instead of dereferencing nothing (the missing-stub
/// philosophy, same as GATEWAY_READY_WAIT's default).
pub static mut GATEWAY_STATE: unsafe extern "C" fn() -> *mut u8 = missing_gateway_state;

/// Default stub: a static state object whose ready byte never reads 1.
unsafe extern "C" fn missing_gateway_state() -> *mut u8 {
    static mut NOT_READY: [u8; READY_FLAG_OFFSET + 1] = [0; READY_FLAG_OFFSET + 1];
    core::ptr::addr_of_mut!(NOT_READY) as *mut u8
}

/// Reads the state-getter slot (the ready_wait hook! rationale).
#[inline(always)]
fn gateway_state() -> unsafe extern "C" fn() -> *mut u8 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(GATEWAY_STATE)) }
}

/// gateway_wait_ready — original: FUN_080c8304 @ 0x080c8304 (36 bytes).
/// Spins calling the gateway state getter until the state object's ready
/// byte at +0x6a reads 1, sleeping one tick between polls; the getter is
/// re-invoked on every poll (`bl 0x081a5500` sits inside the loop) and the
/// poll runs before the first sleep (the entry `b 0x080c8314`). Deviations:
/// the getter dispatches through GATEWAY_STATE (never-ready default, above)
/// and the one-tick sleep calls the ported task::task_sleep directly — the
/// original's callee is thunk 0x080e9eb0, a bare `b 0x080568e8` alias of
/// task_sleep; the sleep's result is discarded exactly like the original.
/// The ready byte is read volatile so the poll cannot be hoisted.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn gateway_wait_ready() {
    loop {
        let state = (gateway_state())();
        if state.add(READY_FLAG_OFFSET).read_volatile() == READY {
            break;
        }
        task::task_sleep(POLL_SLEEP_TICKS);
    }
}

/// gateway_request_blocking — original: FUN_08048000 @ 0x08048000 (100
/// bytes). Waits for the ROM gateway to report ready, then posts a tag-0
/// request frame carrying `payload` and `flag` through the ROM kernel's
/// mode-1 mailbox-send gateway body, serialized by kernel semaphore 9. See
/// the module header for the frame layout and deviations.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn gateway_request_blocking(payload: usize, flag: usize) {
    (ready_wait())();
    let frame: [usize; FRAME_SLOTS] = [
        0,
        0,
        0,
        0,
        REQUEST_TAG,
        payload,
        0, // padding (uninitialized in the original)
        0, // padding (uninitialized in the original)
        flag,
    ];
    task_lock::rom_sem_wait(REQUEST_LOCK);
    mailbox_send_gateway_mode1(
        GATEWAY_MAILBOX,
        frame.as_ptr() as usize as u32,
        GATEWAY_PRIORITY,
        GATEWAY_SEMAPHORE,
    );
    task_lock::rom_sem_signal(REQUEST_LOCK);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::task_lock::tests::OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::tests::DISPATCH_OPS_LOCK;
    use crate::runtime::message_dispatch_veneer::{
        MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::MutexGuard as ParkingLotMutexGuard;
    use std::sync::MutexGuard;
    use std::vec::Vec;
    use task_lock::RomThunkOps;

    /// Ordered log of the ready wait, semaphore calls, and actual dispatch.
    /// The RTXC request's deliberately uninitialized words are never read.
    static mut CALL_LOG: Vec<&'static str> = Vec::new();
    static mut WAIT_ARG: usize = 0;
    static mut SIGNAL_ARG: usize = 0;
    static mut DISPATCH_COUNT: usize = 0;
    static mut DISPATCH_REQUEST: [u32; 9] = [0; 9];

    unsafe extern "C" fn mock_ready_wait() {
        (*addr_of_mut!(CALL_LOG)).push("ready");
    }

    unsafe extern "C" fn mock_sem_wait(sem: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("wait");
        *addr_of_mut!(WAIT_ARG) = sem;
        0
    }

    unsafe extern "C" fn mock_dispatch(request: *mut u32) {
        (*addr_of_mut!(CALL_LOG)).push("dispatch");
        *addr_of_mut!(DISPATCH_COUNT) += 1;
        for word in [0, 2, 3, 5, 6, 7, 8] {
            (*addr_of_mut!(DISPATCH_REQUEST))[word] = request.add(word).read();
        }
    }

    unsafe extern "C" fn mock_sem_signal(sem: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("signal");
        *addr_of_mut!(SIGNAL_ARG) = sem;
        0
    }

    /// Restores the ready-wait, semaphore, and dispatch seams and releases
    /// their shared test locks.
    struct Installed {
        _dispatch_lock: ParkingLotMutexGuard<'static, ()>,
        _kernel_lock: MutexGuard<'static, ()>,
        saved_kernel: RomThunkOps,
        saved_dispatch: MessageDispatchVeneerOps,
        saved_ready_wait: unsafe extern "C" fn(),
    }

    impl Drop for Installed {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(task_lock::ROM_KERNEL).write(self.saved_kernel);
                MESSAGE_DISPATCH_VENEER_OPS = self.saved_dispatch;
                addr_of_mut!(GATEWAY_READY_WAIT).write(self.saved_ready_wait);
            }
        }
    }

    /// Installs ready-wait and semaphore mocks plus a recorder at the
    /// established message-dispatch veneer seam.
    fn install() -> Installed {
        let dispatch_lock = DISPATCH_OPS_LOCK.lock();
        let kernel_lock = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(CALL_LOG)).clear();
            *addr_of_mut!(WAIT_ARG) = 0;
            *addr_of_mut!(SIGNAL_ARG) = 0;
            *addr_of_mut!(DISPATCH_COUNT) = 0;
            *addr_of_mut!(DISPATCH_REQUEST) = [0; 9];

            let saved_kernel = core::ptr::read_volatile(addr_of!(task_lock::ROM_KERNEL));
            let mut patched_kernel = saved_kernel;
            patched_kernel.rom_sem_wait = mock_sem_wait;
            patched_kernel.rom_sem_signal = mock_sem_signal;
            addr_of_mut!(task_lock::ROM_KERNEL).write(patched_kernel);

            let saved_dispatch = MESSAGE_DISPATCH_VENEER_OPS;
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps {
                dispatch: mock_dispatch,
            };
            let saved_ready_wait = core::ptr::read_volatile(addr_of!(GATEWAY_READY_WAIT));
            addr_of_mut!(GATEWAY_READY_WAIT).write(mock_ready_wait);
            Installed {
                _dispatch_lock: dispatch_lock,
                _kernel_lock: kernel_lock,
                saved_kernel,
                saved_dispatch,
                saved_ready_wait,
            }
        }
    }

    /// The ready wait runs first, then semaphore 9 brackets exactly one
    /// mode-1 mailbox-send dispatch. Its sparse RTXC request preserves the
    /// raw fourth argument as word 2: `{4, _, 6, 1, _, 5, frame, 1, 0}`.
    #[test]
    fn posts_tag0_frame_through_mode1_gateway_under_semaphore_9_after_ready_wait() {
        let _installed = install();
        unsafe {
            gateway_request_blocking(0x080c_1234, 1);
            assert_eq!(
                *addr_of!(CALL_LOG),
                ["ready", "wait", "dispatch", "signal"]
            );
            assert_eq!(*addr_of!(WAIT_ARG), 9);
            assert_eq!(*addr_of!(SIGNAL_ARG), 9);
            assert_eq!(*addr_of!(DISPATCH_COUNT), 1, "exactly one dispatch");
            let request = *addr_of!(DISPATCH_REQUEST);
            assert_eq!(request[0], 4, "mailbox-send selector");
            assert_eq!(request[2], 6, "preserved r3 semaphore");
            assert_eq!(request[3], 1, "mailbox");
            assert_eq!(request[5], 5, "priority");
            assert_ne!(request[6], 0, "frame pointer");
            assert_eq!(request[7], 1, "mode");
            assert_eq!(request[8], 0, "trailing mode word");
        }
    }

    /// Each request reruns the ready wait and independently brackets one
    /// actual dispatcher call.
    #[test]
    fn every_blocking_request_rebrackets_the_dispatcher() {
        let _installed = install();
        unsafe {
            gateway_request_blocking(0, 0);
            gateway_request_blocking(0x33, 0);
            gateway_request_blocking(0xdead_beef, 1);
            assert_eq!(*addr_of!(DISPATCH_COUNT), 3);
            assert_eq!(
                *addr_of!(CALL_LOG),
                [
                    "ready", "wait", "dispatch", "signal", "ready", "wait", "dispatch", "signal",
                    "ready", "wait", "dispatch", "signal"
                ]
            );
        }
    }

    // --- gateway_wait_ready (FUN_080c8304) -------------------------------

    /// Mock gateway state object: the ready byte lives at +0x6a; the mock
    /// getter flips it to 1 on poll READY_ON (1-based) and counts polls.
    static mut STATE_BUF: [u8; 0x6b] = [0; 0x6b];
    static mut POLL_COUNT: usize = 0;
    static mut READY_ON: usize = 0;

    unsafe extern "C" fn mock_gateway_state() -> *mut u8 {
        *addr_of_mut!(POLL_COUNT) += 1;
        if *addr_of!(POLL_COUNT) >= *addr_of!(READY_ON) {
            (*addr_of_mut!(STATE_BUF))[READY_FLAG_OFFSET] = READY;
        }
        addr_of_mut!(STATE_BUF) as *mut u8
    }

    /// Installs the mock getter (OPS_LOCK serializes the GATEWAY_STATE swap
    /// against this module's and task_lock's/csem's tests), returning the
    /// guard and the saved slot.
    fn install_state(ready_on: usize) -> (MutexGuard<'static, ()>, unsafe extern "C" fn() -> *mut u8) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(STATE_BUF))[READY_FLAG_OFFSET] = 0;
            *addr_of_mut!(POLL_COUNT) = 0;
            *addr_of_mut!(READY_ON) = ready_on;
            let saved = core::ptr::read_volatile(addr_of!(GATEWAY_STATE));
            addr_of_mut!(GATEWAY_STATE).write(mock_gateway_state);
            (guard, saved)
        }
    }

    fn restore_state(state: (MutexGuard<'static, ()>, unsafe extern "C" fn() -> *mut u8)) {
        unsafe {
            addr_of_mut!(GATEWAY_STATE).write(state.1);
        }
        drop(state);
    }

    /// Already ready: the entry branch polls before any sleep, so one poll
    /// reading 1 returns immediately.
    #[test]
    fn returns_after_one_poll_when_already_ready() {
        let state = install_state(1);
        unsafe {
            gateway_wait_ready();
            assert_eq!(*addr_of!(POLL_COUNT), 1);
        }
        restore_state(state);
    }

    /// Not ready: the getter is re-invoked on every poll (the original's
    /// `bl 0x081a5500` sits inside the loop) until the byte at +0x6a reads
    /// exactly 1. The one-tick sleep runs with task.rs's default no-op ROM
    /// hooks, matching the original's discarded sleep result.
    #[test]
    fn repolls_the_getter_until_the_ready_byte_reads_one() {
        let state = install_state(7);
        unsafe {
            gateway_wait_ready();
            assert_eq!(*addr_of!(POLL_COUNT), 7);
            assert_eq!((*addr_of!(STATE_BUF))[READY_FLAG_OFFSET], READY);
        }
        restore_state(state);
    }

    /// The default getter hands back a stable never-ready object (the wait
    /// on it hangs loudly — the documented missing-stub behavior — so this
    /// checks the stub itself, never the loop around it).
    #[test]
    fn default_state_stub_is_stable_and_never_ready() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let stub: unsafe extern "C" fn() -> *mut u8 = missing_gateway_state;
            let a = stub();
            let b = stub();
            assert_eq!(a, b, "same static object every call");
            assert_eq!(a.add(READY_FLAG_OFFSET).read_volatile(), 0);
        }
    }
}
