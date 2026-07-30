//! Port of the blocking kernel-gateway request helper @ 0x08048000 (100 bytes,
//! 64 `bl` call sites in osos 2.0.4) — the tag-0 member of the four-helper
//! request family @ 0x08047edc..0x0804805c (tags 3/2/4/0), sibling of
//! kernel/gateway_request.rs's gateway_request_timed. Like the rest of the
//! family it posts a 5-word request frame to the ROM kernel gateway's
//! service-4 stub (`rom_svc_2200418c`, thunk 0x08037e18 -> ROM 0x2200418c)
//! serialized by kernel semaphore 9 (`rom_sem_wait`/`rom_sem_signal`, thunks
//! 0x08037e08 / 0x08037e10 -> ROM 0x22003fd0 / 0x220042b4 — the ported veneer
//! family in kernel/task_lock.rs).
//!
//! Algorithm (verified against osos.asm @ 0x08048000..0x08048064): first call
//! the gateway-ready wait FUN_080c8304 (see GATEWAY_READY_WAIT below), then
//! build a 9-word stack frame — words 0..3 zeroed (the original's two
//! `stmia` pairs), tag byte 0 stored at word 4 (frame layout matches Ghidra's
//! {local_30..local_10}), word 5 = the payload argument, words 6 and 7
//! untouched padding, word 8 = the flag argument. Then, holding kernel
//! semaphore 9, call the service-4 gateway stub with (kind = 1, &frame,
//! FRAME_WORDS = 5) and release the semaphore. The payload/flag words sit
//! past the declared frame — the ROM service reads them through the same
//! pointer beyond the announced count. Call-site survey (all 64 `bl` sites):
//! r0 (payload) is a small id (0x1, 0x8, 0x10, 0x23, 0x30, 0x33, 0x37
//! observed) or an object pointer; r1 (flag) is an immediate 0 or 1 at every
//! immediate site (a handful pass a register).
//!
//! Deviations from the original (the task_lock.rs ROM-dispatch design, same
//! as gateway_request.rs):
//! - The leading ready wait FUN_080c8304 is ported below as
//!   gateway_wait_ready, but the call still dispatches through the
//!   GATEWAY_READY_WAIT slot below, whose documented spin default stays
//!   installed until gateway_wait_ready (or the stock function) is wired
//!   in — the observable_set_observer dispatch-boundary precedent.
//! - The three ROM calls dispatch indirectly through task_lock::ROM_KERNEL
//!   instead of `bl` to the 8-byte thunk veneers; match.py diffs are
//!   structural, as with the rest of the family.
//! - The original loads r3 = 6 (the service-4 sub-op) before the gateway
//!   call; the ported veneer `rom_svc_2200418c` forwards only r0-r2, so
//!   the sub-op cannot ride along — visible to match.py as a missing
//!   `mov r3, #6`. Same caveat as every client of that veneer.
//! - The padding words 6 and 7 (sp+0x18/sp+0x1c in the original) are zeroed
//!   rather than left uninitialized; nothing declared reads them.
//! - The original leaves the semaphore-signal result in r0; no caller
//!   consumes it, so the port returns nothing.

use crate::kernel::task;
use crate::kernel::task_lock;

/// Kernel semaphore serializing the whole request family (r0 = 9 at all
/// four helpers' wait/signal call sites).
const REQUEST_LOCK: usize = 9;

/// Tag byte identifying this helper's request flavor (frame word 4).
const REQUEST_TAG: usize = 0;

/// First argument to the service-4 gateway stub (`mov r0, #1`).
const SERVICE4_KIND: usize = 1;

/// Declared frame length in words, the stub's third argument (`mov r2, #5`).
const FRAME_WORDS: usize = 5;

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
/// request frame carrying `payload` and `flag` to the ROM kernel gateway's
/// service-4 stub, serialized by kernel semaphore 9. See the module header
/// for the frame layout and deviations.
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
    task_lock::rom_svc_2200418c(SERVICE4_KIND, frame.as_ptr() as usize, FRAME_WORDS);
    task_lock::rom_sem_signal(REQUEST_LOCK);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::kernel::task_lock::tests::OPS_LOCK;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::MutexGuard;
    use std::vec::Vec;
    use task_lock::RomThunkOps;

    /// Ordered log of the calls the helper makes (ready wait plus the ROM
    /// calls), plus the frame contents the service-4 mock reads back
    /// through the frame pointer.
    static mut CALL_LOG: Vec<&'static str> = Vec::new();
    static mut WAIT_ARG: usize = 0;
    static mut SIGNAL_ARG: usize = 0;
    static mut SVC_ARGS: [usize; 3] = [0; 3];
    static mut FRAME_READ: [usize; FRAME_SLOTS] = [0; FRAME_SLOTS];

    unsafe extern "C" fn mock_ready_wait() {
        (*addr_of_mut!(CALL_LOG)).push("ready");
    }

    unsafe extern "C" fn mock_sem_wait(sem: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("wait");
        *addr_of_mut!(WAIT_ARG) = sem;
        0
    }

    unsafe extern "C" fn mock_svc4(a0: usize, a1: usize, a2: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("svc4");
        *addr_of_mut!(SVC_ARGS) = [a0, a1, a2];
        // The ROM service reads the request through the frame pointer;
        // capture everything the original wrote around it.
        for (i, slot) in (*addr_of_mut!(FRAME_READ)).iter_mut().enumerate() {
            *slot = (a1 as *const usize).add(i).read_volatile();
        }
        0
    }

    unsafe extern "C" fn mock_sem_signal(sem: usize) -> usize {
        (*addr_of_mut!(CALL_LOG)).push("signal");
        *addr_of_mut!(SIGNAL_ARG) = sem;
        0
    }

    /// Installs the mocks in task_lock's ROM_KERNEL and the ready-wait slot
    /// (OPS_LOCK serializes the swap against task_lock's, csem's and
    /// gateway_request's tests), returns the guard and the saved state.
    fn install() -> (MutexGuard<'static, ()>, RomThunkOps, unsafe extern "C" fn()) {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(CALL_LOG)).clear();
            *addr_of_mut!(WAIT_ARG) = 0;
            *addr_of_mut!(SIGNAL_ARG) = 0;
            *addr_of_mut!(SVC_ARGS) = [0; 3];
            *addr_of_mut!(FRAME_READ) = [0; FRAME_SLOTS];
            let saved_ops = core::ptr::read_volatile(addr_of!(task_lock::ROM_KERNEL));
            let mut patched = saved_ops;
            patched.rom_sem_wait = mock_sem_wait;
            patched.rom_svc_2200418c = mock_svc4;
            patched.rom_sem_signal = mock_sem_signal;
            addr_of_mut!(task_lock::ROM_KERNEL).write(patched);
            let saved_wait = core::ptr::read_volatile(addr_of!(GATEWAY_READY_WAIT));
            addr_of_mut!(GATEWAY_READY_WAIT).write(mock_ready_wait);
            (guard, saved_ops, saved_wait)
        }
    }

    fn restore(state: (MutexGuard<'static, ()>, RomThunkOps, unsafe extern "C" fn())) {
        unsafe {
            addr_of_mut!(task_lock::ROM_KERNEL).write(state.1);
            addr_of_mut!(GATEWAY_READY_WAIT).write(state.2);
        }
        drop(state);
    }

    /// The full contract: the ready wait runs first, then semaphore 9
    /// brackets the service-4 call, the stub gets (1, &frame, 5), and the
    /// stack frame carries {0,0,0,0, tag 0, payload, pad, pad, flag}.
    #[test]
    fn posts_tag0_frame_under_semaphore_9_after_ready_wait() {
        let state = install();
        unsafe {
            gateway_request_blocking(0x080c_1234, 1);
            assert_eq!(*addr_of!(CALL_LOG), ["ready", "wait", "svc4", "signal"]);
            assert_eq!(*addr_of!(WAIT_ARG), 9);
            assert_eq!(*addr_of!(SIGNAL_ARG), 9);
            let svc = *addr_of!(SVC_ARGS);
            assert_eq!(svc[0], 1, "service-4 kind");
            assert_ne!(svc[1], 0, "frame pointer");
            assert_eq!(svc[2], 5, "declared frame words");
            assert_eq!(
                *addr_of!(FRAME_READ),
                [0, 0, 0, 0, 0, 0x080c_1234, 0, 0, 1],
                "frame layout"
            );
        }
        restore(state);
    }

    /// The payload lands at frame word 5 and the flag at word 8 with the
    /// pad words zeroed; each call re-runs the ready wait and re-brackets
    /// the semaphore.
    #[test]
    fn payload_and_flag_land_in_their_frame_words() {
        let state = install();
        unsafe {
            gateway_request_blocking(0, 0);
            assert_eq!(*addr_of!(FRAME_READ), [0; FRAME_SLOTS]);
            gateway_request_blocking(0x33, 0);
            assert_eq!((*addr_of!(FRAME_READ))[5], 0x33);
            assert_eq!((*addr_of!(FRAME_READ))[8], 0);
            gateway_request_blocking(0xdead_beef, 1);
            assert_eq!((*addr_of!(FRAME_READ))[5], 0xdead_beef);
            assert_eq!((*addr_of!(FRAME_READ))[8], 1);
            assert_eq!((*addr_of!(FRAME_READ))[6], 0, "pad word 6");
            assert_eq!((*addr_of!(FRAME_READ))[7], 0, "pad word 7");
            assert_eq!(
                *addr_of!(CALL_LOG),
                [
                    "ready", "wait", "svc4", "signal", "ready", "wait", "svc4", "signal", "ready",
                    "wait", "svc4", "signal"
                ]
            );
        }
        restore(state);
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
