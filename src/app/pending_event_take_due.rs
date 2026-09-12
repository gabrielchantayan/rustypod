//! `pending_event_take_due` — original: `FUN_081394b0` @ 0x081394b0.
//!
//! **Extent:** 204 bytes of code, 0x081394b0..0x0813957c. The next
//! function starts with `push {r0-r6,lr}` at 0x0813957c, so Ghidra's
//! reported size is exact. **Call count:** every ARM B/BL word in
//! `osos.dec` was decoded: 8 direct, unconditional `bl` call sites; 0
//! predicated `bl`, 0 tail `b`, and 0 data-word references.
//!
//! Under the pending-event queue mutex at `this + 0x2ac`, inspect the
//! live-list head. If its deadline is due according to the firmware's
//! wrapping signed comparison (`deadline_ms - now_ms` is zero or has bit
//! 31 set), copy its key, two tags, and payload to the four output
//! pointers; release it; then re-arm the timer when release succeeds.
//! An empty queue or a future deadline leaves every output untouched and
//! returns 0x52.
//!
//! # Deliberate deviations
//!
//! The release and rearm calls reuse the existing
//! [`super::pending_event_take::PENDING_EVENT_TAKE_OPS`] seam: their ROM
//! targets are still unported at 0x0813908c and 0x0813957c. The clock read
//! is the original dynamic vtable call through `clock + 0x0c`; its stock
//! slot is the documented mid-function anomaly, so the target default
//! reads and calls it rather than inventing a callee. Host tests replace
//! that dynamic call with a deterministic clock model.

use core::ffi::c_void;

use super::pending_event_take::{
    PendingEventNode, PendingEventTakeOps, PENDING_EVENT_TAKE_OPS, QUEUE_MUTEX_OFFSET,
};
use crate::cxx::clock_source_construct::clock_source_construct;
use crate::cxx::clock_source_destroy::clock_source_destroy;
use crate::fp::fp_misc::timespec_to_milliseconds;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

/// Firmware status for an empty queue or a head whose deadline has not
/// arrived (`mov r6, #0x52`). It has the same numeric value as the
/// keyed-take sibling's miss, but specifically means "no due event" here.
pub const ERR_NO_DUE_PENDING_EVENT: u32 = 0x52;

const CLOCK_OBJECT_LEN: usize = 8;

/// The dynamic clock read at vtable slot +0x0c. This is not a named ROM
/// callee: the installed slot is a known mid-function image address.
#[derive(Clone, Copy)]
pub struct PendingEventTakeDueOps {
    pub clock_read_time: unsafe extern "C" fn(clock: *mut u8, ts_out: *mut i32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_clock_read_time(clock: *mut u8, ts_out: *mut i32) {
    let vtable = (clock as *const u32).read_volatile() as usize;
    let slot = (vtable as *const u32).add(3).read_volatile() as usize;
    let read_time: unsafe extern "C" fn(*mut u8, *mut i32) = core::mem::transmute(slot);
    read_time(clock, ts_out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_clock_read_time(_clock: *mut u8, ts_out: *mut i32) {
    ts_out.write(0);
    ts_out.add(1).write(0);
}

pub const DEFAULT_PENDING_EVENT_TAKE_DUE_OPS: PendingEventTakeDueOps = PendingEventTakeDueOps {
    clock_read_time: firmware_clock_read_time,
};

/// Active model of the raw dynamic clock call. `read_volatile` below keeps
/// target LLVM from replacing the dynamic dispatch with a builtin or fold.
pub static mut PENDING_EVENT_TAKE_DUE_OPS: PendingEventTakeDueOps =
    DEFAULT_PENDING_EVENT_TAKE_DUE_OPS;

#[inline(always)]
fn pending_event_take_due_ops() -> PendingEventTakeDueOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PENDING_EVENT_TAKE_DUE_OPS)) }
}

#[inline(always)]
fn pending_event_take_ops() -> PendingEventTakeOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PENDING_EVENT_TAKE_OPS)) }
}

/// `pending_event_take_due` — original `FUN_081394b0` @ 0x081394b0 (204
/// bytes; 8 unconditional `bl` call sites, binary-verified — see module
/// header).
///
/// Consume the live-list head only when its deadline is due. On success,
/// copy `{key, tag_a, tag_b, payload}` out before releasing the node; a
/// nonzero release status skips rearming and becomes the result. The
/// firmware's deadline ordering is wrapping: an elapsed difference of
/// 0x80000000 is due, while 1..=0x7fffffff remains future.
///
/// # Safety
/// `this` must name a queue-bearing session object with a valid mutex at
/// +0x2ac. All four output pointers must be writable; firmware makes no
/// null checks for any of them.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_event_take_due(
    this: *mut u8,
    key_out: *mut u32,
    tag_a_out: *mut u16,
    tag_b_out: *mut u16,
    payload_out: *mut u32,
) -> u32 {
    let mut status = ERR_NO_DUE_PENDING_EVENT;
    let mutex = this.wrapping_add(QUEUE_MUTEX_OFFSET) as *mut PosixMutex;
    posix_mutex_lock(mutex);

    let node = (this.add(4) as *const u32).read() as usize as *mut PendingEventNode;
    if !node.is_null() {
        let mut clock = [0u8; CLOCK_OBJECT_LEN];
        clock_source_construct(clock.as_mut_ptr());
        let mut timespec = [0i32; 2];
        (pending_event_take_due_ops().clock_read_time)(clock.as_mut_ptr(), timespec.as_mut_ptr());
        let now_ms = timespec_to_milliseconds(timespec.as_ptr()) as u32;
        let deadline_delta = (*node).deadline_ms.wrapping_sub(now_ms);
        if deadline_delta == 0 || deadline_delta >= 0x8000_0000 {
            key_out.write((*node).key);
            tag_a_out.write((*node).tag_a);
            tag_b_out.write((*node).tag_b);
            payload_out.write((*node).payload);
            let take_ops = pending_event_take_ops();
            status = (take_ops.release_node)(this, node);
            if status == 0 {
                status = (take_ops.rearm_timer)(this);
            }
        }
        clock_source_destroy(clock.as_mut_ptr() as *mut c_void);
    }

    posix_mutex_unlock(mutex);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, PENDING_EVENT_TAKE_OPS_TEST_LOCK,
    };
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    const HEAD_OFFSET: usize = 0x004;
    const NODE_OFFSET: usize = 0x300;
    const SLAB_LEN: usize = NODE_OFFSET + core::mem::size_of::<PendingEventNode>();

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        Clock { now_ms: u32 },
        Release { key: u32 },
        Rearm,
    }

    static mut CALLS: Vec<Call> = Vec::new();
    static mut NOW_MS: u32 = 0;
    static mut RELEASE_STATUS: u32 = 0;
    static mut REARM_STATUS: u32 = 0;

    struct Bench {
        _take_ops_lock: MutexGuard<'static, ()>,
        _lock: MutexGuard<'static, ()>,
        previous_due_ops: PendingEventTakeDueOps,
        previous_take_ops: PendingEventTakeOps,
        slab: *mut u8,
    }

    unsafe fn slab() -> *mut u8 {
        static mut SLAB: *mut u8 = core::ptr::null_mut();
        if SLAB.is_null() {
            match try_map_u32_slab(hints::PENDING_EVENT_TAKE_DUE, SLAB_LEN) {
                Some(mapped) => SLAB = mapped,
                None => {
                    note_missing_u32_fixture("app::pending_event_take_due");
                }
            }
        }
        SLAB
    }

    unsafe fn node() -> *mut PendingEventNode {
        slab().add(NODE_OFFSET) as *mut PendingEventNode
    }

    unsafe fn mutex() -> *mut PosixMutex {
        slab().add(QUEUE_MUTEX_OFFSET) as *mut PosixMutex
    }

    unsafe fn reset_queue() {
        core::ptr::write_bytes(slab(), 0, SLAB_LEN);
        CALLS.clear();
        NOW_MS = 0;
        RELEASE_STATUS = 0;
        REARM_STATUS = 0;
    }

    unsafe fn assert_locked() {
        assert_eq!(
            (*mutex()).owner,
            crate::kernel::posix_mutex::PRE_KERNEL_THREAD,
            "queue mutex remains held inside the callee"
        );
    }

    unsafe extern "C" fn mock_clock_read_time(_clock: *mut u8, ts_out: *mut i32) {
        assert_locked();
        CALLS.push(Call::Clock { now_ms: NOW_MS });
        ts_out.write((NOW_MS / 1000) as i32);
        ts_out.add(1).write(((NOW_MS % 1000) * 1_000_000) as i32);
    }

    unsafe extern "C" fn mock_release_node(this: *mut u8, released: *mut PendingEventNode) -> u32 {
        assert_locked();
        CALLS.push(Call::Release { key: (*released).key });
        let head = this.add(HEAD_OFFSET) as *mut u32;
        assert_eq!(*head as usize, released as usize, "only the live head is released");
        *head = (*released).next;
        RELEASE_STATUS
    }

    unsafe extern "C" fn mock_rearm_timer(_this: *mut u8) -> u32 {
        assert_locked();
        CALLS.push(Call::Rearm);
        REARM_STATUS
    }

    fn bench() -> Option<Bench> {
        let take_ops_lock = PENDING_EVENT_TAKE_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let slab = unsafe { slab() };
        if slab.is_null() {
            note_missing_u32_fixture("app::pending_event_take_due");
            return None;
        }
        let previous_due_ops = unsafe { PENDING_EVENT_TAKE_DUE_OPS };
        let previous_take_ops = unsafe { PENDING_EVENT_TAKE_OPS };
        unsafe {
            PENDING_EVENT_TAKE_DUE_OPS = PendingEventTakeDueOps {
                clock_read_time: mock_clock_read_time,
            };
            PENDING_EVENT_TAKE_OPS = PendingEventTakeOps {
                find_link: previous_take_ops.find_link,
                release_node: mock_release_node,
                rearm_timer: mock_rearm_timer,
            };
            reset_queue();
        }
        Some(Bench {
            _take_ops_lock: take_ops_lock,
            _lock: lock,
            previous_due_ops,
            previous_take_ops,
            slab,
        })
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                PENDING_EVENT_TAKE_DUE_OPS = self.previous_due_ops;
                PENDING_EVENT_TAKE_OPS = self.previous_take_ops;
            }
        }
    }

    unsafe fn plant_head(deadline_ms: u32, key: u32, tag_a: u16, tag_b: u16, payload: u32) {
        *node() = PendingEventNode {
            next: 0,
            key,
            deadline_ms,
            tag_a,
            tag_b,
            payload,
        };
        (slab().add(HEAD_OFFSET) as *mut u32).write(node() as usize as u32);
    }

    #[test]
    fn consumes_an_exactly_due_head_and_copies_all_outputs() {
        let bench = match bench() { Some(bench) => bench, None => return };
        unsafe {
            NOW_MS = 7_500;
            plant_head(NOW_MS, 0x33, 0x44, 0x55, 0xfeed_beef);
            let mut key = 0;
            let mut tag_a = 0;
            let mut tag_b = 0;
            let mut payload = 0;

            let status = pending_event_take_due(bench.slab, &mut key, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, 0);
            assert_eq!((key, tag_a, tag_b, payload), (0x33, 0x44, 0x55, 0xfeed_beef));
            assert_eq!(*CALLS, [Call::Clock { now_ms: 7_500 }, Call::Release { key: 0x33 }, Call::Rearm]);
            assert_eq!((bench.slab.add(HEAD_OFFSET) as *const u32).read(), 0);
            assert_eq!((*mutex()).owner, 0, "mutex is released after success");
        }
    }

    #[test]
    fn empty_or_future_head_leaves_outputs_and_head_untouched() {
        let bench = match bench() { Some(bench) => bench, None => return };
        unsafe {
            let mut key = 1;
            let mut tag_a = 2;
            let mut tag_b = 3;
            let mut payload = 4;
            assert_eq!(pending_event_take_due(bench.slab, &mut key, &mut tag_a, &mut tag_b, &mut payload), ERR_NO_DUE_PENDING_EVENT);
            assert_eq!((key, tag_a, tag_b, payload), (1, 2, 3, 4));
            assert!(CALLS.is_empty(), "an empty list does not construct a clock");

            NOW_MS = 11;
            plant_head(NOW_MS.wrapping_add(0x7fff_ffff), 5, 6, 7, 8);
            assert_eq!(pending_event_take_due(bench.slab, &mut key, &mut tag_a, &mut tag_b, &mut payload), ERR_NO_DUE_PENDING_EVENT);
            assert_eq!((key, tag_a, tag_b, payload), (1, 2, 3, 4));
            assert_eq!(*CALLS, [Call::Clock { now_ms: 11 }]);
            assert_ne!((bench.slab.add(HEAD_OFFSET) as *const u32).read(), 0, "future head stays linked");
            assert_eq!((*mutex()).owner, 0, "mutex is released on both miss paths");
        }
    }

    #[test]
    fn wrapping_signed_deadline_boundary_is_due() {
        let bench = match bench() { Some(bench) => bench, None => return };
        unsafe {
            NOW_MS = 0xffff_fff0;
            plant_head(NOW_MS.wrapping_add(0x8000_0000), 9, 10, 11, 12);
            let mut key = 0;
            let mut tag_a = 0;
            let mut tag_b = 0;
            let mut payload = 0;

            assert_eq!(pending_event_take_due(bench.slab, &mut key, &mut tag_a, &mut tag_b, &mut payload), 0);
            assert_eq!((key, tag_a, tag_b, payload), (9, 10, 11, 12));
            assert_eq!(*CALLS, [Call::Clock { now_ms: 0xffff_fff0 }, Call::Release { key: 9 }, Call::Rearm]);
        }
    }

    #[test]
    fn release_failure_skips_rearm_but_rearm_status_chains_on_success() {
        let bench = match bench() { Some(bench) => bench, None => return };
        unsafe {
            NOW_MS = 100;
            RELEASE_STATUS = 7;
            plant_head(99, 1, 2, 3, 4);
            let mut key = 0;
            let mut tag_a = 0;
            let mut tag_b = 0;
            let mut payload = 0;
            assert_eq!(pending_event_take_due(bench.slab, &mut key, &mut tag_a, &mut tag_b, &mut payload), 7);
            assert_eq!((key, tag_a, tag_b, payload), (1, 2, 3, 4), "outputs precede release");
            assert_eq!(*CALLS, [Call::Clock { now_ms: 100 }, Call::Release { key: 1 }]);

            reset_queue();
            NOW_MS = 100;
            REARM_STATUS = 9;
            plant_head(99, 5, 6, 7, 8);
            assert_eq!(pending_event_take_due(bench.slab, &mut key, &mut tag_a, &mut tag_b, &mut payload), 9);
            assert_eq!(*CALLS, [Call::Clock { now_ms: 100 }, Call::Release { key: 5 }, Call::Rearm]);
        }
    }
}
