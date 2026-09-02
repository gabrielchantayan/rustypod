//! `pending_event_insert` — original: `FUN_08138fd0` @ 0x08138fd0
//! (**188 bytes**, 0x08138fd0..0x813908c: pure code, no literal pool;
//! the body ends in `pop {.., pc}` at 0x08139088 and the next function
//! — the sorted-insert helper 0x081390ec this one calls — was itself
//! byte-decoded as starting at 0x081390ec…0x8139190, so the extent is
//! exact. Ghidra's "188" is right for once; still byte-decoded from
//! osos.dec, not trusted).
//! **22 `bl` call sites**, binary-verified by decoding every B/BL word
//! in osos.dec — all 22 unconditional `bl` (0 predicated forms, 0 tail
//! `b`), and **0 occurrences of 0x08138fd0 as a data word**, so it is
//! reached only by direct call, never through a vtable.
//!
//! The schedule-half of the pending-event queue embedded at the start
//! of the playback session object — the sibling of
//! [`super::pending_event_take`] @ 0x08138f14 (ported), whose module
//! header maps the whole family. This function pops a free node
//! (helper 0x081391f0, free-list head at +0x18), fills it, stamps an
//! absolute deadline of `now_ms + delta_ms` from the kind-1 clock
//! source, links it into the live chain (helper 0x081390ec, a sorted
//! insert by remaining time), re-arms the deadline timer (helper
//! 0x0813957c, unconditional), and reports a status — all under the
//! queue [`PosixMutex`] at `this + 0x2ac`:
//!
//! ```text
//! 08138fd0  push {r0-r3, r4-r9, sl, fp, lr}
//! 08138fd4  sub  sp, sp, #20
//! 08138fd8  ldr  r0, [sp, #20]        @ this (stacked arg r0)
//! 08138fdc  mov  r9, r3               @ tag_b
//! 08138fe0  add  r6, r0, #0x2ac       @ &this->mutex
//! 08138fe8  mov  r8, r2               @ tag_a
//! 08138fec  mov  r5, #12              @ default status: no free node
//! 08138ff0  ldrd sl, fp, [sp, #72]    @ payload, delta_ms (stack args)
//! 08138ff4  bl   0x08261e20           @ posix_mutex_lock(&mutex)
//! 08139000  bl   0x081391f0           @ node = pop_free_node(this)
//! 08139008  beq  0x08139068           @ none free -> rearm/unlock/0x0c
//! 08139010  bl   0x08262958           @ clock_source_construct(&clock)
//! 08139014  str  r7, [r4]             @ node->next = NULL
//! 0813901c  add  r1, sp, #4           @ &timespec (r1 live till blx)
//! 08139020  str  r0, [r4, #4]         @ node->key = key
//! 08139024  strh r8, [r4, #12]        @ node->tag_a
//! 08139028  strh r9, [r4, #14]        @ node->tag_b
//! 0813902c  str  sl, [r4, #16]        @ node->payload
//! 08139034  ldr  r2, [r0, #12]        @ vtable slot +0x0c: read_time
//! 0813903c  blx  r2                   @ read_time(&clock, &timespec)
//! 08139044  bl   0x082a1c30           @ timespec_to_milliseconds(&ts)
//! 08139048  add  r0, r0, fp           @ now_ms + delta_ms
//! 0813904c  str  r0, [r4, #8]         @ node->deadline_ms
//! 08139058  bl   0x081390ec           @ status = insert(this, node)
//! 08139064  bl   0x08262908           @ clock_source_destroy(&clock)
//! 0813906c  bl   0x0813957c           @ rearm(this) — ALWAYS
//! 08139070  cmp  r5, #0
//! 08139074  moveq r5, r0              @ keep rearm status on success
//! 0813907c  bl   0x08261e24           @ posix_mutex_unlock(&mutex)
//! 08139088  pop  {r4-r9, sl, fp, pc}  @ return status
//! ```
//!
//! Three behavioural facts the bytes pin down:
//!
//! - The default status is **0x0c** (`mov r5, #12`), returned when the
//!   free list is empty; the take sibling uses 0x52 for its miss, so
//!   these are module-level codes, not errno values. On firmware the
//!   insert helper returns 0 or panics and the rearm always returns 0,
//!   so the observable contract is **0 = scheduled, 0x0c = queue
//!   pool exhausted** — but the port keeps the original's general
//!   status chaining because those callees sit behind the ops seam.
//! - The rearm runs **unconditionally**, even when no node was free or
//!   the insert failed; its return value is kept only when the status
//!   so far is 0 (`cmp r5, #0; moveq r5, r0`).
//! - The two stack arguments arrive as a pair loaded with
//!   `ldrd sl, fp, [sp, #72]`: payload first, delta_ms second.
//!
//! # Deviations
//!
//! - **Four callees are unported** and dispatch through
//!   [`PENDING_EVENT_INSERT_OPS`] (the `ui/table_slot_allocate.rs`
//!   pattern): the free-node pop 0x081391f0, the sorted insert
//!   0x081390ec and the rearm 0x0813957c transmute their ROM addresses
//!   on target; the clock read is the `blx` through vtable slot +0x0c,
//!   whose target default re-reads the vtable word from the
//!   constructed object and calls whatever slot +0x0c holds — exactly
//!   the original's indirection, which names.yaml documents as
//!   pointing mid-function in the stock image (the
//!   `clock_source_construct` anomaly; documented, not invented).
//!   Host defaults are inert (NULL / 0 / a zeroed timespec) and every
//!   test installs a recording reference model.
//! - The lock/unlock go through the canonical ported
//!   [`crate::kernel::posix_mutex::posix_mutex_lock`]/_unlock directly
//!   — the original calls the 4-byte alias veneers
//!   0x08261e20/0x08261e24, which names.yaml resolves to those symbols.
//! - The clock construct/destroy and the timespec conversion call the
//!   ported [`clock_source_construct`], [`clock_source_destroy`] and
//!   [`timespec_to_milliseconds`] directly. The original constructs
//!   the clock before touching the node and destroys it after the
//!   insert; the port keeps that order, and keeps the original's
//!   field-write order (next, key, tag_a, tag_b, payload, deadline).
//! - The millisecond sum wraps silently on ARM; the port uses
//!   `wrapping_add` so a debug host build cannot panic where the
//!   original's bare `add` wraps.

use core::ffi::c_void;

use super::pending_event_take::{PendingEventNode, QUEUE_MUTEX_OFFSET};
use crate::cxx::clock_source_construct::clock_source_construct;
use crate::cxx::clock_source_destroy::clock_source_destroy;
use crate::fp::fp_misc::timespec_to_milliseconds;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

/// Status returned when the free list is empty and no node could be
/// scheduled (original `mov r5, #12`). The take sibling reports 0x52
/// for its miss; these are module-level codes, not errno values.
pub const ERR_NO_FREE_NODE: u32 = 0x0c;

/// The stack clock object is `{ u32 vtable, u8 kind }` (see
/// `clock_source_construct`); the original reserves eight bytes for it
/// at sp+12 and eight more for the `{ sec, nsec }` pair at sp+4.
const CLOCK_OBJECT_LEN: usize = 8;

/// Indirect dispatch for the four unported callees (see the module
/// header). Host tests install recording models; a later port of each
/// callee replaces its default without touching this caller.
#[derive(Clone, Copy)]
pub struct PendingEventInsertOps {
    /// Free-node pop 0x081391f0 `(this)` -> the free-list head node,
    /// unlinked, or NULL when the pool is exhausted. The returned
    /// node's `next` still holds the old free-link; this function
    /// overwrites it.
    pub pop_free_node: unsafe extern "C" fn(this: *mut u8) -> *mut PendingEventNode,
    /// Clock read, the original's `blx` through vtable slot +0x0c:
    /// `(clock, ts_out)` fills `{ sec, nsec }`. The target default
    /// re-reads the vtable from the object and calls the slot,
    /// reproducing the original indirection verbatim.
    pub clock_read_time: unsafe extern "C" fn(clock: *mut u8, ts_out: *mut i32),
    /// Sorted insert 0x081390ec `(this, node)`: links the node into
    /// the live chain ordered by remaining time. Returns 0 on
    /// firmware.
    pub insert_node: unsafe extern "C" fn(this: *mut u8, node: *mut PendingEventNode) -> u32,
    /// Rearm 0x0813957c `(this)`: re-programs the IAP-thread wakeup
    /// from the new head's deadline. Always returns 0 on firmware and
    /// is called even when scheduling failed.
    pub rearm_timer: unsafe extern "C" fn(this: *mut u8) -> u32,
}

/// Target default: the ROM free-node pop.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_pop_free_node(this: *mut u8) -> *mut PendingEventNode {
    let f: unsafe extern "C" fn(*mut u8) -> *mut PendingEventNode =
        core::mem::transmute(0x0813_91f0usize);
    f(this)
}

/// Host default: inert — the tests install their own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_pop_free_node(_this: *mut u8) -> *mut PendingEventNode {
    core::ptr::null_mut()
}

/// Target default: the original's `blx` through vtable slot +0x0c,
/// re-resolved from the constructed object exactly like the `ldr r0,
/// [sp, #12] / ldr r2, [r0, #12] / blx r2` sequence it replaces.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_clock_read_time(clock: *mut u8, ts_out: *mut i32) {
    let vtable = (clock as *const u32).read_volatile() as usize;
    let slot = (vtable as *const u32).add(3).read_volatile() as usize;
    let f: unsafe extern "C" fn(*mut u8, *mut i32) = core::mem::transmute(slot);
    f(clock, ts_out)
}

/// Host default: inert — writes a zeroed `{ sec, nsec }` so the
/// conversion stays deterministic; the tests install their own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_clock_read_time(_clock: *mut u8, ts_out: *mut i32) {
    ts_out.write(0);
    ts_out.add(1).write(0);
}

/// Target default: the ROM sorted insert.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_insert_node(
    this: *mut u8,
    node: *mut PendingEventNode,
) -> u32 {
    let f: unsafe extern "C" fn(*mut u8, *mut PendingEventNode) -> u32 =
        core::mem::transmute(0x0813_90ecusize);
    f(this, node)
}

/// Host default: inert — the tests install their own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_insert_node(
    _this: *mut u8,
    _node: *mut PendingEventNode,
) -> u32 {
    0
}

/// Target default: the ROM timer rearm.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_rearm_timer(this: *mut u8) -> u32 {
    let f: unsafe extern "C" fn(*mut u8) -> u32 = core::mem::transmute(0x0813_957cusize);
    f(this)
}

/// Host default: inert — the tests install their own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_rearm_timer(_this: *mut u8) -> u32 {
    0
}

/// Wired defaults: ROM addresses on target, documented inert stubs on
/// host.
pub const DEFAULT_PENDING_EVENT_INSERT_OPS: PendingEventInsertOps = PendingEventInsertOps {
    pop_free_node: firmware_pop_free_node,
    clock_read_time: firmware_clock_read_time,
    insert_node: firmware_insert_node,
    rearm_timer: firmware_rearm_timer,
};

/// The active callee set, read through `read_volatile` so LLVM cannot
/// fold the indirect calls to the defaults.
pub static mut PENDING_EVENT_INSERT_OPS: PendingEventInsertOps =
    DEFAULT_PENDING_EVENT_INSERT_OPS;

#[inline(always)]
fn pending_event_insert_ops() -> PendingEventInsertOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PENDING_EVENT_INSERT_OPS)) }
}

/// pending_event_insert — original: `FUN_08138fd0` @ 0x08138fd0 (188
/// bytes; 22 `bl` call sites, binary-verified — see the module
/// header).
///
/// Under the queue mutex at `this + 0x2ac`: pop a free node, fill it
/// with `{next = 0, key, tag_a, tag_b, payload}`, stamp
/// `deadline_ms = now_ms + delta_ms` from the kind-1 clock source,
/// link it into the live chain, re-arm the deadline timer (always,
/// even on failure), and report 0 — or [`ERR_NO_FREE_NODE`] (0x0c)
/// when the pool is exhausted, in which case no node is touched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_event_insert(
    this: *mut u8,
    key: u32,
    tag_a: u16,
    tag_b: u16,
    payload: u32,
    delta_ms: u32,
) -> u32 {
    let mut status: u32 = ERR_NO_FREE_NODE;
    let mutex = this.wrapping_add(QUEUE_MUTEX_OFFSET) as *mut PosixMutex;
    posix_mutex_lock(mutex);
    let ops = pending_event_insert_ops();
    let node = (ops.pop_free_node)(this);
    if !node.is_null() {
        let mut clock = [0u8; CLOCK_OBJECT_LEN];
        clock_source_construct(clock.as_mut_ptr());
        (*node).next = 0;
        (*node).key = key;
        (*node).tag_a = tag_a;
        (*node).tag_b = tag_b;
        (*node).payload = payload;
        let mut timespec = [0i32; 2];
        (ops.clock_read_time)(clock.as_mut_ptr(), timespec.as_mut_ptr());
        let now_ms = timespec_to_milliseconds(timespec.as_ptr()) as u32;
        (*node).deadline_ms = now_ms.wrapping_add(delta_ms);
        status = (ops.insert_node)(this, node);
        clock_source_destroy(clock.as_mut_ptr() as *mut c_void);
    }
    let rearm_status = (ops.rearm_timer)(this);
    if status == 0 {
        status = rearm_status;
    }
    posix_mutex_unlock(mutex);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test here: they share one fixture slab (the
    /// mapper never unmaps, so a second mapping would land above 4 GiB
    /// and skip silently) and swap the global ops table.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Fixture layout inside the mapped slab (same map as the take
    /// sibling's):
    ///
    /// ```text
    /// S+0x000  session object; live-chain head at S+0x004, free-list
    ///          head at S+0x018, PosixMutex at S+0x2ac
    /// S+0x300  node pool: NODE_SLOTS entries of 0x20 bytes each
    /// ```
    const FREE_OFFSET: usize = 0x018;
    const POOL_OFFSET: usize = 0x300;
    const NODE_STRIDE: usize = 0x20;
    const NODE_SLOTS: usize = 8;
    const SLAB_LEN: usize = POOL_OFFSET + NODE_SLOTS * NODE_STRIDE;

    /// Recorded callee invocations, in order. `Insert` carries the
    /// node's pool offset so expectations stay address-independent.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Call {
        PopFree,
        ReadTime { vtable: u32 },
        Insert { pool_slot: usize },
        Rearm,
    }

    static mut CALLS: Vec<Call> = Vec::new();

    /// What the mock insert slot reports.
    static mut INSERT_STATUS: u32 = 0;

    /// What the mock rearm slot reports.
    static mut REARM_STATUS: u32 = 0;

    /// What the mock clock read writes into the timespec.
    static mut NOW_SEC: i32 = 0;
    static mut NOW_NSEC: i32 = 0;

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: PendingEventInsertOps,
        slab: *mut u8,
    }

    unsafe fn slab() -> *mut u8 {
        // Mapped once per process at the unique hint; every later call
        // gets the same block back because the region stays occupied.
        static mut SLAB: *mut u8 = core::ptr::null_mut();
        if SLAB.is_null() {
            match try_map_u32_slab(hints::PENDING_EVENT_INSERT, SLAB_LEN) {
                Some(p) => SLAB = p,
                None => {
                    note_missing_u32_fixture("app::pending_event_insert");
                    // Unreachable in tests: note_missing returns true,
                    // callers check availability before driving logic.
                }
            }
        }
        SLAB
    }

    unsafe fn word(offset: usize) -> u32 {
        (slab().wrapping_add(offset) as *const u32).read_volatile()
    }

    unsafe fn set_word(offset: usize, value: u32) {
        (slab().wrapping_add(offset) as *mut u32).write_volatile(value)
    }

    unsafe fn node_at(slot: usize) -> *mut PendingEventNode {
        slab().wrapping_add(POOL_OFFSET + slot * NODE_STRIDE) as *mut PendingEventNode
    }

    unsafe fn pool_slot_of(node: *mut PendingEventNode) -> usize {
        (node as usize - (slab() as usize + POOL_OFFSET)) / NODE_STRIDE
    }

    unsafe fn mutex() -> *mut PosixMutex {
        slab().wrapping_add(QUEUE_MUTEX_OFFSET) as *mut PosixMutex
    }

    /// The queue mutex must be held (owner = us) while any callee runs
    /// inside the critical section.
    unsafe fn assert_locked() {
        assert_eq!(
            (*mutex()).owner,
            crate::kernel::posix_mutex::PRE_KERNEL_THREAD,
            "the queue mutex is held during the callee"
        );
    }

    unsafe fn reset_queue() {
        core::ptr::write_bytes(slab(), 0, SLAB_LEN);
        CALLS.clear();
        INSERT_STATUS = 0;
        REARM_STATUS = 0;
        NOW_SEC = 0;
        NOW_NSEC = 0;
    }

    /// Reference model of the pop helper 0x081391f0 over the fixture
    /// free list: `head = this+0x18; node = *head; if node { *head =
    /// node->next } return node` — the helper's whole body.
    unsafe extern "C" fn mock_pop_free_node(this: *mut u8) -> *mut PendingEventNode {
        CALLS.push(Call::PopFree);
        assert_locked();
        debug_assert_eq!(this, slab(), "pop_free_node receives this");
        let head = this.wrapping_add(FREE_OFFSET) as *mut u32;
        let node = *head as usize as *mut PendingEventNode;
        if !node.is_null() {
            *head = (*node).next;
        }
        node
    }

    /// Recording clock read: pins the vtable the real construct
    /// installed, then fills the configured `{ sec, nsec }`.
    unsafe extern "C" fn mock_clock_read_time(clock: *mut u8, ts_out: *mut i32) {
        assert_locked();
        let vtable = (clock as *const u32).read();
        CALLS.push(Call::ReadTime { vtable });
        ts_out.write(NOW_SEC);
        ts_out.add(1).write(NOW_NSEC);
    }

    /// Recording insert: does not link (that is the unported helper's
    /// job); reports the configured status.
    unsafe extern "C" fn mock_insert_node(
        this: *mut u8,
        node: *mut PendingEventNode,
    ) -> u32 {
        assert_locked();
        debug_assert_eq!(this, slab(), "insert_node receives this");
        CALLS.push(Call::Insert {
            pool_slot: pool_slot_of(node),
        });
        INSERT_STATUS
    }

    unsafe extern "C" fn mock_rearm_timer(this: *mut u8) -> u32 {
        assert_locked();
        debug_assert_eq!(this, slab(), "rearm_timer receives this");
        CALLS.push(Call::Rearm);
        REARM_STATUS
    }

    fn bench() -> Option<Bench> {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let slab = unsafe { slab() };
        if slab.is_null() {
            note_missing_u32_fixture("app::pending_event_insert");
            return None;
        }
        let previous_ops = unsafe { PENDING_EVENT_INSERT_OPS };
        unsafe {
            PENDING_EVENT_INSERT_OPS = PendingEventInsertOps {
                pop_free_node: mock_pop_free_node,
                clock_read_time: mock_clock_read_time,
                insert_node: mock_insert_node,
                rearm_timer: mock_rearm_timer,
            };
            reset_queue();
        }
        Some(Bench {
            _lock: lock,
            previous_ops,
            slab,
        })
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                PENDING_EVENT_INSERT_OPS = self.previous_ops;
            }
        }
    }

    /// Chains the given slots on the free list in order, head first.
    unsafe fn plant_free_list(slots: &[usize]) {
        set_word(FREE_OFFSET, 0);
        for &slot in slots.iter().rev() {
            let node = node_at(slot);
            (*node).next = word(FREE_OFFSET);
            set_word(FREE_OFFSET, node as usize as u32);
        }
    }

    #[test]
    fn schedules_popped_node_and_returns_zero() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_free_list(&[0, 1]);
            NOW_SEC = 5;
            NOW_NSEC = 2_500_000; // now = 5*1000 + 2 = 5002 ms

            let status = pending_event_insert(bench.slab, 7, 0x36, 4, 0xabcd_1234, 100);

            assert_eq!(status, 0, "a stocked pool schedules successfully");
            let node = node_at(0);
            assert_eq!((*node).next, 0, "the link word is cleared");
            assert_eq!((*node).key, 7);
            assert_eq!((*node).tag_a, 0x36);
            assert_eq!((*node).tag_b, 4);
            assert_eq!((*node).payload, 0xabcd_1234);
            assert_eq!(
                (*node).deadline_ms,
                5102,
                "deadline = now_ms + delta_ms"
            );
            assert_eq!(
                word(FREE_OFFSET),
                node_at(1) as usize as u32,
                "the free list lost its head node"
            );
            assert_eq!(
                *CALLS,
                [
                    Call::PopFree,
                    Call::ReadTime {
                        vtable: crate::cxx::clock_source_construct::VTABLE_ADDRESS,
                    },
                    Call::Insert { pool_slot: 0 },
                    Call::Rearm,
                ],
                "pop, clock read, insert, rearm — once each, in order; \
                 the clock read saw the vtable the real construct installed"
            );
            assert_eq!((*mutex()).owner, 0, "the mutex is released afterwards");
        }
    }

    #[test]
    fn empty_pool_reports_0x0c_and_still_rearms() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            // Guard pattern: nothing may be written with the pool empty.
            core::ptr::write_bytes(node_at(0), 0xaa, NODE_STRIDE);

            let status = pending_event_insert(bench.slab, 9, 1, 2, 3, 4);

            assert_eq!(status, ERR_NO_FREE_NODE);
            assert_eq!(status, 0x0c);
            assert_eq!(
                *CALLS,
                [Call::PopFree, Call::Rearm],
                "no clock read, no insert — but the rearm still runs"
            );
            let slot = node_at(0) as *const u8;
            for i in 0..NODE_STRIDE {
                assert_eq!(slot.add(i).read(), 0xaa, "byte {i:#x} of the pool untouched");
            }
            assert_eq!((*mutex()).owner, 0, "the mutex is released on the miss path");
        }
    }

    #[test]
    fn deadline_wraps_silently_like_the_arm_add() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_free_list(&[2]);
            // sec*1000 + nsec/1000000 wraps to 0xffff_ff00 in u32.
            NOW_SEC = 4_294_967;
            NOW_NSEC = 40_000_000;

            let status = pending_event_insert(bench.slab, 1, 2, 3, 4, 0x200);

            assert_eq!(status, 0);
            assert_eq!(
                (*node_at(2)).deadline_ms,
                0x100,
                "0xffff_ff00 + 0x200 wraps to 0x100, no panic"
            );
        }
    }

    #[test]
    fn insert_failure_propagates_and_discards_rearm_status() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_free_list(&[3]);
            INSERT_STATUS = 7;
            REARM_STATUS = 9;

            let status = pending_event_insert(bench.slab, 5, 6, 7, 8, 9);

            assert_eq!(status, 7, "a nonzero insert status becomes the result");
            assert_eq!(
                *CALLS,
                [
                    Call::PopFree,
                    Call::ReadTime {
                        vtable: crate::cxx::clock_source_construct::VTABLE_ADDRESS,
                    },
                    Call::Insert { pool_slot: 3 },
                    Call::Rearm,
                ],
                "the rearm runs even when the insert failed"
            );
            assert_eq!((*mutex()).owner, 0, "the mutex is released on the failure path");
        }
    }

    #[test]
    fn rearm_status_chains_through_success() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_free_list(&[4]);
            REARM_STATUS = 9;

            let status = pending_event_insert(bench.slab, 5, 6, 7, 8, 9);

            assert_eq!(status, 9, "the rearm status replaces a zero status");
        }
    }

    #[test]
    fn field_writes_stay_inside_the_node() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_free_list(&[5]);
            // Guard bytes past the 20-byte node, inside its 0x20 slot.
            let guard = node_at(5) as *mut u8;
            for i in 0x14..NODE_STRIDE {
                guard.add(i).write(0xaa);
            }

            let status = pending_event_insert(bench.slab, 1, 0xbeef, 0xcafe, 0xdead_f00d, 0);

            assert_eq!(status, 0);
            assert_eq!((*node_at(5)).tag_a, 0xbeef);
            assert_eq!((*node_at(5)).tag_b, 0xcafe);
            for i in 0x14..NODE_STRIDE {
                assert_eq!(
                    guard.add(i).read(),
                    0xaa,
                    "guard byte {i:#x}: the halfword stores did not stray past the node"
                );
            }
        }
    }
}
