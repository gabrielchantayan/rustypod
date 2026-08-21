//! `pending_event_take` — original: `FUN_08138f14` @ 0x08138f14
//! (**188 bytes**, 0x08138f14..0x08138fd0: 184 bytes of code plus the
//! 4-byte literal @ 0x08138fcc holding the tag wildcard `0x0000ffff`;
//! Ghidra's "184 bytes" drops that trailing pool word, and the next
//! function starts at 0x08138fd0. Byte-decoded from osos.dec).
//! **45 `bl` call sites**, binary-verified by decoding every B/BL word
//! in osos.dec — all 45 unconditional `bl` (no predicated forms, no
//! tail branches), scattered across the playback/IAP cluster
//! 0x08139cb0..0x082091cc; no DATA word anywhere references the
//! address, so it is reached only by direct call.
//!
//! The take-and-cancel half of the pending-event queue embedded at the
//! start of the playback session object (the same object carries the
//! queue mutex at +0x2ac, the IAP-thread handle at +0x2c8 and its own
//! notification mutex at +0x2d8). The family, all decoded from raw
//! bytes:
//!
//! - insert `FUN_08138fd0` @ 0x08138fd0: pops a free node
//!   (`FUN_081391f0`, free-list head at +0x18), fills
//!   `{next=0, key, deadline = now_ms + delta, tag_a, tag_b, payload}`
//!   and links it in;
//! - search `FUN_08139190` @ 0x08139190: walks the intrusive chain
//!   whose head word is at +0x04 and returns **the address of the link
//!   word** pointing at the match (`&prev->next`, or `&head`), matching
//!   `key` exactly and each tag as *equal-or-wildcard* against the twin
//!   literal 0xffff @ 0x081391e8;
//! - release `FUN_0813908c` @ 0x0813908c: re-searches by the node's own
//!   key/tags, panics into [`crate::heap::veneers::heap_panic`] unless
//!   `*link == node`, unlinks, pushes the node on the +0x18 free list,
//!   returns 0;
//! - rearm `FUN_0813957c` @ 0x0813957c: reads the first live node's
//!   deadline (+0x08), converts it against the clock source and
//!   re-programs the wakeup on the IAP incoming-process thread's timer
//!   queue (mutex at thread+0x114); always returns 0.
//!
//! A node is 20 bytes (`PendingEventNode` below; layout recovered from
//! the insert/search/release trio). Entries are consumed on read: this
//! function is how the playback engine cancels a scheduled event and
//! retrieves its payload in one locked step — every caller either
//! compares the result against 0 or ignores it after feeding the taken
//! payload to the notifier `FUN_08257b60`.
//!
//! ```text
//! 08138f14  push {r4-r9, sl, lr}
//! 08138f18  mov  r9, r0              @ this
//! 08138f1c  add  r6, r0, #0x2ac      @ &this->mutex
//! 08138f20  ldr  r8, [sp, #32]       @ payload_out (5th arg)
//! 08138f2c  mov  r7, #0x52           @ default status: no such entry
//! 08138f38  bl   0x08261e20          @ posix_mutex_lock(&mutex)
//! 08138f3c  ldrh r3, [r5]            @ *tag_b
//! 08138f40  ldrh r2, [r4]            @ *tag_a
//! 08138f4c  bl   0x08139190          @ link = find(this, key, *tag_a, *tag_b)
//! 08138f50  cmp  r0, #0
//! 08138f54  beq  0x08138fbc          @ not found -> unlock, return 0x52
//! 08138f58  ldr  r1, [r0]            @ node = *link
//! 08138f5c  cmp  r1, #0
//! 08138f60  bleq 0x08030f44          @ defensive heap_panic (unreachable)
//! 08138f6c  cmp  r2, r3              @ *tag_a == 0xffff?
//! 08138f70  ldrheq r1, [r1, #12]
//! 08138f74  strheq r1, [r4]          @   *tag_a = node->tag_a
//! 08138f7c  cmp  r1, r3              @ *tag_b == 0xffff?
//! 08138f84  ldrheq r1, [r1, #14]
//! 08138f88  strheq r1, [r5]          @   *tag_b = node->tag_b
//! 08138f8c  cmp  r8, #0
//! 08138f98  strne r1, [r8]           @   *payload_out = node->payload
//! 08138fa4  bl   0x0813908c          @ status = release(this, node)
//! 08138fa8  movs r7, r0
//! 08138fac  bne  0x08138fbc          @ nonzero -> skip the rearm
//! 08138fb4  bl   0x0813957c          @ status = rearm(this)
//! 08138fbc  mov  r0, r6
//! 08138fc0  bl   0x08261e24          @ posix_mutex_unlock(&mutex)
//! 08138fc8  pop  {r4-r9, sl, pc}     @ return status
//! 08138fcc  .word 0x0000ffff         @ the wildcard literal
//! ```
//!
//! On the firmware release/rearm pair the plumbed-through status can
//! only be 0 (release returns 0 or panics; rearm always returns 0), so
//! the observable contract is **0 = entry taken, 0x52 = no matching
//! entry** — but the port keeps the original's general chaining because
//! both callees sit behind the ops seam below.
//!
//! # Deviations
//!
//! - **The three callees are unported** and dispatch through
//!   [`PENDING_EVENT_TAKE_OPS`] (the `ui/table_slot_allocate.rs`
//!   pattern): target builds transmute the ROM addresses
//!   0x08139190/0x0813908c/0x0813957c; host defaults are inert stubs
//!   (NULL / 0) and every test installs a recording reference model.
//! - The lock/unlock go through the canonical ported
//!   [`crate::kernel::posix_mutex::posix_mutex_lock`]/`_unlock`
//!   directly — the original calls the 4-byte alias veneers
//!   0x08261e20/0x08261e24, which names.yaml resolves to those symbols
//!   (no separate Rust symbol exists for a bare `b` alias).
//! - The original reloads `node` from the link word before each use
//!   (the compiler cannot prove `*tag_a`/`*tag_b` stores do not alias
//!   it); the port loads it once. No observable difference for any
//!   non-aliased argument set, which is the only kind callers can pass
//!   (stack slots vs heap nodes).
//! - The defensive `node == NULL` branch calls the ported
//!   [`crate::heap::veneers::heap_panic`] exactly like the original's
//!   `bleq 0x08030f44`. It is unreachable through find-link's contract
//!   (a returned link always points at a non-null node) and is not
//!   exercised on host — `heap_panic` runs the raise/exit/terminate
//!   chain, whose default terminate spins (the
//!   `util/service_manager_get.rs` precedent).

use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};

/// Offset of the queue's [`PosixMutex`] inside the session object
/// (original `add r6, r0, #0x2ac`).
pub const QUEUE_MUTEX_OFFSET: usize = 0x2ac;

/// Status returned when no live entry matches `(key, tag_a, tag_b)`
/// (original `mov r7, #0x52`). The insert sibling uses 0x0c for "no
/// free node", so these are module-level codes, not errno values.
pub const ERR_NO_PENDING_ENTRY: u32 = 0x52;

/// Tag wildcard-and-fill sentinel: an input tag of 0xffff matches any
/// node tag and is replaced by the found node's value (original literal
/// @ 0x08138fcc, twin @ 0x081391e8 inside the search).
pub const WILDCARD_TAG: u16 = 0xffff;

/// One queued entry, 20 bytes on the 32-bit target. Layout recovered
/// from insert 0x08138fd0 (which writes every field), search 0x08139190
/// (which compares +0x04/+0x0c/+0x0e) and this function (which reads
/// +0x0c/+0x0e/+0x10). `next` is a target pointer word, hence `u32`.
#[repr(C)]
pub struct PendingEventNode {
    /// +0x00 — next entry, or 0 end-of-chain (also the free-list link).
    pub next: u32,
    /// +0x04 — lookup key (observed values: track indices).
    pub key: u32,
    /// +0x08 — absolute deadline in milliseconds (insert stores
    /// now + delta; rearm subtracts the current time from it).
    pub deadline_ms: u32,
    /// +0x0c — first tag halfword (wildcard-filled by this function).
    pub tag_a: u16,
    /// +0x0e — second tag halfword (wildcard-filled by this function).
    pub tag_b: u16,
    /// +0x10 — payload word handed to the taker.
    pub payload: u32,
}

const _: () = assert!(core::mem::size_of::<PendingEventNode>() == 0x14);
const _: () = assert!(core::mem::offset_of!(PendingEventNode, key) == 0x04);
const _: () = assert!(core::mem::offset_of!(PendingEventNode, deadline_ms) == 0x08);
const _: () = assert!(core::mem::offset_of!(PendingEventNode, tag_a) == 0x0c);
const _: () = assert!(core::mem::offset_of!(PendingEventNode, tag_b) == 0x0e);
const _: () = assert!(core::mem::offset_of!(PendingEventNode, payload) == 0x10);

/// Indirect dispatch for the three unported callees (see the module
/// header). Host tests install recording models; a later port of each
/// callee replaces its default without touching this caller.
#[derive(Clone, Copy)]
pub struct PendingEventTakeOps {
    /// Search 0x08139190 `(this, key, tag_a, tag_b)` -> address of the
    /// link word pointing at the first match, or NULL. Both tags match
    /// as equal-or-0xffff; the key must be exact.
    pub find_link: unsafe extern "C" fn(
        this: *mut u8,
        key: u32,
        tag_a: u16,
        tag_b: u16,
    ) -> *mut u32,
    /// Release 0x0813908c `(this, node)`: unlink the node from the live
    /// chain and push it on the +0x18 free list. Returns 0, or panics
    /// on a corrupt queue.
    pub release_node: unsafe extern "C" fn(this: *mut u8, node: *mut PendingEventNode) -> u32,
    /// Rearm 0x0813957c `(this)`: re-program the IAP-thread wakeup from
    /// the new head's deadline. Always returns 0 on firmware.
    pub rearm_timer: unsafe extern "C" fn(this: *mut u8) -> u32,
}

/// Target default: the ROM search.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_find_link(
    this: *mut u8,
    key: u32,
    tag_a: u16,
    tag_b: u16,
) -> *mut u32 {
    let f: unsafe extern "C" fn(*mut u8, u32, u16, u16) -> *mut u32 =
        core::mem::transmute(0x0813_9190usize);
    f(this, key, tag_a, tag_b)
}

/// Host default: inert — the tests install their own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_find_link(
    _this: *mut u8,
    _key: u32,
    _tag_a: u16,
    _tag_b: u16,
) -> *mut u32 {
    core::ptr::null_mut()
}

/// Target default: the ROM release path.
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_release_node(
    this: *mut u8,
    node: *mut PendingEventNode,
) -> u32 {
    let f: unsafe extern "C" fn(*mut u8, *mut PendingEventNode) -> u32 =
        core::mem::transmute(0x0813_908cusize);
    f(this, node)
}

/// Host default: inert — the tests install their own model.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_release_node(
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
pub const DEFAULT_PENDING_EVENT_TAKE_OPS: PendingEventTakeOps = PendingEventTakeOps {
    find_link: firmware_find_link,
    release_node: firmware_release_node,
    rearm_timer: firmware_rearm_timer,
};

/// The active callee set, read through `read_volatile` so LLVM cannot
/// fold the indirect calls to the defaults.
pub static mut PENDING_EVENT_TAKE_OPS: PendingEventTakeOps =
    DEFAULT_PENDING_EVENT_TAKE_OPS;

#[inline(always)]
fn pending_event_take_ops() -> PendingEventTakeOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PENDING_EVENT_TAKE_OPS)) }
}

/// pending_event_take — original: `FUN_08138f14` @ 0x08138f14 (188
/// bytes including the trailing wildcard literal; 45 `bl` call sites,
/// binary-verified — see the module header).
///
/// Under the queue mutex at `this + 0x2ac`: find the first live entry
/// matching `key` exactly and `*tag_a`/`*tag_b` equal-or-wildcard,
/// fill each wildcarded tag from the entry, copy the payload word out
/// when `payload_out` is non-null, unlink the entry onto the free
/// list, re-arm the deadline timer, and report 0. With no match, leave
/// all three out-parameters untouched and report
/// [`ERR_NO_PENDING_ENTRY`] (0x52).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_event_take(
    this: *mut u8,
    key: u32,
    tag_a: *mut u16,
    tag_b: *mut u16,
    payload_out: *mut u32,
) -> u32 {
    let mut status: u32 = ERR_NO_PENDING_ENTRY;
    let mutex = this.wrapping_add(QUEUE_MUTEX_OFFSET) as *mut PosixMutex;
    posix_mutex_lock(mutex);
    let ops = pending_event_take_ops();
    let link = (ops.find_link)(this, key, *tag_a, *tag_b);
    if !link.is_null() {
        let node = *link as usize as *mut PendingEventNode;
        if node.is_null() {
            crate::heap::veneers::heap_panic();
        }
        if *tag_a == WILDCARD_TAG {
            *tag_a = (*node).tag_a;
        }
        if *tag_b == WILDCARD_TAG {
            *tag_b = (*node).tag_b;
        }
        if !payload_out.is_null() {
            *payload_out = (*node).payload;
        }
        status = (ops.release_node)(this, node);
        if status == 0 {
            status = (ops.rearm_timer)(this);
        }
    }
    posix_mutex_unlock(mutex);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab, hints};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test here: they share one fixture slab (the
    /// mapper never unmaps, so a second mapping would land above 4 GiB
    /// and skip silently) and swap the global ops table.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Fixture layout inside the mapped slab:
    ///
    /// ```text
    /// S+0x000  session object; head word at S+0x004, free-list head at
    ///          S+0x018, PosixMutex at S+0x2ac
    /// S+0x300  node pool: NODE_SLOTS entries of 0x20 bytes each
    /// ```
    const HEAD_OFFSET: usize = 0x004;
    const FREE_OFFSET: usize = 0x018;
    const POOL_OFFSET: usize = 0x300;
    const NODE_STRIDE: usize = 0x20;
    const NODE_SLOTS: usize = 8;
    const SLAB_LEN: usize = POOL_OFFSET + NODE_SLOTS * NODE_STRIDE;

    /// Recorded callee invocations, in order.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Call {
        FindLink { key: u32, tag_a: u16, tag_b: u16 },
        Release { node_key: u32 },
        Rearm,
    }

    static mut CALLS: Vec<Call> = Vec::new();

    /// What the mock release slot reports.
    static mut RELEASE_STATUS: u32 = 0;

    /// What the mock rearm slot reports.
    static mut REARM_STATUS: u32 = 0;

    struct Bench {
        _lock: MutexGuard<'static, ()>,
        previous_ops: PendingEventTakeOps,
        slab: *mut u8,
    }

    unsafe fn slab() -> *mut u8 {
        // Mapped once per process at the unique hint; every later call
        // gets the same block back because the region stays occupied.
        static mut SLAB: *mut u8 = core::ptr::null_mut();
        if SLAB.is_null() {
            match try_map_u32_slab(hints::PENDING_EVENT_TAKE, SLAB_LEN) {
                Some(p) => SLAB = p,
                None => {
                    note_missing_u32_fixture("app::pending_event_take");
                    // Unreachable in tests: note_missing returns true,
                    // callers check availability before driving logic.
                }
            }
        }
        SLAB
    }

    unsafe fn available() -> bool {
        !slab().is_null()
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

    unsafe fn mutex() -> *mut PosixMutex {
        slab().wrapping_add(QUEUE_MUTEX_OFFSET) as *mut PosixMutex
    }

    unsafe fn reset_queue() {
        core::ptr::write_bytes(slab(), 0, SLAB_LEN);
        CALLS.clear();
        RELEASE_STATUS = 0;
        REARM_STATUS = 0;
    }

    unsafe extern "C" fn mock_find_link(
        this: *mut u8,
        key: u32,
        tag_a: u16,
        tag_b: u16,
    ) -> *mut u32 {
        CALLS.push(Call::FindLink { key, tag_a, tag_b });
        let base = this as usize;
        debug_assert_eq!(base, slab() as usize, "find_link receives this");
        // Reference model of FUN_08139190 over the fixture chain: walk
        // the intrusive list, match key exactly and each tag as
        // equal-or-wildcard, return the ADDRESS OF THE LINK WORD.
        let mut cursor: *mut u32 = slab().wrapping_add(HEAD_OFFSET) as *mut u32;
        while *cursor != 0 {
            let node = *cursor as usize as *mut PendingEventNode;
            if (*node).key == key
                && (tag_a == (*node).tag_a || tag_a == WILDCARD_TAG)
                && (tag_b == (*node).tag_b || tag_b == WILDCARD_TAG)
            {
                // The queue mutex must be held while a caller is
                // inside the critical section (owner = us).
                assert_eq!(
                    (*(this.wrapping_add(QUEUE_MUTEX_OFFSET) as *mut PosixMutex)).owner,
                    crate::kernel::posix_mutex::PRE_KERNEL_THREAD,
                    "the queue mutex is held during find_link"
                );
                return cursor;
            }
            cursor = core::ptr::addr_of_mut!((*node).next);
        }
        core::ptr::null_mut()
    }

    unsafe extern "C" fn mock_release_node(
        this: *mut u8,
        node: *mut PendingEventNode,
    ) -> u32 {
        CALLS.push(Call::Release {
            node_key: (*node).key,
        });
        // Reference model of FUN_0813908c: unlink via a fresh search,
        // then push the node on the free list.
        let mut cursor: *mut u32 = this.wrapping_add(HEAD_OFFSET) as *mut u32;
        loop {
            let linked = *cursor as usize as *mut PendingEventNode;
            if linked.is_null() {
                panic!("release: node is not on the live chain");
            }
            if linked == node {
                break;
            }
            cursor = core::ptr::addr_of_mut!((*linked).next);
        }
        *cursor = (*node).next;
        (*node).next = word(FREE_OFFSET);
        set_word(FREE_OFFSET, node as usize as u32);
        RELEASE_STATUS
    }

    unsafe extern "C" fn mock_rearm_timer(_this: *mut u8) -> u32 {
        CALLS.push(Call::Rearm);
        REARM_STATUS
    }

    fn bench() -> Option<Bench> {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let slab = unsafe { slab() };
        if slab.is_null() {
            note_missing_u32_fixture("app::pending_event_take");
            return None;
        }
        let previous_ops = unsafe { PENDING_EVENT_TAKE_OPS };
        unsafe {
            PENDING_EVENT_TAKE_OPS = PendingEventTakeOps {
                find_link: mock_find_link,
                release_node: mock_release_node,
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
                PENDING_EVENT_TAKE_OPS = self.previous_ops;
            }
        }
    }

    /// Plants one live entry in slot `slot` and links it as the only
    /// list element.
    unsafe fn plant_entry(slot: usize, key: u32, tag_a: u16, tag_b: u16, payload: u32) {
        let node = node_at(slot);
        *node = PendingEventNode {
            next: 0,
            key,
            deadline_ms: 0x1000,
            tag_a,
            tag_b,
            payload,
        };
        set_word(HEAD_OFFSET, node as usize as u32);
    }

    #[test]
    fn takes_matching_entry_fills_wildcards_and_returns_zero() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_entry(0, 7, 0x36, 4, 0xabcd_1234);
            let mut tag_a: u16 = WILDCARD_TAG;
            let mut tag_b: u16 = WILDCARD_TAG;
            let mut payload: u32 = 0;

            let status = pending_event_take(bench.slab, 7, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, 0, "a matching entry is reported as taken");
            assert_eq!(tag_a, 0x36, "wildcard tag_a is filled from the entry");
            assert_eq!(tag_b, 4, "wildcard tag_b is filled from the entry");
            assert_eq!(payload, 0xabcd_1234, "the payload word is copied out");
            assert_eq!(
                *CALLS,
                [
                    Call::FindLink {
                        key: 7,
                        tag_a: WILDCARD_TAG,
                        tag_b: WILDCARD_TAG
                    },
                    Call::Release { node_key: 7 },
                    Call::Rearm,
                ],
                "find, then release, then rearm — once each"
            );
            // The entry left the live chain and sits on the free list.
            assert_eq!(word(HEAD_OFFSET), 0, "the live chain is empty again");
            assert_eq!(
                word(FREE_OFFSET),
                node_at(0) as usize as u32,
                "the released node heads the free list"
            );
            assert_eq!((*mutex()).owner, 0, "the mutex is released afterwards");
        }
    }

    #[test]
    fn empty_queue_reports_no_such_entry_and_touches_nothing() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            let mut tag_a: u16 = 0x11;
            let mut tag_b: u16 = 0x22;
            let mut payload: u32 = 0x33;

            let status = pending_event_take(bench.slab, 9, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, ERR_NO_PENDING_ENTRY);
            assert_eq!(status, 0x52);
            assert_eq!(tag_a, 0x11, "tag_a is untouched without a match");
            assert_eq!(tag_b, 0x22, "tag_b is untouched without a match");
            assert_eq!(payload, 0x33, "payload_out is untouched without a match");
            assert_eq!(*CALLS, [Call::FindLink { key: 9, tag_a: 0x11, tag_b: 0x22 }]);
            assert_eq!((*mutex()).owner, 0, "the mutex is released on the miss path");
        }
    }

    #[test]
    fn exact_tags_are_preserved_not_overwritten() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_entry(1, 3, 0x38, 0x10, 0xfeed_beef);
            let mut tag_a: u16 = 0x38;
            let mut tag_b: u16 = 0x10;
            let mut payload: u32 = 0;

            let status = pending_event_take(bench.slab, 3, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, 0);
            assert_eq!(tag_a, 0x38, "an exact tag_a passes through unchanged");
            assert_eq!(tag_b, 0x10, "an exact tag_b passes through unchanged");
            assert_eq!(payload, 0xfeed_beef);
        }
    }

    #[test]
    fn only_the_wildcard_side_is_filled() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_entry(2, 12, 0x3b, 2, 5);
            let mut tag_a: u16 = WILDCARD_TAG;
            let mut tag_b: u16 = 2;
            let mut payload: u32 = 0;

            let status = pending_event_take(bench.slab, 12, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, 0);
            assert_eq!(tag_a, 0x3b, "the wildcarded side is filled");
            assert_eq!(tag_b, 2, "the exact side is kept");
        }
    }

    #[test]
    fn null_payload_out_is_allowed() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_entry(3, 1, 0x36, 0x38, 0xffff_ffff);
            let mut tag_a: u16 = WILDCARD_TAG;
            let mut tag_b: u16 = WILDCARD_TAG;

            let status = pending_event_take(bench.slab, 1, &mut tag_a, &mut tag_b, core::ptr::null_mut());

            assert_eq!(status, 0, "a NULL payload_out skips the copy, not the take");
            assert_eq!(tag_a, 0x36);
            assert_eq!(tag_b, 0x38);
            assert_eq!(word(HEAD_OFFSET), 0, "the entry is still consumed");
        }
    }

    #[test]
    fn release_status_propagates_and_skips_the_rearm() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_entry(4, 42, 1, 2, 3);
            RELEASE_STATUS = 7;
            let mut tag_a: u16 = WILDCARD_TAG;
            let mut tag_b: u16 = WILDCARD_TAG;
            let mut payload: u32 = 0;

            let status = pending_event_take(bench.slab, 42, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, 7, "a nonzero release status becomes the result");
            assert_eq!(
                *CALLS,
                [
                    Call::FindLink { key: 42, tag_a: WILDCARD_TAG, tag_b: WILDCARD_TAG },
                    Call::Release { node_key: 42 },
                ],
                "rearm is skipped when release fails"
            );
            assert_eq!(tag_a, 1, "the tags are still filled before release");
            assert_eq!(tag_b, 2);
        }
    }

    #[test]
    fn rearm_status_propagates_when_release_succeeds() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_entry(5, 8, 9, 10, 11);
            REARM_STATUS = 9;
            let mut tag_a: u16 = WILDCARD_TAG;
            let mut tag_b: u16 = WILDCARD_TAG;
            let mut payload: u32 = 0;

            let status = pending_event_take(bench.slab, 8, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, 9, "the rearm status chains through zero-release");
        }
    }

    #[test]
    fn find_link_sees_the_raw_input_tags() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            // No entry will match; the point is what the seam receives.
            let mut tag_a: u16 = 0xbeef;
            let mut tag_b: u16 = 0xcafe;

            pending_event_take(bench.slab, 77, &mut tag_a, &mut tag_b, core::ptr::null_mut());

            assert_eq!(
                CALLS[0],
                Call::FindLink { key: 77, tag_a: 0xbeef, tag_b: 0xcafe },
                "the search receives the input tag values verbatim"
            );
        }
    }

    #[test]
    fn second_entry_in_chain_is_found_and_unlinked_in_place() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_entry(0, 20, 1, 1, 100);
            plant_entry(1, 21, 2, 2, 200);
            // Chain head -> slot0 -> slot1 (plant_entry re-points the
            // head at each new node, so rebuild the intended order).
            set_word(HEAD_OFFSET, node_at(0) as usize as u32);
            (*node_at(0)).next = node_at(1) as usize as u32;

            let mut tag_a: u16 = WILDCARD_TAG;
            let mut tag_b: u16 = WILDCARD_TAG;
            let mut payload: u32 = 0;

            let status = pending_event_take(bench.slab, 21, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, 0);
            assert_eq!(payload, 200);
            assert_eq!(
                word(HEAD_OFFSET),
                node_at(0) as usize as u32,
                "the predecessor keeps pointing at the (now empty) chain end"
            );
            assert_eq!((*node_at(0)).next, 0, "slot0 is the sole survivor");
            assert_eq!(
                word(FREE_OFFSET),
                node_at(1) as usize as u32,
                "the taken node was pushed on the free list"
            );
        }
    }

    #[test]
    fn wildcard_matches_entries_whose_tag_differs() {
        let mut bench = match bench() {
            Some(b) => b,
            None => return,
        };
        let bench = &mut bench;
        unsafe {
            plant_entry(6, 30, 0x1234, 0x5678, 99);
            let mut tag_a: u16 = WILDCARD_TAG;
            let mut tag_b: u16 = WILDCARD_TAG;
            let mut payload: u32 = 0;

            let status = pending_event_take(bench.slab, 30, &mut tag_a, &mut tag_b, &mut payload);

            assert_eq!(status, 0, "0xffff matches regardless of the stored tags");
            assert_eq!(tag_a, 0x1234);
            assert_eq!(tag_b, 0x5678);
            assert_eq!(payload, 99);
        }
    }
}
