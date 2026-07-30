//! Port of the block-manager client's **populate** op — the fill half
//! of the client machinery (`client_erase`, heap/client_erase.rs, runs
//! the same deque the other way), and the verdict `block_deque_fill`
//! (heap/block_deque.rs) returns:
//!
//! - `client_populate` — original: `FUN_081fc298` @ 0x081fc298 (348
//!   bytes; 2 `bl` call sites @ 0x081a8434 (FUN_081a83b8) and
//!   0x082140b0 (`block_deque_fill`), binary-verified). Under the
//!   client's own mutex (client + 0x24 — NOT the pool base's +0x8 one —
//!   the same unported C++ recursive-mutex pair @ 0x082e8390 /
//!   0x082e83d8 via the alias thunks @ 0x082621a8 / 0x082621ac that
//!   client_erase/client_commit use) it:
//!   1. gates on headroom: either the client's 0x40000 state-flag bit
//!      is set (the real `state_flags_contain` @ 0x081fc3f4,
//!      util/state_flags.rs — called TWICE, once per gate, faithfully),
//!      or the produced/expected counters at client +0x18/+0x1c already
//!      cover `count` more blocks (signed: `(+0x1c - +0x18) - count`
//!      must not be negative — `subs`/`bmi`);
//!   2. when the flag is set, additionally requires
//!      `count <= +0x50 - +0x18` (unsigned — `cmpne`/`bcc`; the
//!      subtraction itself is predicated `ldrne/subne`);
//!   3. asks the block manager for the blocks through the manager
//!      pointer at client +0x4: 0x0818b0c4(manager, client + 0x8,
//!      count) — a mutex bracket (manager +0x148) around the
//!      0x0818b108 body; zero refuses the whole op;
//!   4. walks the client's region list (head at client +0xc; node:
//!      +0x4 next, +0xc region object) pushing one 0x28-byte region
//!      element per block onto the deque: the node's region is
//!      copy-constructed into a stack temp (0x08280464; a NULL node
//!      first default-constructs a second temp via 0x082804b8 and
//!      destroys it via 0x082804fc), the deque is grown when it is
//!      empty or its end segment is spent (0x083dda08), the temp is
//!      copy-constructed onto `end.cur` (only when `end.cur` is
//!      non-NULL — the advance below runs regardless), then
//!      `end.cur += 0x28`, `count += 1`, the temp is destroyed, and
//!      the node advances through +0x4. A NULL node AT THE ADVANCE
//!      (list shorter than `count`) tail-calls `heap_panic`
//!      @ 0x08030f44 (heap/veneers.rs, non-returning) — one default
//!      element has already been pushed, faithfully. The snapshotted
//!      head node is also spilled to the stack (`str r0,[sp,#0x50]`)
//!      and never read — dead store, kept as `_first_node`.
//!   Success returns 1, every refusal path 0 — exactly the 0/1 verdict
//!   `block_deque_fill` forwards.
//!
//! # Deviations
//!
//! - **Mutex**: client + 0x24 is locked/unlocked through
//!   block_region.rs's `REGION_MUTEX_OPS` (one boundary for the one
//!   unported original pair — the client_erase.rs/client_commit.rs
//!   precedent; defaults are documented no-ops, no mutual exclusion).
//!   The offset constant is shared: `client_erase::CLIENT_MUTEX_OFFSET`.
//! - **Headroom probes** dispatch to the REAL `state_flags_contain`
//!   (0x081fc3f4 is its canonical address, not a copy) — direct calls.
//! - **Emptiness check**: the original `bl 0x083d75b0` (a byte-identical
//!   copy of cxx/templates.rs's `container_is_empty`) reads the count
//!   word at deque +0x20. The port reads the typed [`BlockDeque::count`]
//!   field instead — identical on the 32-bit target, correct under the
//!   wider 64-bit host layout where the count sits at +0x40 (the
//!   block_deque.rs host-layout lesson; the copy cannot be called
//!   verbatim on host for exactly that reason).
//! - **Unported callees** dispatch through [`CLIENT_POPULATE_OPS`]
//!   (house ops-slot pattern, indirect `blx` in place of `bl`): the
//!   manager block hand-out @ 0x0818b0c4, the deque growth @ 0x083dda08,
//!   and the region object ctor/copy/dtor triple @ 0x082804b8 /
//!   0x08280464 / 0x082804fc (their return values are discarded by the
//!   original, so the region slots return `()`). The defaults are
//!   documented: the manager stub refuses (0) — the no-manager contract
//!   of block_deque.rs's `stub_client_populate` — so with the wired
//!   defaults the loop is unreachable and the no-op grow/region stubs
//!   never run; the port then reports the same refusal 0 the old stub
//!   faked wholesale.
//! - **Shipped wiring**: block_deque.rs is off-limits in this shared
//!   tree (its `stub_client_populate` stays the POOL_BASE_OPS default —
//!   behavior-identical under the no-manager defaults above), so the
//!   port is exercised through the slot by heap/mod.rs's integration
//!   tests, which install it plus recorders over the ops table.
//! - **Client/list fields** are read by literal byte offset as u32
//!   words (the client object is 0x170 bytes of unported ctor layout,
//!   ctor 0x081e6b34 — the util/state_flags.rs precedent); the pointer
//!   fields (manager +0x4, list head +0xc, node +0x4/+0xc) are u32
//!   target pointers zero-extended — exact on target, and host tests
//!   keep their fake objects below 4 GiB.
//! - The loop counter is unsigned (`bcc`), like the original.

use crate::heap::block_deque::{BlockDeque, DEQUE_ELEM_SIZE};
use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::heap::client_erase::CLIENT_MUTEX_OFFSET;
use crate::heap::veneers::heap_panic;
use crate::util::state_flags::state_flags_contain;

/// State-flag mask of both headroom probes (original: `mov r1,
/// #0x40000` ahead of each `bl 0x081fc3f4`).
const HEADROOM_MASK: u32 = 0x40000;

/// Byte offset of the manager pointer inside the client object
/// (original: `ldr r0, [r9, #0x4]` ahead of the 0x0818b0c4 call).
const CLIENT_MANAGER_OFFSET: usize = 0x4;

/// Byte offset of the client state word passed by address to the
/// manager call (original: `add r1, r9, #0x8`).
const CLIENT_STATE_OFFSET: usize = 0x8;

/// Byte offset of the region-list head inside the client object
/// (original: `ldr r0, [r9, #0xc]`).
const CLIENT_REGION_LIST_OFFSET: usize = 0xc;

/// Byte offset of the produced counter (original: `ldr r0, [r9, #0x18]`).
const CLIENT_PRODUCED_OFFSET: usize = 0x18;

/// Byte offset of the expected counter (original: `ldr r1, [r9, #0x1c]`).
const CLIENT_EXPECTED_OFFSET: usize = 0x1c;

/// Byte offset of the head counter the flagged path checks against
/// (original: `ldrne r1, [r9, #0x50]`).
const CLIENT_HEAD_OFFSET: usize = 0x50;

/// Byte offset of the next pointer inside a region-list node
/// (original: `ldrne r5, [r5, #0x4]`).
const NODE_NEXT_OFFSET: usize = 0x4;

/// Byte offset of the region object pointer inside a node (original:
/// `ldr r1, [r5, #0xc]`).
const NODE_REGION_OFFSET: usize = 0xc;

/// One 0x28-byte region object temp (the original's `auStack_70` /
/// `auStack_48` stack slots); five pointer-width words on any host.
type RegionTemp = [usize; 5];

/// Reads one u32 word of the opaque client/node layout (see the module
/// header — literal byte offsets, `read_unaligned` for the host, the
/// client_erase.rs idiom).
#[inline(always)]
unsafe fn word(object: *mut u8, offset: usize) -> u32 {
    (object.add(offset) as *const u32).read_unaligned()
}

/// Reads one u32 target pointer of the opaque layout, zero-extended
/// (exact on the 32-bit target; host fixtures live below 4 GiB).
#[inline(always)]
unsafe fn ptr_word(object: *mut u8, offset: usize) -> *mut u8 {
    word(object, offset) as usize as *mut u8
}

/// Indirect dispatch table for the unported callees (see the module
/// header for each default's contract).
#[derive(Clone, Copy)]
pub struct ClientPopulateOps {
    /// Manager block hand-out @ 0x0818b0c4 `(manager, client + 0x8,
    /// count)`: nonzero hands `count` blocks to the client, zero
    /// refuses the whole populate.
    pub manager_take_blocks:
        unsafe extern "C" fn(manager: *mut u8, client_state: *mut u8, count: usize) -> i32,
    /// Deque growth @ 0x083dda08 `(deque)`: installs a fresh segment
    /// and re-anchors the iterators (both of them, on an empty deque).
    pub deque_grow: unsafe extern "C" fn(deque: *mut BlockDeque),
    /// Region default ctor @ 0x082804b8 `(dst)` — the NULL-node temp.
    pub region_default: unsafe extern "C" fn(dst: *mut u8),
    /// Region copy ctor @ 0x08280464 `(dst, src)`.
    pub region_copy: unsafe extern "C" fn(dst: *mut u8, src: *const u8),
    /// Region dtor @ 0x082804fc `(obj)`.
    pub region_destroy: unsafe extern "C" fn(obj: *mut u8),
}

/// Default manager stub: no block manager — no blocks to take, refuse
/// (the no-manager contract of block_deque.rs's `stub_client_populate`;
/// the refusal makes the whole populate report 0 before the loop, so
/// the stubs below are unreachable in the wired configuration).
unsafe extern "C" fn stub_manager_take_blocks(
    _manager: *mut u8,
    _client_state: *mut u8,
    _count: usize,
) -> i32 {
    0
}

/// Default growth/region stubs: see [`stub_manager_take_blocks`].
unsafe extern "C" fn stub_deque_grow(_deque: *mut BlockDeque) {}

unsafe extern "C" fn stub_region_default(_dst: *mut u8) {}

unsafe extern "C" fn stub_region_copy(_dst: *mut u8, _src: *const u8) {}

unsafe extern "C" fn stub_region_destroy(_obj: *mut u8) {}

/// Wired defaults (documented no-ops/no-manager refusal until the
/// block-manager machinery is ported).
pub(crate) const DEFAULT_CLIENT_POPULATE_OPS: ClientPopulateOps = ClientPopulateOps {
    manager_take_blocks: stub_manager_take_blocks,
    deque_grow: stub_deque_grow,
    region_default: stub_region_default,
    region_copy: stub_region_copy,
    region_destroy: stub_region_destroy,
};

/// The active implementation table. Written once at init on target;
/// host tests swap in recorders and restore the defaults.
pub static mut CLIENT_POPULATE_OPS: ClientPopulateOps = DEFAULT_CLIENT_POPULATE_OPS;

/// Reads one op (volatile — same rationale as every dispatch table: a
/// build in which nothing swaps it must not constant-fold the default
/// in).
macro_rules! op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLIENT_POPULATE_OPS.$field)) }
    };
}

/// Reads one op of the shared C++ mutex boundary (block_region.rs).
macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// client_populate — original: `FUN_081fc298` @ 0x081fc298 (348 bytes).
///
/// Fills `deque` with `count` block descriptors from the client's
/// region list under the client's mutex, after the headroom gates and
/// the manager hand-out (see the module header for the full protocol).
/// Nonzero on success — `block_deque_fill`'s return value.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_populate(
    client: *mut u8,
    count: usize,
    deque: *mut BlockDeque,
) -> i32 {
    let mutex = client.add(CLIENT_MUTEX_OFFSET);
    (mutex_op!(lock))(mutex);
    let mut result: i32 = 0;
    'populate: {
        // Gate 1: the flag, or the counters already cover `count`
        // (signed — `subs`/`bmi`).
        if state_flags_contain(client, HEADROOM_MASK) == 0 {
            let covered = (word(client, CLIENT_EXPECTED_OFFSET) as i32)
                .wrapping_sub(word(client, CLIENT_PRODUCED_OFFSET) as i32)
                .wrapping_sub(count as u32 as i32);
            if covered < 0 {
                break 'populate;
            }
        }
        // Gate 2: the second probe; when flagged, the head counter must
        // cover `count` too (unsigned — `cmpne`/`bcc`).
        let headroom = state_flags_contain(client, HEADROOM_MASK);
        let mut head: u32 = 0;
        if headroom != 0 {
            head = word(client, CLIENT_HEAD_OFFSET)
                .wrapping_sub(word(client, CLIENT_PRODUCED_OFFSET));
        }
        if headroom != 0 && (count as u32) > head {
            break 'populate;
        }
        // The manager hand-out: 0x0818b0c4(*(client+4), client+8, count).
        let manager = ptr_word(client, CLIENT_MANAGER_OFFSET);
        if (op!(manager_take_blocks))(manager, client.add(CLIENT_STATE_OFFSET), count) == 0 {
            break 'populate;
        }
        let mut node = ptr_word(client, CLIENT_REGION_LIST_OFFSET);
        // The original's `str r0, [sp, #0x50]` — a dead spill of the
        // head node, kept for the frame's shape.
        let _first_node = node;
        let mut pushed: usize = 0;
        while pushed < count {
            let mut scratch: RegionTemp = [0; 5];
            let mut temp: RegionTemp = [0; 5];
            if node.is_null() {
                (op!(region_default))(scratch.as_mut_ptr() as *mut u8);
                (op!(region_copy))(temp.as_mut_ptr() as *mut u8, scratch.as_ptr() as *const u8);
                (op!(region_destroy))(scratch.as_mut_ptr() as *mut u8);
            } else {
                let region = ptr_word(node, NODE_REGION_OFFSET);
                (op!(region_copy))(temp.as_mut_ptr() as *mut u8, region as *const u8);
            }
            // Empty deque or spent end segment: grow first (the
            // original's emptiness check is the 0x083d75b0 copy of
            // container_is_empty; typed field here — module header).
            if (*deque).count == 0 || (*deque).end.cur == (*deque).end.seg_end {
                (op!(deque_grow))(deque);
            }
            if !(*deque).end.cur.is_null() {
                (op!(region_copy))((*deque).end.cur, temp.as_ptr() as *const u8);
            }
            (*deque).end.cur = (*deque).end.cur.wrapping_add(DEQUE_ELEM_SIZE);
            (*deque).count = (*deque).count.wrapping_add(1);
            (op!(region_destroy))(temp.as_mut_ptr() as *mut u8);
            pushed = pushed.wrapping_add(1);
            if node.is_null() {
                // List shorter than `count`: non-returning, exactly as
                // the original's `bl 0x08030f44`.
                heap_panic();
            }
            node = ptr_word(node, NODE_NEXT_OFFSET);
        }
        result = 1;
    }
    (mutex_op!(unlock))(mutex);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_deque::{deque_iter_init, DEQUE_SEG_BYTES};
    use crate::heap::block_region::{RegionMutexOps, DEFAULT_REGION_MUTEX_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes this module's slot swaps (tests run serially —
    /// RUST_TEST_THREADS=1 — so one lock is enough, the client_erase.rs
    /// precedent).
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// One shared, ordered event log across every mocked boundary.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        Lock(usize),
        Unlock(usize),
        TakeBlocks { manager: usize, state: usize, count: usize },
        Grow(usize),
        RegionDefault(usize),
        RegionCopy { dst: usize, src: usize },
        RegionDestroy(usize),
    }

    static mut EVENTS: Vec<Ev> = Vec::new();

    /// The verdict the mocked manager hand-out returns.
    static mut TAKE_RET: i32 = 1;

    fn push(ev: Ev) {
        unsafe { (*addr_of_mut!(EVENTS)).push(ev) }
    }

    fn events() -> Vec<Ev> {
        unsafe { (*addr_of!(EVENTS)).clone() }
    }

    unsafe extern "C" fn mock_lock(m: *mut u8) -> u32 {
        push(Ev::Lock(m as usize));
        0
    }

    unsafe extern "C" fn mock_unlock(m: *mut u8) -> u32 {
        push(Ev::Unlock(m as usize));
        0
    }

    unsafe extern "C" fn mock_take_blocks(
        manager: *mut u8,
        client_state: *mut u8,
        count: usize,
    ) -> i32 {
        push(Ev::TakeBlocks {
            manager: manager as usize,
            state: client_state as usize,
            count,
        });
        addr_of!(TAKE_RET).read()
    }

    unsafe extern "C" fn mock_grow(deque: *mut BlockDeque) {
        push(Ev::Grow(deque as usize));
    }

    unsafe extern "C" fn mock_region_default(dst: *mut u8) {
        push(Ev::RegionDefault(dst as usize));
    }

    unsafe extern "C" fn mock_region_copy(dst: *mut u8, src: *const u8) {
        push(Ev::RegionCopy {
            dst: dst as usize,
            src: src as usize,
        });
    }

    unsafe extern "C" fn mock_region_destroy(obj: *mut u8) {
        push(Ev::RegionDestroy(obj as usize));
    }

    const MOCK_OPS: ClientPopulateOps = ClientPopulateOps {
        manager_take_blocks: mock_take_blocks,
        deque_grow: mock_grow,
        region_default: mock_region_default,
        region_copy: mock_region_copy,
        region_destroy: mock_region_destroy,
    };

    /// Installs the recorders (this module's ops + the shared mutex
    /// boundary), resets the log and knobs, returns the guard.
    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(TAKE_RET).write(1);
            addr_of_mut!(CLIENT_POPULATE_OPS).write(MOCK_OPS);
            addr_of_mut!(REGION_MUTEX_OPS).write(RegionMutexOps {
                lock: mock_lock,
                unlock: mock_unlock,
            });
        }
        guard
    }

    /// Restores every wired default this module dispatches through.
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(CLIENT_POPULATE_OPS).write(DEFAULT_CLIENT_POPULATE_OPS);
            addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
        }
        drop(guard);
    }

    /// The fixtures (client object, region-list nodes) must live below
    /// 4 GiB: the port reads the opaque client/node pointer fields as
    /// u32 target pointers and zero-extends, so a Box/static-mut
    /// fixture wherever ASLR put it truncates (the mod.rs
    /// pool_integration_tests lesson). One low mmap holds everything.
    fn slab() -> *mut u8 {
        use std::sync::OnceLock;
        static SLAB: OnceLock<usize> = OnceLock::new();
        *SLAB.get_or_init(|| {
            extern "C" {
                fn mmap(
                    addr: usize,
                    len: usize,
                    prot: i32,
                    flags: i32,
                    fd: i32,
                    offset: i64,
                ) -> usize;
            }
            #[cfg(target_os = "macos")]
            const MAP_PRIVATE_ANON: i32 = 0x1002;
            #[cfg(target_os = "linux")]
            const MAP_PRIVATE_ANON: i32 = 0x22;
            const PROT_READ_WRITE: i32 = 3;
            // Distinct hint from the other test slabs so the spans
            // cannot contend.
            let p = unsafe { mmap(0x0b00_0000, 0x1000, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
            assert!(p != usize::MAX && (p | (p + 0xfff)) & 0x8000_0000 == 0);
            p
        }) as *mut u8
    }

    /// The fake client object (0x60 bytes of target-layout u32 words).
    unsafe fn client() -> *mut u8 {
        slab()
    }

    /// Fake region-list node `i` (+0x4 next, +0xc region).
    unsafe fn node(i: usize) -> *mut u8 {
        slab().add(0x100 + i * 0x10)
    }

    /// Writes one u32 word of the fake layout.
    unsafe fn set_word(object: *mut u8, offset: usize, value: u32) {
        (object.add(offset) as *mut u32).write_unaligned(value);
    }

    /// Builds a chain of `regions.len()` nodes over the given fake
    /// region addresses; returns the head.
    unsafe fn node_chain(regions: &[u32]) -> *mut u8 {
        for (i, &region) in regions.iter().enumerate() {
            let next = if i + 1 < regions.len() {
                node(i + 1) as u32
            } else {
                0
            };
            set_word(node(i), NODE_NEXT_OFFSET, next);
            set_word(node(i), NODE_REGION_OFFSET, region);
        }
        node(0)
    }

    /// Wires the fake client: manager marker at +0x4, list head at
    /// +0xc, counters and flags as given.
    unsafe fn client_with(flags: u32, produced: u32, expected: u32, head: u32, list_head: *mut u8) {
        let c = client();
        set_word(c, CLIENT_MANAGER_OFFSET, 0x0b10_c000);
        set_word(c, CLIENT_REGION_LIST_OFFSET, list_head as u32);
        set_word(c, CLIENT_PRODUCED_OFFSET, produced);
        set_word(c, CLIENT_EXPECTED_OFFSET, expected);
        // The state-flag word at +0x44 (state_flags.rs's STATE_FLAGS).
        set_word(c, 0x44, flags);
        set_word(c, CLIENT_HEAD_OFFSET, head);
    }

    /// An empty deque fixture (no segment installed).
    fn empty_deque() -> std::boxed::Box<BlockDeque> {
        std::boxed::Box::new(BlockDeque {
            begin: crate::heap::block_deque::DequeIter::NULL,
            end: crate::heap::block_deque::DequeIter::NULL,
            count: 0,
            map: core::ptr::null_mut(),
            map_cap: 0,
        })
    }

    #[test]
    fn no_headroom_and_insufficient_coverage_refuses_before_the_manager() {
        let _guard = install();
        unsafe {
            // expected - produced - count = 2 - 0 - 3 < 0 (signed bmi).
            client_with(0, 0, 2, 0, core::ptr::null_mut());
            let client = client();
            let mut dq = empty_deque();
            assert_eq!(client_populate(client, 3, &mut *dq), 0);
            let mutex = client.add(CLIENT_MUTEX_OFFSET) as usize;
            assert_eq!(
                events(),
                std::vec![Ev::Lock(mutex), Ev::Unlock(mutex)],
                "the gate fails ahead of the manager call"
            );
            assert_eq!(dq.count, 0, "deque untouched");
        }
        restore(_guard);
    }

    #[test]
    fn the_flagged_path_still_requires_the_head_counter() {
        let _guard = install();
        unsafe {
            // Flag set: the coverage counters are garbage but skipped;
            // head - produced = 1 - 0 < count 3 (unsigned bcc).
            client_with(HEADROOM_MASK, 0, 0, 1, core::ptr::null_mut());
            let client = client();
            let mut dq = empty_deque();
            assert_eq!(client_populate(client, 3, &mut *dq), 0);
            let mutex = client.add(CLIENT_MUTEX_OFFSET) as usize;
            assert_eq!(events(), std::vec![Ev::Lock(mutex), Ev::Unlock(mutex)]);
        }
        restore(_guard);
    }

    #[test]
    fn the_flagged_path_ignores_the_coverage_counters() {
        let _guard = install();
        unsafe {
            // Flag set with headroom (head - produced = 8 >= 3): gate 1
            // must NOT look at produced/expected (0/0 would fail it).
            client_with(HEADROOM_MASK, 0, 0, 8, core::ptr::null_mut());
            let client = client();
            addr_of_mut!(TAKE_RET).write(0);
            let mut dq = empty_deque();
            assert_eq!(client_populate(client, 3, &mut *dq), 0);
            let log = events();
            assert!(
                log.iter()
                    .any(|ev| matches!(ev, Ev::TakeBlocks { count: 3, .. })),
                "the manager call was reached through the flagged gate: {log:?}"
            );
        }
        restore(_guard);
    }

    #[test]
    fn a_manager_refusal_returns_zero_and_unlocks() {
        let _guard = install();
        unsafe {
            client_with(0, 0, 4, 0, core::ptr::null_mut());
            let client = client();
            addr_of_mut!(TAKE_RET).write(0);
            let mut dq = empty_deque();
            assert_eq!(client_populate(client, 3, &mut *dq), 0);
            let mutex = client.add(CLIENT_MUTEX_OFFSET) as usize;
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(mutex),
                    Ev::TakeBlocks {
                        manager: 0x0b10_c000,
                        state: client.add(CLIENT_STATE_OFFSET) as usize,
                        count: 3,
                    },
                    Ev::Unlock(mutex),
                ]
            );
            assert_eq!(dq.count, 0);
        }
        restore(_guard);
    }

    #[test]
    fn a_full_populate_copies_every_region_in_list_order() {
        let _guard = install();
        unsafe {
            let regions = [0x0ae9_1000u32, 0x0ae9_2000, 0x0ae9_3000];
            let head = node_chain(&regions);
            client_with(0, 0, 3, 0, head);
            let client = client();
            let mut dq = empty_deque();
            assert_eq!(client_populate(client, 3, &mut *dq), 1);
            let log = events();
            let mutex = client.add(CLIENT_MUTEX_OFFSET) as usize;
            assert_eq!(log.first(), Some(&Ev::Lock(mutex)));
            assert_eq!(
                log[1],
                Ev::TakeBlocks {
                    manager: 0x0b10_c000,
                    state: client.add(CLIENT_STATE_OFFSET) as usize,
                    count: 3,
                }
            );
            // Per iteration: a temp copy from the node's region, grow
            // on the first (empty deque), the element copy from the
            // temp, the temp destroyed. The grow mock installs no
            // segment, so end.cur starts NULL (iteration 1's element
            // copy is skipped) — but the advance is unconditional, so
            // from iteration 2 on end.cur is 0x28/0x50 and the element
            // copies land there, exactly like the original.
            let copies: std::vec::Vec<(usize, usize)> = log
                .iter()
                .filter_map(|ev| match ev {
                    Ev::RegionCopy { dst, src } => Some((*dst, *src)),
                    _ => None,
                })
                .collect();
            assert_eq!(copies.len(), 5, "3 temp copies + 2 element copies");
            let grows = log
                .iter()
                .filter(|ev| matches!(ev, Ev::Grow(_)))
                .count();
            assert_eq!(grows, 1, "one growth for the empty deque");
            let destroys = log
                .iter()
                .filter(|ev| matches!(ev, Ev::RegionDestroy(_)))
                .count();
            assert_eq!(destroys, 3, "one temp destroyed per block");
            assert_eq!(dq.end.cur as usize, 3 * DEQUE_ELEM_SIZE);
            assert_eq!(dq.count, 3);
            assert_eq!(copies[0].1, regions[0] as usize);
            assert_eq!(copies[1].1, regions[1] as usize);
            assert_eq!(
                copies[2],
                (DEQUE_ELEM_SIZE, copies[1].0),
                "element copy at the advanced end.cur, from the temp"
            );
            assert_eq!(copies[3].1, regions[2] as usize);
            assert_eq!(copies[4], (2 * DEQUE_ELEM_SIZE, copies[3].0));
            assert_eq!(log.last(), Some(&Ev::Unlock(mutex)));
        }
        restore(_guard);
    }

    #[test]
    fn growth_installing_a_segment_lands_the_element_copies() {
        let _guard = install();
        unsafe {
            // A grow mock that really installs one host segment, like
            // the original's 0x083dda08 empty-deque path.
            static mut SEG: [u8; DEQUE_SEG_BYTES] = [0; DEQUE_SEG_BYTES];
            static mut MAP: [*mut u8; 1] = [core::ptr::null_mut()];
            unsafe extern "C" fn grow_installs(deque: *mut BlockDeque) {
                push(Ev::Grow(deque as usize));
                let seg = addr_of_mut!(SEG) as *mut u8;
                (*addr_of_mut!(MAP))[0] = seg;
                (*deque).map = addr_of_mut!(MAP) as *mut *mut u8;
                (*deque).map_cap = 1;
                deque_iter_init(
                    addr_of_mut!((*deque).begin),
                    seg,
                    addr_of_mut!(MAP) as *mut *mut u8,
                );
                (*deque).end = (*deque).begin;
            }
            addr_of_mut!(CLIENT_POPULATE_OPS).write(ClientPopulateOps {
                deque_grow: grow_installs,
                ..MOCK_OPS
            });
            let regions = [0x0ae9_1000u32, 0x0ae9_2000];
            let head = node_chain(&regions);
            client_with(0, 0, 2, 0, head);
            let client = client();
            let mut dq = empty_deque();
            assert_eq!(client_populate(client, 2, &mut *dq), 1);
            let seg = addr_of_mut!(SEG) as *mut u8 as usize;
            let log = events();
            let copies: std::vec::Vec<(usize, usize)> = log
                .iter()
                .filter_map(|ev| match ev {
                    Ev::RegionCopy { dst, src } => Some((*dst, *src)),
                    _ => None,
                })
                .collect();
            assert_eq!(copies.len(), 4);
            for i in 0..2 {
                assert_eq!(copies[2 * i].1, [0x0ae9_1000u32, 0x0ae9_2000][i] as usize);
                assert_eq!(
                    copies[2 * i + 1].0,
                    seg + i * DEQUE_ELEM_SIZE,
                    "element {i} constructed at end.cur"
                );
                assert_eq!(
                    copies[2 * i + 1].1, copies[2 * i].0,
                    "element copy source is the temp"
                );
            }
            assert_eq!(dq.end.cur as usize, seg + 2 * DEQUE_ELEM_SIZE);
            assert_eq!(dq.count, 2);
            // Second iteration: count 1, end.cur != seg_end -> no grow.
            let grows = log.iter().filter(|ev| matches!(ev, Ev::Grow(_))).count();
            assert_eq!(grows, 1);
        }
        restore(_guard);
    }

    #[test]
    fn growth_also_runs_when_the_end_segment_is_spent() {
        let _guard = install();
        unsafe {
            let mut seg = [0u8; DEQUE_SEG_BYTES];
            let mut map = [seg.as_mut_ptr()];
            let mut dq = empty_deque();
            dq.count = 1;
            deque_iter_init(addr_of_mut!(dq.begin), seg.as_mut_ptr(), map.as_mut_ptr());
            dq.end = dq.begin;
            dq.end.cur = dq.end.seg_end; // spent
            let regions = [0x0ae9_1000u32];
            let head = node_chain(&regions);
            client_with(0, 0, 2, 0, head);
            let client = client();
            assert_eq!(client_populate(client, 1, &mut *dq), 1);
            let grows = events()
                .iter()
                .filter(|ev| matches!(ev, Ev::Grow(_)))
                .count();
            assert_eq!(grows, 1, "spent segment grows even when non-empty");
        }
        restore(_guard);
    }

    #[test]
    fn the_wired_defaults_report_the_no_manager_refusal() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(CLIENT_POPULATE_OPS).write(DEFAULT_CLIENT_POPULATE_OPS);
            addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
            client_with(0, 0, 4, 0, core::ptr::null_mut());
            let client = client();
            let mut dq = empty_deque();
            // The gates pass; the fail-closed manager stub refuses.
            assert_eq!(client_populate(client, 3, &mut *dq), 0, "no manager -> refused");
            assert_eq!(dq.count, 0);
            assert!(events().is_empty(), "the no-op mutex stubs ran, nothing else");
        }
        drop(guard);
    }
}
