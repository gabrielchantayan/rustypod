//! Ports of the block-manager global queries used by the aligned-block
//! pool allocator (heap/pool.rs) and the block-deque fill
//! (heap/block_deque.rs):
//!
//! - `block_manager_get` — original: `FUN_0818ae48` @ 0x0818ae48
//!   (12 bytes; 14 `bl` call sites): `ldr r0, =0x089cb1b4;
//!   ldr r0, [r0]; bx lr` — returns the block-manager object pointer.
//! - `region_block_size` — original: `FUN_0818a364` @ 0x0818a364
//!   (24 bytes; 16 `bl` call sites + the alias thunk `b` @ 0x081a7a9c,
//!   1 caller): reads the same global; NULL manager returns 0, otherwise
//!   the per-region block size word at manager + 0x30.
//! - `manager_take_blocks` — original: `FUN_0818b0c4` @ 0x0818b0c4 (60
//!   bytes; the `bl` @ 0x081fc310 inside `client_populate`,
//!   heap/client_populate.rs, binary-verified): the block-manager
//!   hand-out the client's populate op calls as
//!   `0x0818b0c4(*(client+4), client+8, count)`. A pure mutex bracket:
//!   lock the manager's own mutex object at manager + 0x148 (the same
//!   unported C++ recursive-mutex pair @ 0x082e8390 / 0x082e83d8 via
//!   the alias thunks @ 0x082621a8 / 0x082621ac every heap client uses
//!   — block_region.rs's `REGION_MUTEX_OPS` boundary), run the real
//!   hand-out body @ 0x0818b108 `(manager, client_state, count)`,
//!   unlock, return the body's verdict (held in a callee-saved
//!   register across the unlock, like client_commit.rs). The body
//!   dispatches through [`BLOCK_MANAGER_OPS`]; its default is the REAL
//!   port below (`take_blocks_body`), whose own unported splice callee
//!   is the table's second slot with a documented no-op default — with
//!   no block manager on device nothing calls the bracket at all, the
//!   same fail-closed no-manager contract the
//!   CLIENT_POPULATE_OPS.manager_take_blocks default used to fake
//!   wholesale.
//! - `take_blocks_body` — original: `FUN_0818b108` @ 0x0818b108 (264
//!   bytes; 2 `bl` call sites @ 0x0818b0e8 (the `manager_take_blocks`
//!   bracket) and @ 0x0818b050 (FUN_0818b028, count always 1),
//!   binary-verified): the actual block hand-out, run under the
//!   manager mutex. See the function's doc header for the algorithm.
//!
//! The global @ 0x089cb1b4 holds the "AMBlockManagerThread" object
//! (see pool.rs's alignment-table provenance note: the whole 0x089cb1xx
//! page is re-initialized at runtime — the decrypted image shows UI
//! strings there). Until the block-manager thread itself is ported,
//! nothing in this crate writes the pointer; the deviation below keeps
//! both queries testable and faithful.
//!
//! Deviation (by necessity, same as types.rs's `DEFAULT_HEAP` for
//! 0x089ca638): the global word is modeled as the crate static
//! [`BLOCK_MANAGER`] instead of living at 0x089cb1b4. It defaults to
//! NULL — exactly the pre-init state on device — so `region_block_size`
//! returns 0 and `block_manager_get` returns NULL until an install (or a
//! host test) stores the object pointer.

use crate::heap::veneers::heap_panic;

/// Byte offset of the per-region block size word in the block-manager
/// object (original: `ldrne r0, [r0, #0x30]`).
pub const BLOCK_SIZE_OFFSET: usize = 0x30;

/// Byte offset of the manager's own mutex object inside the
/// block-manager object (original: `add r0, r0, #0x148` ahead of both
/// thunk calls).
pub const MANAGER_MUTEX_OFFSET: usize = 0x148;

/// Byte offset of the manager's free-list object (original: `add r2,
/// r6, #0x4` ahead of the splice call — the list base passed to
/// 0x083d5d20).
pub const MANAGER_FREE_LIST_OFFSET: usize = 0x4;

/// Byte offset of the head-node word inside a list object (original:
/// `ldr r0, [r6, #0x8]` = manager free list + 0x4, `ldr r0, [r7,
/// #0x4]` = client state + 0x4 — the client state IS a list object).
const LIST_HEAD_OFFSET: usize = 0x4;

/// Byte offset of the node-count word inside a list object (original:
/// `ldr r0, [r0, #0x14]` = manager free list + 0x10, the hand-out
/// gate).
const LIST_COUNT_OFFSET: usize = 0x10;

/// Byte offset of the next pointer inside a list node (original: `ldr
/// r1, [r1, #0x4]` inside the 0x083d5e88 advance).
const NODE_NEXT_OFFSET: usize = 0x4;

/// Byte offset of the block-entry pointer inside a list node
/// (original: `ldrne r0, [r0, #0xc]` inside the 0x083d5ea0 deref).
const NODE_ENTRY_OFFSET: usize = 0xc;

/// Byte offset of the owner handle inside a block entry (original:
/// `ldr r0, [r0, #0x4]` after each deref in the stamping walk).
const ENTRY_OWNER_OFFSET: usize = 0x4;

/// Byte offset of the node back-link the hand-out stamps into the
/// owner handle (original: `str r1, [r0, #0xc]`).
const OWNER_NODE_OFFSET: usize = 0xc;

/// The block-manager object pointer: original global word @ 0x089cb1b4
/// (see the module header for the modeling deviation). NULL until the
/// block-manager thread is up.
pub static mut BLOCK_MANAGER: *mut u8 = core::ptr::null_mut();

/// Reads the global. Volatile: the word is written at runtime (block
/// manager startup / host tests), and a build in which nothing writes it
/// must not constant-fold the NULL in.
#[inline(always)]
fn block_manager() -> *mut u8 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BLOCK_MANAGER)) }
}

/// block_manager_get — original: `FUN_0818ae48` @ 0x0818ae48 (12 bytes).
///
/// Returns the block-manager object pointer (NULL before the manager
/// thread exists).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_manager_get() -> *mut u8 {
    block_manager()
}

/// region_block_size — original: `FUN_0818a364` @ 0x0818a364 (24 bytes;
/// alias thunk `b` @ 0x081a7a9c).
///
/// Per-region block size: the word at manager + 0x30, or 0 when no block
/// manager exists.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn region_block_size() -> u32 {
    let mgr = block_manager();
    if mgr.is_null() {
        return 0;
    }
    (mgr.add(BLOCK_SIZE_OFFSET) as *const u32).read()
}

/// Reads one u32 word of the opaque manager/list/node layout (the
/// objects are unported-ctor layouts — literal byte offsets,
/// `read_unaligned` for the host, the client_populate.rs idiom).
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

/// Writes one u32 word of the opaque layout (the owner back-link
/// stamp — a target pointer truncated to u32; host fixtures live
/// below 4 GiB).
#[inline(always)]
unsafe fn set_word(object: *mut u8, offset: usize, value: u32) {
    (object.add(offset) as *mut u32).write_unaligned(value);
}

/// list_iter_advance — original: `FUN_083d5e88` @ 0x083d5e88 (24
/// bytes), the only two call sites being this module's body, so it is
/// ported in place rather than exported.
///
/// Advances a single-word list iterator (`*it` = current node) to the
/// node's +0x4 next; a NULL current node is fatal (`bleq 0x08030f44`,
/// heap/veneers.rs's `heap_panic`, non-returning).
#[inline(always)]
unsafe fn iter_advance(it: &mut *mut u8) {
    let node = *it;
    if node.is_null() {
        heap_panic();
    }
    *it = ptr_word(node, NODE_NEXT_OFFSET);
}

/// list_iter_entry — original: `FUN_083d5ea0` @ 0x083d5ea0 (20 bytes),
/// same in-place rationale as [`iter_advance`].
///
/// Dereferences a single-word list iterator to the node's +0xc block
/// entry, NULL in → NULL out (`moveq r0, #0`).
#[inline(always)]
unsafe fn iter_entry(node: *mut u8) -> *mut u8 {
    if node.is_null() {
        core::ptr::null_mut()
    } else {
        ptr_word(node, NODE_ENTRY_OFFSET)
    }
}

/// Indirect dispatch table for the hand-out body and its own unported
/// callee (see the module header for the defaults' contract).
#[derive(Clone, Copy)]
pub struct BlockManagerOps {
    /// Hand-out body @ 0x0818b108 `(manager, client_state, count)`,
    /// run under the manager mutex: nonzero hands `count` blocks to the
    /// client, zero refuses the whole populate. The wired default is
    /// the REAL port below (`take_blocks_body`).
    pub take_blocks_body:
        unsafe extern "C" fn(manager: *mut u8, client_state: *mut u8, count: usize) -> i32,
    /// Range splice @ 0x083d5d20 `(dst_list, &dst_pos, src_list,
    /// &src_first, &src_last)` (316 bytes, unported): moves the node
    /// range [src_first, src_last) out of `src_list` into `dst_list`
    /// ahead of `dst_pos`, fixing the links and both list counts. The
    /// original body's callers discard its 0/1 verdict, so the slot
    /// returns `()`.
    pub splice_blocks: unsafe extern "C" fn(
        dst_list: *mut u8,
        dst_pos: *mut *mut u8,
        src_list: *mut u8,
        src_first: *mut *mut u8,
        src_last: *mut *mut u8,
    ),
}

/// Default splice stub: no block-manager machinery — no-op. With no
/// manager on device nothing calls the body at all (the no-manager
/// contract), so this never runs in the wired configuration; host
/// tests install recorders.
unsafe extern "C" fn stub_splice_blocks(
    _dst_list: *mut u8,
    _dst_pos: *mut *mut u8,
    _src_list: *mut u8,
    _src_first: *mut *mut u8,
    _src_last: *mut *mut u8,
) {
}

/// Wired defaults: the real hand-out body plus the documented no-op
/// splice until the splice itself is ported.
pub(crate) const DEFAULT_BLOCK_MANAGER_OPS: BlockManagerOps = BlockManagerOps {
    take_blocks_body,
    splice_blocks: stub_splice_blocks,
};

/// The active implementation table. Written once at init on target;
/// host tests swap in recorders and restore the default.
pub static mut BLOCK_MANAGER_OPS: BlockManagerOps = DEFAULT_BLOCK_MANAGER_OPS;

/// Reads one op (volatile — same rationale as every dispatch table: a
/// build in which nothing swaps it must not constant-fold the default
/// in).
macro_rules! mgr_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BLOCK_MANAGER_OPS.$field)) }
    };
}

/// Reads one op of the shared C++ mutex boundary (block_region.rs).
macro_rules! mutex_op {
    ($field:ident) => {
        unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(
                crate::heap::block_region::REGION_MUTEX_OPS.$field
            ))
        }
    };
}

/// take_blocks_body — original: `FUN_0818b108` @ 0x0818b108 (264
/// bytes; the `bl` @ 0x0818b0e8 inside the `manager_take_blocks`
/// bracket above and the `bl` @ 0x0818b050 inside FUN_0818b028, count
/// always 1 there, binary-verified).
///
/// The actual block hand-out, run under the manager + 0x148 mutex by
/// the bracket. Algorithm:
///
/// 1. Gate: the manager free list's count word (list object at
///    manager + 0x4, count at +0x10 → absolute +0x14) must cover
///    `count` (unsigned `bcc` — equality suffices); otherwise refuse
///    the whole hand-out with 0.
/// 2. Walk a stack end-iterator `count` steps from the free-list head
///    (head word at list + 0x4 → absolute manager + 0x8) through the
///    0x083d5e88 advance ([`iter_advance`]); a short list panics —
///    unreachable given the gate, defensive.
/// 3. Splice the range [head, end) out of the manager's free list
///    into the client state's own list (the client state IS a list
///    object; the insertion position is its head word at +0x4) through
///    the unported 0x083d5d20 — [`BLOCK_MANAGER_OPS`].splice_blocks,
///    verdict discarded exactly like the original.
/// 4. Stamping walk: re-read the client state's head AFTER the splice
///    (`ldr r0, [r7, #0x4]` at 0x0818b1a4) and walk `count` nodes; for
///    each, deref the node to its +0xc block entry (0x083d5ea0,
///    [`iter_entry`]), read the entry's +0x4 owner handle — NULL is
///    fatal (`bleq 0x08030f44`, non-returning) — and stamp the handle's
///    +0xc back-link with the node pointer, so every handed-out block
///    knows which client-list node holds it.
/// 5. Return 1 (granted).
///
/// Deviations: the original reads the entry/owner three times per
/// node across the panic boundary (ADS could not CSE around
/// 0x08030f44) and re-checks the owner for NULL after the
/// non-returning panic — the port reads once; the redundant re-check
/// is dead on every path. The original's intermediate iterator spills
/// (`str r0, [sp, #0x18]` written with the head and immediately
/// overwritten with the position) collapse into the two locals the
/// splice actually consumes. List pointer fields are u32 target
/// pointers zero-extended on read / truncated on the stamp (exact on
/// target; host fixtures live below 4 GiB — the client_populate.rs
/// idiom).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn take_blocks_body(
    manager: *mut u8,
    client_state: *mut u8,
    count: usize,
) -> i32 {
    let free_list = manager.add(MANAGER_FREE_LIST_OFFSET);
    if word(free_list, LIST_COUNT_OFFSET) < count as u32 {
        return 0;
    }
    // End iterator: `count` advances from the free-list head
    // (0x083d5e88 loop, NULL node panics inside the advance).
    let mut end: *mut u8 = ptr_word(free_list, LIST_HEAD_OFFSET);
    let mut remaining = count;
    while remaining != 0 {
        iter_advance(&mut end);
        remaining -= 1;
    }
    // The splice (unported 0x083d5d20): [head, end) moves from the
    // manager's free list into the client state's list ahead of its
    // head position. The original discards the verdict.
    let mut pos: *mut u8 = ptr_word(client_state, LIST_HEAD_OFFSET);
    let mut first: *mut u8 = ptr_word(free_list, LIST_HEAD_OFFSET);
    (mgr_op!(splice_blocks))(client_state, &mut pos, free_list, &mut first, &mut end);
    // The stamping walk over the client state's freshly spliced head
    // (re-read after the splice, like the original).
    let mut cursor: *mut u8 = ptr_word(client_state, LIST_HEAD_OFFSET);
    let mut remaining = count;
    while remaining != 0 {
        let owner = ptr_word(iter_entry(cursor), ENTRY_OWNER_OFFSET);
        if owner.is_null() {
            // Non-returning, exactly like the original's
            // `bleq 0x08030f44`.
            heap_panic();
        }
        set_word(owner, OWNER_NODE_OFFSET, cursor as u32);
        iter_advance(&mut cursor);
        remaining -= 1;
    }
    1
}


///
/// Hands `count` blocks to the client identified by `client_state`
/// (client + 0x8 at the call site) under the manager's mutex at
/// manager + 0x148; returns the unported body 0x0818b108's verdict
/// (nonzero granted, zero refused — `client_populate` forwards it).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn manager_take_blocks(
    manager: *mut u8,
    client_state: *mut u8,
    count: usize,
) -> i32 {
    let mutex = manager.add(MANAGER_MUTEX_OFFSET);
    (mutex_op!(lock))(mutex);
    let result = (mgr_op!(take_blocks_body))(manager, client_state, count);
    (mutex_op!(unlock))(mutex);
    result
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that swap the global manager pointer. pub(crate)
    /// so client_register.rs's tests can hold it while they install a
    /// manager (the kobj.rs HOOKS_LOCK precedent).
    pub(crate) static MGR_LOCK: Mutex<()> = Mutex::new(());

    /// Fake block-manager object: big enough to hold the +0x30 word.
    #[repr(align(4))]
    struct FakeManager([u8; 0x40]);
    static mut FAKE_MGR: FakeManager = FakeManager([0; 0x40]);

    /// Locks the global and installs the fake manager with the given
    /// block-size word.
    fn install_manager(block_size: u32) -> MutexGuard<'static, ()> {
        let guard = MGR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mgr = core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8;
            (mgr.add(BLOCK_SIZE_OFFSET) as *mut u32).write(block_size);
            BLOCK_MANAGER = mgr;
        }
        guard
    }

    /// Restores the NULL default. Call before dropping the guard.
    fn clear_manager() {
        unsafe { BLOCK_MANAGER = core::ptr::null_mut() };
    }

    #[test]
    fn no_manager_returns_zero_size_and_null() {
        let _guard = MGR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_manager();
        unsafe {
            assert_eq!(region_block_size(), 0);
            assert!(block_manager_get().is_null());
        }
    }

    #[test]
    fn size_comes_from_manager_plus_0x30() {
        let _guard = install_manager(0x8_0000);
        unsafe {
            assert_eq!(region_block_size(), 0x8_0000);
            assert_eq!(
                block_manager_get(),
                core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8
            );
        }
        clear_manager();
    }

    #[test]
    fn zero_size_word_reads_back_as_zero_with_a_manager() {
        // A present manager with a 0 word is distinguishable from "no
        // manager" only by block_manager_get — the size query returns 0
        // either way, exactly like the original.
        let _guard = install_manager(0);
        unsafe {
            assert_eq!(region_block_size(), 0);
            assert!(!block_manager_get().is_null());
        }
        clear_manager();
    }

    /// One ordered event log across the mocked mutex boundary and the
    /// mocked body/splice (the client_commit.rs recorder precedent).
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        Lock(usize),
        Body {
            manager: usize,
            state: usize,
            count: usize,
        },
        Unlock(usize),
        Splice {
            dst_list: usize,
            pos: usize,
            src_list: usize,
            first: usize,
            last: usize,
        },
    }

    static mut EVENTS: std::vec::Vec<Ev> = std::vec::Vec::new();

    /// The verdict the mocked body returns.
    static mut BODY_RET: i32 = 1;

    fn push(ev: Ev) {
        unsafe { (*core::ptr::addr_of_mut!(EVENTS)).push(ev) }
    }

    fn events() -> std::vec::Vec<Ev> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    unsafe extern "C" fn mock_lock(m: *mut u8) -> u32 {
        push(Ev::Lock(m as usize));
        0
    }

    unsafe extern "C" fn mock_unlock(m: *mut u8) -> u32 {
        push(Ev::Unlock(m as usize));
        0
    }

    unsafe extern "C" fn mock_body(manager: *mut u8, state: *mut u8, count: usize) -> i32 {
        push(Ev::Body {
            manager: manager as usize,
            state: state as usize,
            count,
        });
        core::ptr::addr_of!(BODY_RET).read()
    }

    /// Records the splice with the iterator words DEREFERENCED (the
    /// values the original passes by reference).
    unsafe extern "C" fn mock_splice(
        dst_list: *mut u8,
        dst_pos: *mut *mut u8,
        src_list: *mut u8,
        src_first: *mut *mut u8,
        src_last: *mut *mut u8,
    ) {
        push(Ev::Splice {
            dst_list: dst_list as usize,
            pos: *dst_pos as usize,
            src_list: src_list as usize,
            first: *src_first as usize,
            last: *src_last as usize,
        });
    }

    /// Installs the recorders over both boundaries, resets the log and
    /// the verdict knob; returns the guard.
    fn install_ops() -> MutexGuard<'static, ()> {
        let guard = MGR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::addr_of_mut!(BODY_RET).write(1);
            core::ptr::addr_of_mut!(crate::heap::block_region::REGION_MUTEX_OPS).write(
                crate::heap::block_region::RegionMutexOps {
                    lock: mock_lock,
                    unlock: mock_unlock,
                },
            );
            core::ptr::addr_of_mut!(BLOCK_MANAGER_OPS).write(BlockManagerOps {
                take_blocks_body: mock_body,
                splice_blocks: mock_splice,
            });
        }
        guard
    }

    /// Restores every wired default this module dispatches through.
    fn restore_ops(guard: MutexGuard<'static, ()>) {
        unsafe {
            core::ptr::addr_of_mut!(crate::heap::block_region::REGION_MUTEX_OPS)
                .write(crate::heap::block_region::DEFAULT_REGION_MUTEX_OPS);
            core::ptr::addr_of_mut!(BLOCK_MANAGER_OPS).write(DEFAULT_BLOCK_MANAGER_OPS);
        }
        drop(guard);
    }

    #[test]
    fn the_bracket_locks_runs_the_body_and_unlocks_in_order() {
        let _guard = install_ops();
        unsafe {
            let mgr = core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8;
            let state = mgr.add(0x10); // any client_state pointer
            assert_eq!(manager_take_blocks(mgr, state, 7), 1);
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(mgr.add(MANAGER_MUTEX_OFFSET) as usize),
                    Ev::Body {
                        manager: mgr as usize,
                        state: state as usize,
                        count: 7,
                    },
                    Ev::Unlock(mgr.add(MANAGER_MUTEX_OFFSET) as usize),
                ],
                "lock(manager+0x148) -> body(manager, state, count) -> unlock"
            );
        }
        restore_ops(_guard);
    }

    #[test]
    fn the_body_verdict_passes_through_and_the_mutex_is_released() {
        let _guard = install_ops();
        unsafe {
            let mgr = core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8;
            for verdict in [0i32, 1, -1, 7] {
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
                core::ptr::addr_of_mut!(BODY_RET).write(verdict);
                assert_eq!(manager_take_blocks(mgr, mgr, 1), verdict);
                let log = events();
                assert!(
                    matches!(log.last(), Some(Ev::Unlock(_))),
                    "unlock runs even on a refusal: {log:?}"
                );
            }
        }
        restore_ops(_guard);
    }

    #[test]
    fn the_wired_default_refuses_through_the_real_bodys_gate() {
        let guard = MGR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::addr_of_mut!(crate::heap::block_region::REGION_MUTEX_OPS)
                .write(crate::heap::block_region::DEFAULT_REGION_MUTEX_OPS);
            core::ptr::addr_of_mut!(BLOCK_MANAGER_OPS).write(DEFAULT_BLOCK_MANAGER_OPS);
            let mgr = core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8;
            // The default body is now the REAL port; the zeroed fake
            // manager's free-count word (+0x14) falls short of 3, so
            // the bracket still reports the refusal 0 the old body
            // stub faked — the fail-closed no-manager contract, one
            // gate deeper. The no-op mutex stubs record nothing.
            assert_eq!(manager_take_blocks(mgr, mgr, 3), 0);
            assert_eq!(events(), std::vec![]);
        }
        drop(guard);
    }

    /// --- take_blocks_body fixtures ---------------------------------
    ///
    /// The manager/list/node objects are read by literal byte offset
    /// as u32 target pointers, so the fixtures must live below 4 GiB
    /// (the client_populate.rs slab lesson). One low mmap holds
    /// everything; distinct hint from the other modules' slabs.
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
            let p = unsafe { mmap(0x0c00_0000, 0x1000, PROT_READ_WRITE, MAP_PRIVATE_ANON, -1, 0) };
            assert!(p != usize::MAX && (p | (p + 0xfff)) & 0x8000_0000 == 0);
            p
        }) as *mut u8
    }

    /// The fake manager object; its free-list object sits at +0x4.
    unsafe fn mgr() -> *mut u8 {
        slab()
    }

    /// Fake free-list node `i` (+0x4 next, +0xc entry — the walk never
    /// touches the free nodes' entries, only the advance's +0x4).
    unsafe fn mgr_node(i: usize) -> *mut u8 {
        slab().add(0x100 + i * 0x10)
    }

    /// The fake client state (itself a list object: head at +0x4).
    unsafe fn client() -> *mut u8 {
        slab().add(0x200)
    }

    /// Fake client-list node `i` (+0x4 next, +0xc entry).
    unsafe fn client_node(i: usize) -> *mut u8 {
        slab().add(0x300 + i * 0x10)
    }

    /// Fake block entry `i` (+0x4 owner handle).
    unsafe fn entry(i: usize) -> *mut u8 {
        slab().add(0x400 + i * 0x10)
    }

    /// Fake owner handle `i` (+0xc node back-link, stamped).
    unsafe fn owner(i: usize) -> *mut u8 {
        slab().add(0x500 + i * 0x10)
    }

    /// Builds the fixture: the manager's free list holds `free` chained
    /// nodes (count word set), the client state's list holds
    /// `owned` chained nodes each pointing at a distinct entry whose
    /// owner handle's back-link starts at the 0xdeadbeef sentinel.
    unsafe fn build(free: usize, owned: usize) {
        let free_list = mgr().add(MANAGER_FREE_LIST_OFFSET);
        for i in 0..free {
            let next = if i + 1 < free {
                mgr_node(i + 1) as u32
            } else {
                0
            };
            set_word(mgr_node(i), NODE_NEXT_OFFSET, next);
        }
        set_word(
            free_list,
            LIST_HEAD_OFFSET,
            if free > 0 { mgr_node(0) as u32 } else { 0 },
        );
        set_word(free_list, LIST_COUNT_OFFSET, free as u32);
        for i in 0..owned {
            let next = if i + 1 < owned {
                client_node(i + 1) as u32
            } else {
                0
            };
            set_word(client_node(i), NODE_NEXT_OFFSET, next);
            set_word(client_node(i), NODE_ENTRY_OFFSET, entry(i) as u32);
            set_word(entry(i), ENTRY_OWNER_OFFSET, owner(i) as u32);
            set_word(owner(i), OWNER_NODE_OFFSET, 0xdead_beef);
        }
        set_word(
            client(),
            LIST_HEAD_OFFSET,
            if owned > 0 { client_node(0) as u32 } else { 0 },
        );
    }

    /// Installs the real body with the recording splice (no mutex
    /// mocking: the tests call the body directly), resets the log.
    fn install_body() -> MutexGuard<'static, ()> {
        let guard = MGR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::addr_of_mut!(BLOCK_MANAGER_OPS).write(BlockManagerOps {
                take_blocks_body,
                splice_blocks: mock_splice,
            });
        }
        guard
    }

    /// Restores the ops default.
    fn restore_body(guard: MutexGuard<'static, ()>) {
        unsafe {
            core::ptr::addr_of_mut!(BLOCK_MANAGER_OPS).write(DEFAULT_BLOCK_MANAGER_OPS);
        }
        drop(guard);
    }

    #[test]
    fn the_body_refuses_when_the_free_count_falls_short() {
        let _guard = install_body();
        unsafe {
            build(2, 2);
            assert_eq!(take_blocks_body(mgr(), client(), 3), 0);
            assert_eq!(events(), std::vec![], "no splice on a refusal");
            // The client list is untouched: no back-link was stamped.
            assert_eq!(
                word(owner(0), OWNER_NODE_OFFSET),
                0xdead_beef,
                "refusal stamps nothing"
            );
        }
        restore_body(_guard);
    }

    #[test]
    fn the_body_splices_the_range_and_stamps_the_owner_back_links() {
        let _guard = install_body();
        unsafe {
            build(3, 2);
            assert_eq!(take_blocks_body(mgr(), client(), 2), 1);
            assert_eq!(
                events(),
                std::vec![Ev::Splice {
                    dst_list: client() as usize,
                    pos: client_node(0) as usize,
                    src_list: mgr().add(MANAGER_FREE_LIST_OFFSET) as usize,
                    first: mgr_node(0) as usize,
                    // Two advances from the head: m0 -> m1 -> m2.
                    last: mgr_node(2) as usize,
                }],
                "splice(client, &pos=head, manager+4, &first=head, &last=end)"
            );
            // The stamping walk re-reads the client head and stamps
            // each entry's owner handle with its node, in list order.
            assert_eq!(word(owner(0), OWNER_NODE_OFFSET), client_node(0) as u32);
            assert_eq!(word(owner(1), OWNER_NODE_OFFSET), client_node(1) as u32);
        }
        restore_body(_guard);
    }

    #[test]
    fn an_equal_free_count_grants_and_the_range_runs_off_the_list() {
        let _guard = install_body();
        unsafe {
            // free == count: the `bcc` gate is strict, so equality
            // grants; the end iterator advances off the last node to
            // NULL (advancing INTO null is fine — only a null CURRENT
            // node panics).
            build(2, 1);
            assert_eq!(take_blocks_body(mgr(), client(), 1), 1);
            assert_eq!(
                events(),
                std::vec![Ev::Splice {
                    dst_list: client() as usize,
                    pos: client_node(0) as usize,
                    src_list: mgr().add(MANAGER_FREE_LIST_OFFSET) as usize,
                    first: mgr_node(0) as usize,
                    last: mgr_node(1) as usize,
                }]
            );
            assert_eq!(word(owner(0), OWNER_NODE_OFFSET), client_node(0) as u32);
        }
        restore_body(_guard);
    }

    #[test]
    fn a_zero_count_splices_an_empty_range_and_grants() {
        let _guard = install_body();
        unsafe {
            build(1, 1);
            assert_eq!(take_blocks_body(mgr(), client(), 0), 1);
            assert_eq!(
                events(),
                std::vec![Ev::Splice {
                    dst_list: client() as usize,
                    pos: client_node(0) as usize,
                    src_list: mgr().add(MANAGER_FREE_LIST_OFFSET) as usize,
                    // No advances: first == last == the head.
                    first: mgr_node(0) as usize,
                    last: mgr_node(0) as usize,
                }],
                "the original calls the splice unconditionally, count 0 too"
            );
            // The walk ran zero times: nothing stamped.
            assert_eq!(word(owner(0), OWNER_NODE_OFFSET), 0xdead_beef);
        }
        restore_body(_guard);
    }
}
