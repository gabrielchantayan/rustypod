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
//!   register across the unlock, like client_commit.rs). The body is
//!   unported, so it dispatches through [`BLOCK_MANAGER_OPS`]; its
//!   default refuses 0 — the no-manager contract the
//!   CLIENT_POPULATE_OPS.manager_take_blocks default used to fake
//!   wholesale (that slot's default is now this real port; the wired
//!   configuration is still fail-closed, just one boundary deeper).
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

/// Byte offset of the per-region block size word in the block-manager
/// object (original: `ldrne r0, [r0, #0x30]`).
pub const BLOCK_SIZE_OFFSET: usize = 0x30;

/// Byte offset of the manager's own mutex object inside the
/// block-manager object (original: `add r0, r0, #0x148` ahead of both
/// thunk calls).
pub const MANAGER_MUTEX_OFFSET: usize = 0x148;

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

/// Indirect dispatch table for the unported hand-out body (see the
/// module header for the default's contract).
#[derive(Clone, Copy)]
pub struct BlockManagerOps {
    /// Hand-out body @ 0x0818b108 `(manager, client_state, count)`,
    /// run under the manager mutex: nonzero hands `count` blocks to the
    /// client, zero refuses the whole populate.
    pub take_blocks_body:
        unsafe extern "C" fn(manager: *mut u8, client_state: *mut u8, count: usize) -> i32,
}

/// Default body stub: no block-manager machinery — refuse (the
/// fail-closed no-manager contract; with the wired defaults the
/// bracket still reports the same 0 the old
/// CLIENT_POPULATE_OPS.manager_take_blocks stub faked at the slot).
unsafe extern "C" fn stub_take_blocks_body(
    _manager: *mut u8,
    _client_state: *mut u8,
    _count: usize,
) -> i32 {
    0
}

/// Wired default (documented refusal until the body is ported).
pub(crate) const DEFAULT_BLOCK_MANAGER_OPS: BlockManagerOps = BlockManagerOps {
    take_blocks_body: stub_take_blocks_body,
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

/// manager_take_blocks — original: `FUN_0818b0c4` @ 0x0818b0c4 (60
/// bytes).
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
    /// mocked body (the client_commit.rs recorder precedent).
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        Lock(usize),
        Body {
            manager: usize,
            state: usize,
            count: usize,
        },
        Unlock(usize),
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
    fn the_wired_default_refuses_without_touching_the_mutex() {
        let guard = MGR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::addr_of_mut!(crate::heap::block_region::REGION_MUTEX_OPS)
                .write(crate::heap::block_region::DEFAULT_REGION_MUTEX_OPS);
            core::ptr::addr_of_mut!(BLOCK_MANAGER_OPS).write(DEFAULT_BLOCK_MANAGER_OPS);
            let mgr = core::ptr::addr_of_mut!(FAKE_MGR) as *mut u8;
            // The no-op mutex stubs bracket the fail-closed body stub:
            // same 0 the old CLIENT_POPULATE_OPS stub faked wholesale.
            assert_eq!(manager_take_blocks(mgr, mgr, 3), 0);
        }
        drop(guard);
    }
}
