//! Port of the block-manager client's **commit** op — the companion of
//! `client_erase` (heap/client_erase.rs) that `pool_base_release_blocks`
//! (heap/block_deque.rs) runs right after the deque drain:
//!
//! - `client_commit` — original: `FUN_081fc884` @ 0x081fc884 (48 bytes;
//!   5 `bl` call sites @ 0x0814bb60 (FUN_0814bb18), 0x081a7a88,
//!   0x082141a4 (`pool_base_release_blocks`), 0x08223664, 0x0828bdbc,
//!   plus 2 tail-branch sites @ 0x08168160 and 0x081f7430,
//!   binary-verified). A pure mutex bracket: under the client's own
//!   mutex (client + 0x24 — NOT the pool base's +0x8 one — the same
//!   C++ owner-tracked mutex pair @ 0x082e8390 / 0x082e83d8 via the
//!   alias thunks @ 0x082621a8 / 0x082621ac that client_erase uses), it
//!   calls the commit body @ 0x081fc408(client, 1) — the `1` flag
//!   (`mov r1, #0x1`) enables the body's post-commit manager
//!   notification (`cmp r7, #0` ahead of `bl 0x0818a3b4`) — saves the
//!   body's 0/1 verdict across the unlock, and returns it verbatim
//!   (`mov r5, r0` … `mov r0, r5`). The verdict means committed (1) /
//!   refused (0); `pool_base_release_blocks` discards it, the other
//!   callers test it.
//!
//! # Deviations
//!
//! - **Mutex**: client + 0x24 is locked/unlocked through
//!   block_region.rs's `REGION_MUTEX_OPS` (one boundary for the one
//!   original pair — the client_erase.rs precedent; the defaults are
//!   the real ports, kernel/posix_mutex.rs). The mutex offset
//!   constant itself is shared: `client_erase::CLIENT_MUTEX_OFFSET`.
//! - **Commit body** @ 0x081fc408 is unported block-manager machinery
//!   (a 0x40000/0x20000 headroom probe pair, state-word updates at
//!   client + 0x44/+0x50, and manager calls through the two-level
//!   client ref at +0x4), so it dispatches through the new
//!   [`CLIENT_COMMIT_OPS`] slot (house ops-slot pattern, indirect `blx`
//!   in place of `bl`). The default is a documented stub returning 0 —
//!   the no-manager verdict, matching block_deque.rs's other no-manager
//!   client stubs (reserve/avail/populate all report failure) and
//!   behavior-identical to the old `stub_client_erase_commit` no-op
//!   default whose only caller discarded the result anyway.
//! - **Shipped wiring**: the port is the default of
//!   `POOL_BASE_OPS.client_erase_commit` (heap/block_deque.rs),
//!   replacing the no-op stub. The slot's signature gains the verdict
//!   return (`-> i32`, discarded by `pool_base_release_blocks` exactly
//!   as the original caller discards r0).

use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::heap::client_erase::CLIENT_MUTEX_OFFSET;

/// Indirect dispatch table for the unported callee (see the module
/// header for the default's contract).
#[derive(Clone, Copy)]
pub struct ClientCommitOps {
    /// Commit body @ 0x081fc408 `(client, notify_flag)`: 1 when the
    /// pending state was committed to the block manager, 0 when
    /// refused. The flag is always 1 at this call site (it arms the
    /// body's post-commit manager notification).
    pub commit_body: unsafe extern "C" fn(client: *mut u8, notify_flag: u32) -> i32,
}

/// Default commit-body stub: no block manager — nothing to commit to,
/// report refusal (the no-manager contract of the
/// `stub_client_erase_commit` default this table's consumer replaces).
unsafe extern "C" fn stub_commit_body(_client: *mut u8, _notify_flag: u32) -> i32 {
    0
}

/// Wired default (documented no-manager stub until the block-manager
/// client machinery is ported).
pub(crate) const DEFAULT_CLIENT_COMMIT_OPS: ClientCommitOps = ClientCommitOps {
    commit_body: stub_commit_body,
};

/// The active implementation table. Written once at init on target;
/// host tests swap in recorders and restore the default.
pub static mut CLIENT_COMMIT_OPS: ClientCommitOps = DEFAULT_CLIENT_COMMIT_OPS;

/// Reads one op (volatile — same rationale as every dispatch table: a
/// build in which nothing swaps it must not constant-fold the default
/// in).
macro_rules! op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CLIENT_COMMIT_OPS.$field)) }
    };
}

/// Reads one op of the shared C++ mutex boundary (block_region.rs).
macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// client_commit — original: `FUN_081fc884` @ 0x081fc884 (48 bytes).
///
/// Runs the commit body @ 0x081fc408(client, 1) under the client's own
/// mutex (client + 0x24) and returns its 0/1 verdict, held across the
/// unlock (see the module header for the full protocol).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn client_commit(client: *mut u8) -> i32 {
    let mutex = client.add(CLIENT_MUTEX_OFFSET);
    (mutex_op!(lock))(mutex);
    // mov r1, #0x1 — the notify flag is constant at every call site.
    let verdict = (op!(commit_body))(client, 1);
    (mutex_op!(unlock))(mutex);
    verdict
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
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
        CommitBody { client: usize, notify_flag: u32 },
    }

    static mut EVENTS: Vec<Ev> = Vec::new();

    /// The verdict the mocked commit body returns.
    static mut BODY_RET: i32 = 0;

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

    unsafe extern "C" fn mock_commit_body(client: *mut u8, notify_flag: u32) -> i32 {
        push(Ev::CommitBody {
            client: client as usize,
            notify_flag,
        });
        unsafe { addr_of!(BODY_RET).read() }
    }

    /// Installs the recorders, resets the log, returns the guard.
    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(BODY_RET).write(1);
            addr_of_mut!(CLIENT_COMMIT_OPS).write(ClientCommitOps {
                commit_body: mock_commit_body,
            });
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
            addr_of_mut!(CLIENT_COMMIT_OPS).write(DEFAULT_CLIENT_COMMIT_OPS);
            addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
        }
        drop(guard);
    }

    /// Fake client object: the mutex lives at +0x24, nothing else is
    /// modeled (the client object is 0x170 bytes, ctor 0x081e6b34).
    #[repr(align(4))]
    struct FakeClient([u8; 0x60]);

    #[test]
    fn the_commit_body_runs_under_the_client_mutex() {
        let _guard = install();
        unsafe {
            let mut client = FakeClient([0; 0x60]);
            let client = client.0.as_mut_ptr();
            let verdict = client_commit(client);
            assert_eq!(verdict, 1);
            let mutex = client.add(CLIENT_MUTEX_OFFSET) as usize;
            assert_eq!(
                events(),
                std::vec![
                    Ev::Lock(mutex),
                    Ev::CommitBody {
                        client: client as usize,
                        notify_flag: 1,
                    },
                    Ev::Unlock(mutex),
                ],
                "lock, body(client, 1), unlock — the mov r1, #0x1 flag"
            );
        }
        restore(_guard);
    }

    #[test]
    fn the_verdict_is_returned_verbatim_and_the_mutex_still_released() {
        let _guard = install();
        unsafe {
            let mut client = FakeClient([0; 0x60]);
            let client = client.0.as_mut_ptr();
            for ret in [0, 1, -1, 7] {
                (*addr_of_mut!(EVENTS)).clear();
                addr_of_mut!(BODY_RET).write(ret);
                assert_eq!(client_commit(client), ret, "mov r0, r5 — verbatim");
                let log = events();
                assert_eq!(
                    log.last(),
                    Some(&Ev::Unlock(client.add(CLIENT_MUTEX_OFFSET) as usize)),
                    "the unlock runs even on a failure verdict"
                );
            }
        }
        restore(_guard);
    }

    #[test]
    fn the_wired_defaults_report_the_no_manager_refusal() {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*addr_of_mut!(EVENTS)).clear();
            addr_of_mut!(CLIENT_COMMIT_OPS).write(DEFAULT_CLIENT_COMMIT_OPS);
            addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
            let mut client = FakeClient([0; 0x60]);
            let client = client.0.as_mut_ptr();
            // No recorders installed: the real mutex pair and the
            // fail-closed body stub run, nothing else.
            assert_eq!(client_commit(client), 0, "no manager -> refused");
            assert!(events().is_empty());
        }
        drop(guard);
    }
}
