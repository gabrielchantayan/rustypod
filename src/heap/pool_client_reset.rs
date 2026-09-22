//! Port of the pool client's reset/commit path.
//!
//! `pool_client_reset` — original: `FUN_08223630` @ `0x08223630`
//! (152 bytes, `0x08223630..0x082236c8`; 10 plain unconditional `bl`
//! instructions and no predicated `bl` instructions, raw-binary verified).
//! It locks the embedded recursive mutex, commits an attached client, and,
//! when its caller requests it, polls the client's 0x50000-byte condition.
//! The first unsuccessful poll waits on the mailbox at +0x48 using the +0x44
//! timeout; any later unsuccessful poll stops. It then clears the pending byte
//! (+0x4c) and timeout (+0x44), and tail-unlocks the mutex.
//!
//! # Deliberate deviations
//!
//! `FUN_081fc8b4` has no established semantic identity. Its verified
//! `(client) -> i32` boundary is therefore an ops slot named for its observed
//! 0x50000-byte polling behavior; the default preserves the stock no-client
//! outcome. The mutex, handle accessor, commit, and queue wait use their real
//! ports.

use crate::cxx::handle::handle_deref_or_null;
use crate::heap::client_commit::client_commit;
use crate::heap::queue_wait::queue_wait;
use crate::kernel::kobj::Mailbox;
use crate::heap::block_region::REGION_MUTEX_OPS;

/// Target layout of the derived pool-client state used at `0x08223630`.
/// Host pointers are wider, so field access rather than byte offsets keeps
/// fixtures sound while the 32-bit assertion preserves the firmware layout.
#[repr(C)]
pub struct PoolClientResetState {
    pub vtable: *mut u8,
    pub client_ref: *const *mut u8,
    pub mutex: [u32; 7],
    pub parent_mailbox: *mut Mailbox,
    pub parent_state: u8,
    pub client_shared: u8,
    pub parent_pad: [u8; 2],
    pub node: [u32; 4],
    pub client_cache: *mut u8,
    pub parent_reserved: u32,
    pub timeout: u32,
    pub mailbox: *mut Mailbox,
    pub pending: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x4c] = [0; core::mem::offset_of!(PoolClientResetState, pending)];

/// Boundary for `FUN_081fc8b4`, which invokes `FUN_081fc6f0(client,
/// 0x50000, 1)` and returns its inverted success predicate.
#[derive(Clone, Copy)]
pub struct PoolClientResetOps {
    pub poll_0x50000: unsafe extern "C" fn(client: *mut u8) -> i32,
}

unsafe extern "C" fn no_client_poll_0x50000(_client: *mut u8) -> i32 {
    1
}

pub const DEFAULT_POOL_CLIENT_RESET_OPS: PoolClientResetOps = PoolClientResetOps {
    poll_0x50000: no_client_poll_0x50000,
};

pub static mut POOL_CLIENT_RESET_OPS: PoolClientResetOps = DEFAULT_POOL_CLIENT_RESET_OPS;

#[inline(always)]
unsafe fn poll_0x50000(client: *mut u8) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(POOL_CLIENT_RESET_OPS.poll_0x50000))(client)
}

/// `pool_client_reset` — original: `FUN_08223630` @ `0x08223630`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pool_client_reset(state: *mut PoolClientResetState, wait: i32) -> u32 {
    let mutex = core::ptr::addr_of_mut!((*state).mutex).cast();
    let lock = core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.lock));
    let unlock = core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.unlock));
    lock(mutex);

    if !handle_deref_or_null(core::ptr::addr_of!((*state).client_ref)).is_null() {
        let client = handle_deref_or_null(core::ptr::addr_of!((*state).client_ref));
        if client_commit(client) != 0 {
            let mut waited = false;
            while wait != 0 {
                let client = handle_deref_or_null(core::ptr::addr_of!((*state).client_ref));
                if poll_0x50000(client) != 0 || waited {
                    let client = handle_deref_or_null(core::ptr::addr_of!((*state).client_ref));
                    let _ = poll_0x50000(client);
                    break;
                }
                waited = true;
                let mailbox = core::ptr::addr_of_mut!((*state).mailbox);
                let _ = queue_wait(mailbox, (*state).timeout);
            }
        }
    }

    (*state).pending = 0;
    (*state).timeout = 0;
    unlock(mutex)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_region::{RegionMutexOps, DEFAULT_REGION_MUTEX_OPS};
    use crate::heap::client_commit::{ClientCommitOps, CLIENT_COMMIT_OPS, DEFAULT_CLIENT_COMMIT_OPS};
    use crate::heap::queue_wait::QUEUE_WAIT_SEM;
    use crate::kernel::csem::CountingSem;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;
    use std::vec::Vec;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: Vec<&'static str> = Vec::new();
    static mut POLLS: usize = 0;
    static mut POLL_RESULTS: [i32; 3] = [0, 1, 1];

    unsafe fn event(value: &'static str) { (*addr_of_mut!(EVENTS)).push(value); }
    unsafe extern "C" fn lock(_mutex: *mut u8) -> u32 { event("lock"); 0 }
    unsafe extern "C" fn unlock(_mutex: *mut u8) -> u32 { event("unlock"); 0 }
    unsafe extern "C" fn commit(_client: *mut u8, _flag: u32) -> i32 { event("commit"); 1 }
    unsafe extern "C" fn poll(_client: *mut u8) -> i32 {
        event("poll");
        let index = *addr_of!(POLLS);
        *addr_of_mut!(POLLS) = index + 1;
        (*addr_of!(POLL_RESULTS))[index]
    }
    unsafe extern "C" fn wait(_sem: *mut CountingSem, _timeout: u32) -> u32 { event("wait"); 0 }

    unsafe fn install() {
        (*addr_of_mut!(EVENTS)).clear();
        *addr_of_mut!(POLLS) = 0;
        addr_of_mut!(REGION_MUTEX_OPS).write(RegionMutexOps { lock, unlock });
        addr_of_mut!(CLIENT_COMMIT_OPS).write(ClientCommitOps { commit_body: commit });
        addr_of_mut!(POOL_CLIENT_RESET_OPS).write(PoolClientResetOps { poll_0x50000: poll });
        addr_of_mut!(QUEUE_WAIT_SEM).write(wait);
    }
    unsafe fn restore() {
        addr_of_mut!(REGION_MUTEX_OPS).write(DEFAULT_REGION_MUTEX_OPS);
        addr_of_mut!(CLIENT_COMMIT_OPS).write(DEFAULT_CLIENT_COMMIT_OPS);
        addr_of_mut!(POOL_CLIENT_RESET_OPS).write(DEFAULT_POOL_CLIENT_RESET_OPS);
        addr_of_mut!(QUEUE_WAIT_SEM).write(crate::kernel::csem::csem_wait);
    }
    fn state() -> PoolClientResetState {
        PoolClientResetState {
            vtable: core::ptr::null_mut(), client_ref: core::ptr::null(), mutex: [0; 7],
            parent_mailbox: core::ptr::null_mut(), parent_state: 0, client_shared: 0,
            parent_pad: [0; 2], node: [0; 4], client_cache: core::ptr::null_mut(),
            parent_reserved: 0, timeout: 9, mailbox: core::ptr::null_mut(), pending: 1,
        }
    }

    #[test]
    fn waits_once_then_rechecks_before_clearing_state() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            install();
            let mut target = 0u8;
            let client_cell = addr_of_mut!(target);
            let mut state = state();
            state.client_ref = addr_of!(client_cell);
            pool_client_reset(addr_of_mut!(state), 1);
            assert_eq!((*addr_of!(EVENTS)).as_slice(), ["lock", "lock", "commit", "unlock", "poll", "wait", "poll", "poll", "unlock"]);
            assert_eq!(state.pending, 0);
            assert_eq!(state.timeout, 0);
            restore();
        }
    }

    #[test]
    fn skips_polling_when_wait_is_disabled() {
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            install();
            let mut target = 0u8;
            let client_cell = addr_of_mut!(target);
            let mut state = state();
            state.client_ref = addr_of!(client_cell);
            pool_client_reset(addr_of_mut!(state), 0);
            assert_eq!((*addr_of!(EVENTS)).as_slice(), ["lock", "lock", "commit", "unlock", "unlock"]);
            restore();
        }
    }
}
