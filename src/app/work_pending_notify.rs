//! Pending-work notification for the owner used by FUN_0814a1c0.
//!
//! FUN_0814a298 @ 0x0814a298: true extent [0x0814a298,0x0814a2c8),
//! 48 bytes, no literals; the next function begins with PUSH. Raw A32
//! decoding verifies two incoming plain BLs (0x0807c6d4,0x0814a284),
//! no predicated incoming BLs, two body plain BLs, no predicated body BLs,
//! and a tail B to mutex_unlock @ 0x0807f6a0.
//!
//! Lock the mutex at +0x2c, set the pending byte at +0x28 to one,
//! broadcast the condition at +0x34, then unlock. Repeated notifications
//! still broadcast. Deliberate deviations: the tail branch is a Rust
//! return-position call; repr(C) native pointer fields expand on the host
//! while retaining firmware offsets on ARM. Volatile publication preserves
//! the byte store before waking waiters. Existing synchronization ports
//! supply the kernel dispatch; no new hooks or callee identities.

use crate::kernel::condvar::{condvar_broadcast, CondVar};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

#[repr(C)]
pub struct WorkPendingOwner {
    pub preserved: [u32; 10],
    pub pending: u8,
    pub padding: [u8; 3],
    pub mutex: Mutex,
    pub changed: CondVar,
}

/// Publish pending work and wake every current waiter under the owner lock.
///
/// # Safety
/// `owner` must be a writable live owner with valid mutex and waiter fields.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn work_pending_notify(owner: *mut WorkPendingOwner) {
    let mutex = core::ptr::addr_of_mut!((*owner).mutex);
    mutex_lock(mutex);
    core::ptr::addr_of_mut!((*owner).pending).write_volatile(1);
    condvar_broadcast(core::ptr::addr_of_mut!((*owner).changed));
    mutex_unlock(mutex);
}
