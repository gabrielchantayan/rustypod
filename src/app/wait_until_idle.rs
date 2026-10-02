//! Waits for an opaque owner's busy byte to clear under its embedded mutex.

use crate::kernel::condvar::{condvar_wait_forever, CondVar};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// Synchronization tail; ARM offsets are busy +0x22d, mutex +0x230,
/// condition variable +0x238. Pointer fields widen together on hosts.
#[repr(C)]
pub struct IdleWaitOwner {
    pub opaque: [u8; 0x22d],
    pub busy: u8,
    pub padding: [u8; 2],
    pub mutex: Mutex,
    pub condvar: CondVar,
}

/// Original: FUN_08295fa0 @ 0x08295fa0, 60 bytes, ending at the next
/// function's push @ 0x08295fdc. Verified inbound BL: two plain calls
/// (0x081003dc, 0x0810078c), zero predicated calls. The body has two plain
/// BL instructions (mutex_lock and condvar_wait_forever), zero predicated
/// BL instructions, and a tail B to mutex_unlock @ 0x0807f6a0.
///
/// Lock the owner's mutex, repeatedly wait while busy is nonzero, and
/// unlock after observing zero. Every wake rechecks the predicate.
/// Deliberate deviations: repr(C) fields widen for host pointers while
/// retaining target offsets; volatile predicate reads preserve external
/// updates; the tail branch is expressed as a return-position Rust call.
///
/// # Safety
/// `owner` must point to a valid, aligned owner with initialized mutex and
/// condition variable. Busy updates must obey the same locking protocol.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn wait_until_idle(owner: *mut IdleWaitOwner) {
    let mutex = core::ptr::addr_of_mut!((*owner).mutex);
    let condvar = core::ptr::addr_of_mut!((*owner).condvar);
    mutex_lock(mutex);
    while core::ptr::read_volatile(core::ptr::addr_of!((*owner).busy)) != 0 {
        condvar_wait_forever(condvar);
    }
    mutex_unlock(mutex);
}
