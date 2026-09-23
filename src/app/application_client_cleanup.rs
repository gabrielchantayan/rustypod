//! `application_client_cleanup` — original: `FUN_0814bb18` @ **0x0814bb18**
//! (**140 bytes**, `0x0814bb18..0x0814bba4`; the next function starts at
//! `0x0814bba4`). Raw ARM decoding finds **3 incoming plain `bl` call sites**
//! (two in `FUN_0814be3c`, one in `FUN_0814c034`) and no predicated incoming
//! `bl`; the body contains 11 unconditional `bl` instructions and one tail
//! branch on each returning path.
//!
//! Algorithm: reject both live cleanup-state words, clear them, erase and
//! commit an attached client when its handle resolves, then either broadcast
//! the embedded condition variable or hand the handle to the global cleanup
//! context. Deliberate deviation: `FUN_0814b80c` and the global cleanup
//! routine at `0x0818a860` have no recovered identities, so target builds
//! call their verified addresses and host builds inject them.

use crate::cxx::handle::handle_deref_or_null;
use crate::heap::client_commit::client_commit;
use crate::heap::client_erase::client_erase;
use crate::kernel::condvar::condvar_broadcast;

const HANDLE_OFFSET: usize = 0x14;
const DEQUE_OFFSET: usize = 0x24;
const ATTACHED_OFFSET: usize = 0x44;
const CLEANUP_STATE_OFFSET: usize = 0x64;
const PENDING_OFFSET: usize = 0x68;
const CONDVAR_OFFSET: usize = 0x6c;
const RETAIL_REJECT_CLEANUP: usize = 0x0814_b80c;
const RETAIL_GLOBAL_CLEANUP: usize = 0x0818_a860;
const RETAIL_GLOBAL_CONTEXT: usize = 0x089c_b1b4;

type RejectCleanup = unsafe extern "C" fn(*mut u8);
type GlobalCleanup = unsafe extern "C" fn(*mut u8, *mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn reject_cleanup(this: *mut u8) {
    let call: RejectCleanup = core::mem::transmute(RETAIL_REJECT_CLEANUP);
    call(this);
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_cleanup(handle: *mut u8) {
    let call: GlobalCleanup = core::mem::transmute(RETAIL_GLOBAL_CLEANUP);
    call((RETAIL_GLOBAL_CONTEXT as *const *mut u8).read_volatile(), handle);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct ApplicationClientCleanupOps {
    pub reject_cleanup: RejectCleanup,
    pub client_erase: unsafe extern "C" fn(*mut u8, *mut u8),
    pub client_commit: unsafe extern "C" fn(*mut u8) -> i32,
    pub condvar_broadcast: unsafe extern "C" fn(*mut u8),
    pub global_cleanup: GlobalCleanup,
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_reject(_: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_erase(_: *mut u8, _: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_commit(_: *mut u8) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_broadcast(_: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_global_cleanup(_: *mut u8, _: *mut u8) {}
#[cfg(not(target_os = "none"))]
pub const DEFAULT_APPLICATION_CLIENT_CLEANUP_OPS: ApplicationClientCleanupOps = ApplicationClientCleanupOps { reject_cleanup: no_reject, client_erase: no_erase, client_commit: no_commit, condvar_broadcast: no_broadcast, global_cleanup: no_global_cleanup };
#[cfg(not(target_os = "none"))]
pub static mut APPLICATION_CLIENT_CLEANUP_OPS: ApplicationClientCleanupOps = DEFAULT_APPLICATION_CLIENT_CLEANUP_OPS;

/// Cleans the attached client and wakes waiters, or transfers its handle to
/// the global cleanup context when one remains.
///
/// # Safety
/// `this` must denote the retail object layout through `+0x6c`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn application_client_cleanup(this: *mut u8) {
    #[cfg(target_os = "none")]
    {
        if (this.add(CLEANUP_STATE_OFFSET) as *const u32).read_volatile() != 0 { reject_cleanup(this); }
        (this.add(CLEANUP_STATE_OFFSET) as *mut u32).write_volatile(0);
        if (this.add(ATTACHED_OFFSET) as *const u32).read_volatile() != 0 {
            let client = handle_deref_or_null(this.add(HANDLE_OFFSET).cast());
            client_erase(client, this.add(DEQUE_OFFSET).cast());
            client_commit(handle_deref_or_null(this.add(HANDLE_OFFSET).cast()));
        }
        if (this.add(PENDING_OFFSET) as *const u32).read_volatile() != 0 { reject_cleanup(this); }
        (this.add(PENDING_OFFSET) as *mut u32).write_volatile(0);
        let client = handle_deref_or_null(this.add(HANDLE_OFFSET).cast());
        if client.is_null() { condvar_broadcast(this.add(CONDVAR_OFFSET).cast()); } else { global_cleanup(this.add(HANDLE_OFFSET)); }
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = APPLICATION_CLIENT_CLEANUP_OPS;
        let handle = || {
            let cell = (this.add(HANDLE_OFFSET) as *const *mut *mut u8).read_unaligned();
            if cell.is_null() { core::ptr::null_mut() } else { cell.read() }
        };
        if (this.add(CLEANUP_STATE_OFFSET) as *const u32).read_unaligned() != 0 { (ops.reject_cleanup)(this); }
        (this.add(CLEANUP_STATE_OFFSET) as *mut u32).write_unaligned(0);
        if (this.add(ATTACHED_OFFSET) as *const u32).read_unaligned() != 0 {
            (ops.client_erase)(handle(), this.add(DEQUE_OFFSET));
            (ops.client_commit)(handle());
        }
        if (this.add(PENDING_OFFSET) as *const u32).read_unaligned() != 0 { (ops.reject_cleanup)(this); }
        (this.add(PENDING_OFFSET) as *mut u32).write_unaligned(0);
        if handle().is_null() { (ops.condvar_broadcast)(this.add(CONDVAR_OFFSET)); } else { (ops.global_cleanup)(core::ptr::null_mut(), this.add(HANDLE_OFFSET)); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<([u8; 3], usize)> = Mutex::new(([0; 3], 0));
    unsafe extern "C" fn erase(_: *mut u8, _: *mut u8) { let mut events = EVENTS.lock(); let i = events.1; events.0[i] = 1; events.1 = i + 1; }
    unsafe extern "C" fn commit(_: *mut u8) -> i32 { let mut events = EVENTS.lock(); let i = events.1; events.0[i] = 2; events.1 = i + 1; 0 }
    unsafe extern "C" fn broadcast(_: *mut u8) { let mut events = EVENTS.lock(); let i = events.1; events.0[i] = 3; events.1 = i + 1; }
    unsafe extern "C" fn global(_: *mut u8, _: *mut u8) { let mut events = EVENTS.lock(); let i = events.1; events.0[i] = 4; events.1 = i + 1; }
    #[test]
    fn null_handle_broadcasts_after_clearing_state() {
        let _lock = LOCK.lock(); *EVENTS.lock() = ([0; 3], 0); let mut object = [0u8; 0x80];
        unsafe { APPLICATION_CLIENT_CLEANUP_OPS = ApplicationClientCleanupOps { client_erase: erase, client_commit: commit, condvar_broadcast: broadcast, global_cleanup: global, ..DEFAULT_APPLICATION_CLIENT_CLEANUP_OPS }; application_client_cleanup(object.as_mut_ptr()); }
        assert_eq!(*EVENTS.lock(), ([3, 0, 0], 1)); assert_eq!(unsafe { (object.as_ptr().add(0x64) as *const u32).read_unaligned() }, 0);
    }
    #[test]
    fn attached_client_is_erased_committed_then_transferred() {
        let _lock = LOCK.lock(); *EVENTS.lock() = ([0; 3], 0); let mut object = [0u8; 0x80]; let mut client = 0u8; let mut cell = &mut client as *mut u8;
        unsafe { (object.as_mut_ptr().add(HANDLE_OFFSET) as *mut *mut u8).write_unaligned((&mut cell as *mut *mut u8).cast()); (object.as_mut_ptr().add(ATTACHED_OFFSET) as *mut u32).write_unaligned(1); }
        unsafe { APPLICATION_CLIENT_CLEANUP_OPS = ApplicationClientCleanupOps { client_erase: erase, client_commit: commit, condvar_broadcast: broadcast, global_cleanup: global, ..DEFAULT_APPLICATION_CLIENT_CLEANUP_OPS }; application_client_cleanup(object.as_mut_ptr()); }
        assert_eq!(*EVENTS.lock(), ([1, 2, 4], 3));
    }
}
