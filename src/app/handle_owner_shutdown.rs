//! Handle-owner shutdown — FUN_0814c2a0 @ 0x0814c2a0.
//! Raw extent [0x0814c2a0,0x0814c320): 124 code bytes and a four-byte
//! event literal. Two inbound plain BLs, seven outbound plain BLs, no
//! predicated BLs. Lock +0x58, bind a stack condition variable to that lock,
//! post event 0x207 with its address, wait while the two-level handle at
//! +0x14 resolves non-null, clear +0x6c, destroy the stack base, and unlock.
//! The event-post result is deliberately ignored, including failure.
//!
//! Deviations: native pointer fields widen on hosts; target offsets remain
//! exact. The unported event-post helper uses its verified address on device
//! and an explicit host seam. Tests substitute the blocking wait only, to
//! model spurious wakes and asynchronous handle clearing deterministically.
//! LLVM may remove redundant pre-bind zero stores and the empty base
//! destructor. Native smoke used the host test configuration because six
//! unrelated missing functions prevent the normal host library build.

use crate::kernel::sync_mutex::{Mutex, mutex_lock, mutex_unlock};
use crate::kernel::condvar::{CondVar, ListHead, condvar_bind};
#[cfg(not(test))]
use crate::kernel::condvar::condvar_wait_forever;
use crate::cxx::handle::handle_deref_or_null;
use crate::cxx::state_object_destroy::state_object_destroy;
use core::ptr::null_mut;

#[repr(C)]
pub struct HandleOwner {
    pub prefix: [u32; 5],
    pub handle: *const *mut u8,
    pub middle: [u32; 16],
    pub mutex: Mutex,
    pub trailing: [u32; 3],
    pub active: u32,
}

type PostEvent = unsafe extern "C" fn(*mut HandleOwner, u32, *mut CondVar) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_post(_: *mut HandleOwner, _: u32, _: *mut CondVar) -> u32 {
    panic!("retailOS event-post helper at 0x0814ba28 is not installed")
}
#[cfg(not(target_os = "none"))]
pub static mut HANDLE_OWNER_POST_EVENT: PostEvent = missing_post;

#[inline(always)]
unsafe fn post_event(owner: *mut HandleOwner, condition: *mut CondVar) {
    #[cfg(target_os = "none")]
    let post = core::mem::transmute::<usize, PostEvent>(0x0814_ba28);
    #[cfg(not(target_os = "none"))]
    let post = core::ptr::read_volatile(core::ptr::addr_of!(HANDLE_OWNER_POST_EVENT));
    let _ = post(owner, 0x207, condition);
}

#[cfg(test)]
static mut TEST_WAIT: unsafe fn(*mut CondVar) = test_wait_missing;
#[cfg(test)]
unsafe fn test_wait_missing(_: *mut CondVar) { panic!("test wait not installed") }

/// # Safety
/// `owner` must be a live retailOS object with a valid lock and readable
/// handle cell. Event delivery must keep the stack condvar alive until the
/// handle clears, and the wait service must obey its normal queue contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn handle_owner_shutdown(owner: *mut HandleOwner) {
    let mutex = core::ptr::addr_of_mut!((*owner).mutex);
    mutex_lock(mutex);
    let mut condition = CondVar {
        lock_obj: null_mut(),
        waiters: ListHead { head: null_mut(), tail: null_mut() },
    };
    condvar_bind(&mut condition, mutex.cast());
    post_event(owner, &mut condition);
    while !handle_deref_or_null(core::ptr::addr_of!((*owner).handle)).is_null() {
        #[cfg(not(test))]
        condvar_wait_forever(&mut condition);
        #[cfg(test)]
        TEST_WAIT(&mut condition);
    }
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*owner).active), 0);
    state_object_destroy((&mut condition as *mut CondVar).cast());
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex as TestMutex;
    static LOCK: TestMutex<()> = TestMutex::new(());
    static mut OWNER: *mut HandleOwner = null_mut();
    static mut WAKES: usize = 0;
    static mut POST_RESULT: u32 = 0;

    unsafe extern "C" fn post(owner: *mut HandleOwner, event: u32, cv: *mut CondVar) -> u32 {
        assert_eq!(event, 0x207);
        assert_eq!((*cv).lock_obj, core::ptr::addr_of_mut!((*owner).mutex).cast());
        assert!((*cv).waiters.head.is_null());
        assert!((*cv).waiters.tail.is_null());
        assert_eq!((*owner).active, 0xa5a5a5a5);
        OWNER = owner;
        POST_RESULT
    }
    unsafe fn wake(_: *mut CondVar) {
        assert_eq!((*OWNER).active, 0xa5a5a5a5);
        WAKES += 1;
        // First wake is spurious. Second replaces the handle slot entirely:
        // the loop must reload it, not cache the original cell.
        if WAKES == 2 { (*OWNER).handle = core::ptr::null(); }
        assert!(WAKES <= 2);
    }

    #[test]
    fn null_slot_null_pointee_and_spurious_wake_with_failed_post() {
        let _guard = LOCK.lock();
        unsafe {
            let saved_post = HANDLE_OWNER_POST_EVENT;
            let saved_wait = TEST_WAIT;
            HANDLE_OWNER_POST_EVENT = post;
            TEST_WAIT = wake;
            for (live, null_slot, result, expected_wakes) in [
                (false, true, 1, 0), (false, false, 0, 0), (true, false, 0, 2),
            ] {
                let mut cell = if live { core::ptr::dangling_mut::<u8>() } else { null_mut() };
                let mut owner = HandleOwner {
                    prefix: [0x12345678; 5],
                    handle: if null_slot { core::ptr::null() } else { &mut cell },
                    middle: [0xabcdef01; 16],
                    mutex: Mutex { sem_cell: null_mut(), unused: 0x87654321 },
                    trailing: [0xfedcba98; 3], active: 0xa5a5a5a5,
                };
                WAKES = 0;
                POST_RESULT = result;
                handle_owner_shutdown(&mut owner);
                assert_eq!(WAKES, expected_wakes);
                assert_eq!(owner.active, 0);
                assert_eq!(owner.prefix, [0x12345678; 5]);
                assert_eq!(owner.middle, [0xabcdef01; 16]);
                assert_eq!(owner.trailing, [0xfedcba98; 3]);
                assert_eq!(owner.mutex.unused, 0x87654321);
            }
            HANDLE_OWNER_POST_EVENT = saved_post;
            TEST_WAIT = saved_wait;
        }
    }
}
