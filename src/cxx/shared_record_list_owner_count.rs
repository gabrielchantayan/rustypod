//! Locked shared-record list count — `FUN_081a88b4` @ `0x081a88b4`.
//!
//! True extent [0x081a88b4,0x081a88dc): 40 instruction bytes; the next
//! function begins with ldr r0,[r1]. Whole-image ARM word decoding finds two
//! incoming plain BLs (0x081a8758, 0x081a8774), zero predicated incoming BLs,
//! and two outgoing plain BLs (lock 0x082621a8, unlock 0x082621ac), zero
//! predicated outgoing BLs. Lock the embedded mutex at target +0x28, snapshot
//! the count at +0x24, unlock, and return the snapshot. Ignore both statuses.
//!
//! Deliberate deviations: reuse the canonical POSIX mutex ports behind the
//! verified branch veneers. Reuse SharedRecordListOwner's repr(C) fields so
//! native-width host pointers shift the count and mutex together, without
//! changing target offsets. No NULL guard or invented error handling.

use super::shared_record_list_owner_construct::SharedRecordListOwner;
use crate::kernel::posix_mutex::{posix_mutex_lock, posix_mutex_unlock, PosixMutex};
use core::ptr::{addr_of, addr_of_mut};

/// # Safety
/// `owner` must reference a live, writable owner with an initialized mutex;
/// its count must be protected by that mutex and configured mutex operations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_record_list_owner_count(owner: *mut SharedRecordListOwner) -> u32 {
    let mutex = addr_of_mut!((*owner).mutex).cast::<PosixMutex>();
    posix_mutex_lock(mutex);
    let count = addr_of!((*owner).count).read();
    posix_mutex_unlock(mutex);
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::posix_mutex::{DEFAULT_POSIX_MUTEX_OPS, POSIX_MUTEX_OPS};

    struct Restore(crate::kernel::posix_mutex::PosixMutexOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { POSIX_MUTEX_OPS = self.0; } }
    }

    unsafe fn owner_from_cell(cell: *mut u32) -> *mut SharedRecordListOwner {
        cell.cast::<u8>().sub(0x14 + core::mem::offset_of!(SharedRecordListOwner, mutex)).cast()
    }

    unsafe extern "C" fn publish_count(cell: *mut u32) -> u32 {
        (*owner_from_cell(cell)).count = u32::MAX;
        0
    }

    unsafe extern "C" fn change_after_snapshot(cell: *mut u32) -> u32 {
        (*owner_from_cell(cell)).count = 17;
        0x27
    }

    #[test]
    fn snapshots_after_acquisition_before_release_even_when_release_fails() {
        let _guard = crate::testing::POSIX_MUTEX_OPS_TEST_LOCK.lock().unwrap();
        unsafe {
            let _restore = Restore(POSIX_MUTEX_OPS);
            POSIX_MUTEX_OPS = DEFAULT_POSIX_MUTEX_OPS;
            POSIX_MUTEX_OPS.sem_acquire = publish_count;
            POSIX_MUTEX_OPS.sem_release = change_after_snapshot;
            let mut owner: SharedRecordListOwner = core::mem::zeroed();
            owner.count = 0;
            assert_eq!(shared_record_list_owner_count(&mut owner), u32::MAX);
            assert_eq!(owner.count, 17);
            let mutex = &*addr_of!(owner.mutex).cast::<PosixMutex>();
            assert_eq!((mutex.owner, mutex.recursion), (0, 0));
        }
    }

    #[test]
    fn recursive_reads_preserve_outer_hold_and_failed_lock_still_reads() {
        let _guard = crate::testing::POSIX_MUTEX_OPS_TEST_LOCK.lock().unwrap();
        unsafe {
            let _restore = Restore(POSIX_MUTEX_OPS);
            POSIX_MUTEX_OPS = DEFAULT_POSIX_MUTEX_OPS;
            let mut owner: SharedRecordListOwner = core::mem::zeroed();
            let mutex = addr_of_mut!(owner.mutex).cast::<PosixMutex>();
            (*mutex).owner = 1;
            (*mutex).attr_flags = 2 << 20;
            (*mutex).recursion = 3;
            for count in [0, 1, 0x8000_0000, u32::MAX] {
                owner.count = count;
                assert_eq!(shared_record_list_owner_count(&mut owner), count);
                assert_eq!(((*mutex).owner, (*mutex).recursion), (1, 3));
            }
            (*mutex).recursion = u16::MAX;
            owner.count = 42;
            assert_eq!(shared_record_list_owner_count(&mut owner), 42);
            // Lock overflows, but the unconditional unlock still decrements.
            assert_eq!(((*mutex).owner, (*mutex).recursion), (1, u16::MAX - 1));
        }
    }
}
