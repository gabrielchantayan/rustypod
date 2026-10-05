//! `block_manager_secondary_mutex_lock` — `FUN_0818af74` at 0x0818af74.
//!
//! True size: 8 bytes, ending at the independent push prologue at 0x0818af7c.
//! Raw words e2800f59 ea035ba8 encode `add r0,r0,#0x164; b 0x08261e20`.
//! Two incoming plain BL sites (0x08207c84, 0x08207d9c), zero predicated
//! incoming BLs; zero internal BLs. Derives the block manager's secondary
//! mutex at +0x164 and returns the blocking acquire status via a tail branch.
//!
//! Deliberate deviation: resolve the mapped bare branch alias at 0x08261e20
//! to the canonical `posix_mutex_lock` port at 0x082e8390. Its existing
//! kernel operation seams and documented limitations apply; no new seam.

use crate::kernel::posix_mutex::posix_mutex_lock;

const SECONDARY_MUTEX_OFFSET: usize = 0x164;

/// # Safety
/// `block_manager` must contain a valid, aligned PosixMutex at +0x164.
/// The original performs no object-pointer validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn block_manager_secondary_mutex_lock(block_manager: *mut u8) -> u32 {
    posix_mutex_lock(block_manager.add(SECONDARY_MUTEX_OFFSET).cast())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::posix_mutex::{PosixMutex, PosixMutexOps, DEFAULT_POSIX_MUTEX_OPS, POSIX_MUTEX_OPS};
    use core::ptr::{addr_of, addr_of_mut};

    #[repr(C)]
    struct Manager {
        prefix: [u32; SECONDARY_MUTEX_OFFSET / 4],
        mutex: PosixMutex,
        suffix: u32,
    }

    struct Restore(PosixMutexOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(POSIX_MUTEX_OPS).write(self.0); }
        }
    }

    unsafe extern "C" fn current_thread() -> u32 { 7 }
    unsafe extern "C" fn acquire(cell: *mut u32) -> u32 {
        if *cell == 0 { return 0x35; }
        *cell -= 1;
        0
    }

    #[test]
    fn secondary_lock_acquire_failure_recursion_and_overflow() {
        let _guard = crate::testing::POSIX_MUTEX_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let _restore = unsafe { Restore(addr_of!(POSIX_MUTEX_OPS).read()) };
        unsafe {
            addr_of_mut!(POSIX_MUTEX_OPS).write(PosixMutexOps {
                current_thread, sem_acquire: acquire, ..DEFAULT_POSIX_MUTEX_OPS
            });
        }
        let mut manager = Manager {
            prefix: [0x5a5a5a5a; SECONDARY_MUTEX_OFFSET / 4],
            mutex: PosixMutex {
                magic: 0x4d555458, owner: 99, reserved_08: 0,
                attr_flags: 2 << 20, reserved_10: 0, recursion: 2, sem_handle: 0,
            },
            suffix: 0xa5a5a5a5,
        };
        let object = addr_of_mut!(manager).cast::<u8>();
        unsafe {
            assert_eq!(block_manager_secondary_mutex_lock(object), 0x35);
            assert_eq!((manager.mutex.owner, manager.mutex.recursion), (99, 2));
            manager.mutex.sem_handle = 1;
            assert_eq!(block_manager_secondary_mutex_lock(object), 0);
            assert_eq!((manager.mutex.owner, manager.mutex.recursion, manager.mutex.sem_handle), (7, 1, 0));
            assert_eq!(block_manager_secondary_mutex_lock(object), 0);
            assert_eq!((manager.mutex.owner, manager.mutex.recursion, manager.mutex.sem_handle), (7, 2, 0));
            manager.mutex.recursion = 0xfffe;
            assert_eq!(block_manager_secondary_mutex_lock(object), 0);
            assert_eq!(manager.mutex.recursion, 0xffff);
            assert_eq!(block_manager_secondary_mutex_lock(object), 0x27);
            assert_eq!((manager.mutex.owner, manager.mutex.recursion, manager.mutex.sem_handle), (7, 0xffff, 0));
            manager.mutex.attr_flags = 1 << 20;
            assert_eq!(block_manager_secondary_mutex_lock(object), 0xf);
            assert_eq!(manager.mutex.recursion, 0xffff);
        }
        assert_eq!(manager.prefix, [0x5a5a5a5a; SECONDARY_MUTEX_OFFSET / 4]);
        assert_eq!(manager.suffix, 0xa5a5a5a5);
    }
}
