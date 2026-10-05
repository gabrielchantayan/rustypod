//! `block_manager_secondary_mutex_unlock` — `FUN_0818b100` at 0x0818b100.
//!
//! True size: 8 bytes, ending at the next push prologue at 0x0818b108.
//! Raw words e2800f59 ea035b46 encode `add r0,r0,#0x164; b 0x08261e24`.
//! Two incoming plain BL sites (0x08207d78, 0x08207e80), zero predicated
//! incoming BLs; zero internal BLs. Derives the block manager's secondary
//! mutex at +0x164 and returns the unlock status via a tail branch.
//!
//! Deliberate deviation: resolve the bare branch alias at 0x08261e24 to
//! the existing canonical `posix_mutex_unlock` port at 0x082e83d8. Its
//! existing kernel operation seams and their documented limitations apply.

use crate::kernel::posix_mutex::{posix_mutex_unlock, PosixMutex};

const SECONDARY_MUTEX_OFFSET: usize = 0x164;

/// # Safety
/// `block_manager` must contain a valid, aligned `PosixMutex` at +0x164.
/// The original performs no object-pointer validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn block_manager_secondary_mutex_unlock(block_manager: *mut u8) -> u32 {
    posix_mutex_unlock(block_manager.add(SECONDARY_MUTEX_OFFSET).cast())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::posix_mutex::{PosixMutexOps, DEFAULT_POSIX_MUTEX_OPS, POSIX_MUTEX_OPS};
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
    unsafe extern "C" fn release(cell: *mut u32) -> u32 {
        *cell += 1;
        0x35
    }

    #[test]
    fn secondary_mutex_ownership_and_recursive_release() {
        let _guard = crate::testing::POSIX_MUTEX_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let _restore = unsafe { Restore(addr_of!(POSIX_MUTEX_OPS).read()) };
        unsafe {
            addr_of_mut!(POSIX_MUTEX_OPS).write(PosixMutexOps {
                current_thread, sem_release: release, ..DEFAULT_POSIX_MUTEX_OPS
            });
        }
        let mut manager = Manager {
            prefix: [0x5a5a5a5a; SECONDARY_MUTEX_OFFSET / 4],
            mutex: PosixMutex {
                magic: 0x4d555458, owner: 99, reserved_08: 0,
                attr_flags: 2 << 20, reserved_10: 0, recursion: 2, sem_handle: 10,
            },
            suffix: 0xa5a5a5a5,
        };
        let object = addr_of_mut!(manager).cast::<u8>();
        unsafe {
            assert_eq!(block_manager_secondary_mutex_unlock(object), 5);
            assert_eq!((manager.mutex.owner, manager.mutex.recursion, manager.mutex.sem_handle), (99, 2, 10));
            manager.mutex.owner = 7;
            assert_eq!(block_manager_secondary_mutex_unlock(object), 0);
            assert_eq!((manager.mutex.owner, manager.mutex.recursion, manager.mutex.sem_handle), (7, 1, 10));
            assert_eq!(block_manager_secondary_mutex_unlock(object), 0x35);
            assert_eq!((manager.mutex.owner, manager.mutex.recursion, manager.mutex.sem_handle), (0, 0, 11));
            assert_eq!(block_manager_secondary_mutex_unlock(object), 5);
            assert_eq!(manager.mutex.sem_handle, 11);
        }
        assert_eq!(manager.prefix, [0x5a5a5a5a; SECONDARY_MUTEX_OFFSET / 4]);
        assert_eq!(manager.suffix, 0xa5a5a5a5);
    }
}
