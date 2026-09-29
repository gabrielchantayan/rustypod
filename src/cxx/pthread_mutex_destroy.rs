//! POSIX mutex destruction.

/// `pthread_mutex_destroy` — retailOS load address `0x082e82a4`, 84 bytes
/// (`0x082e82a4..0x082e82f8`: 76 bytes of code plus the 4-byte magic literal).
///
/// The raw body rejects NULL and objects whose first word is not `0x4d555458`
/// with `EINVAL` (26). It rejects a nonzero owner word at +4 or semaphore word
/// at +8 with `EBUSY` (20). Otherwise it calls `kernel_slot_create` on the
/// semaphore-handle cell at +20, ignores that status, clears the magic word,
/// and returns zero. It has one unconditional internal `bl` and no predicated
/// `bl`; raw decoding finds two unconditional incoming `bl` callers and no
/// predicated incoming calls.
///
/// Deliberate deviation: the ARM call is direct to `kernel_slot_create`; the
/// host-testable port reaches that existing callee through a volatile dispatch
/// slot. The default slot calls the real port on the firmware target.

const MUTEX_MAGIC: u32 = 0x4d55_5458;
const EBUSY: u32 = 20;
const EINVAL: u32 = 26;
const KERNEL_SLOT_OFFSET: usize = 20;

#[derive(Clone, Copy)]
pub struct PthreadMutexDestroyOps {
    pub kernel_slot_create: unsafe extern "C" fn(slot: *mut u8) -> u32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn call_kernel_slot_create(slot: *mut u8) -> u32 {
    crate::kernel::kernel_slot_create::kernel_slot_create(slot.cast()) as u32
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn call_kernel_slot_create(_slot: *mut u8) -> u32 {
    0
}

pub const DEFAULT_PTHREAD_MUTEX_DESTROY_OPS: PthreadMutexDestroyOps = PthreadMutexDestroyOps {
    kernel_slot_create: call_kernel_slot_create,
};

pub static mut PTHREAD_MUTEX_DESTROY_OPS: PthreadMutexDestroyOps = DEFAULT_PTHREAD_MUTEX_DESTROY_OPS;

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut u8) -> u32 {
    if mutex.is_null() || mutex.cast::<u32>().read() != MUTEX_MAGIC {
        return EINVAL;
    }
    if mutex.add(4).cast::<u32>().read() != 0 || mutex.add(8).cast::<u32>().read() != 0 {
        return EBUSY;
    }

    let kernel_slot_create = core::ptr::read_volatile(core::ptr::addr_of!(PTHREAD_MUTEX_DESTROY_OPS.kernel_slot_create));
    kernel_slot_create(mutex.add(KERNEL_SLOT_OFFSET));
    mutex.cast::<u32>().write(0);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SLOT_ARGUMENT: *mut u8 = core::ptr::null_mut();
    static mut SLOT_STATUS: u32 = 0;
    static mut SLOT_CALLS: usize = 0;

    unsafe extern "C" fn recording_kernel_slot_create(slot: *mut u8) -> u32 {
        SLOT_ARGUMENT = slot;
        SLOT_CALLS += 1;
        SLOT_STATUS
    }

    struct OpsGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(PTHREAD_MUTEX_DESTROY_OPS)
                    .write_volatile(DEFAULT_PTHREAD_MUTEX_DESTROY_OPS);
            }
        }
    }

    fn install_slot_recorder(status: u32) -> OpsGuard {
        let lock = OPS_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            SLOT_ARGUMENT = core::ptr::null_mut();
            SLOT_STATUS = status;
            SLOT_CALLS = 0;
            core::ptr::addr_of_mut!(PTHREAD_MUTEX_DESTROY_OPS).write_volatile(PthreadMutexDestroyOps {
                kernel_slot_create: recording_kernel_slot_create,
            });
        }
        OpsGuard { _lock: lock }
    }

    #[test]
    fn null_or_invalid_magic_returns_einval_without_a_callee_call() {
        let _ops = install_slot_recorder(0);
        let mut mutex = [0u32; 6];

        assert_eq!(unsafe { pthread_mutex_destroy(core::ptr::null_mut()) }, EINVAL);
        assert_eq!(unsafe { pthread_mutex_destroy(mutex.as_mut_ptr().cast()) }, EINVAL);
        unsafe { assert_eq!(SLOT_CALLS, 0) };
    }

    #[test]
    fn live_owner_or_semaphore_returns_ebusy_without_writing_magic() {
        let _ops = install_slot_recorder(0);
        let mut mutex = [MUTEX_MAGIC, 1, 0, 0, 0, 0];
        assert_eq!(unsafe { pthread_mutex_destroy(mutex.as_mut_ptr().cast()) }, EBUSY);
        assert_eq!(mutex[0], MUTEX_MAGIC);

        mutex[1] = 0;
        mutex[2] = 1;
        assert_eq!(unsafe { pthread_mutex_destroy(mutex.as_mut_ptr().cast()) }, EBUSY);
        assert_eq!(mutex[0], MUTEX_MAGIC);
        unsafe { assert_eq!(SLOT_CALLS, 0) };
    }

    #[test]
    fn inactive_mutex_calls_slot_ignores_its_status_and_clears_magic() {
        let _ops = install_slot_recorder(20);
        let mut mutex = [MUTEX_MAGIC, 0, 0, 0xa5a5_a5a5, 0x5a5a_5a5a, 0x1234_5678];
        let mutex_ptr = mutex.as_mut_ptr().cast::<u8>();

        assert_eq!(unsafe { pthread_mutex_destroy(mutex_ptr) }, 0);
        unsafe {
            assert_eq!(SLOT_CALLS, 1);
            assert_eq!(SLOT_ARGUMENT, mutex_ptr.add(KERNEL_SLOT_OFFSET));
        }
        assert_eq!(mutex, [0, 0, 0, 0xa5a5_a5a5, 0x5a5a_5a5a, 0x1234_5678]);
    }
}
