//! WindowManager scheduler lock acquisition.
//!
//! `scheduler_lock` — original: `FUN_08148cc8` @ 0x08148cc8 (28 bytes,
//! including its literal pool; 24 instruction bytes). It calls
//! `kernel_running` and, only after the kernel starts, tail-calls
//! `mutex_lock_counted` for the global CountedMutex at 0x08a77d00.

use crate::kernel::sync_mutex::{kernel_running, mutex_lock_counted, mutex_unlock_counted, CountedMutex};
#[cfg(not(target_os = "none"))]
use crate::kernel::sync_mutex::Mutex;

/// The WindowManager scheduler's counted mutex.
const SCHEDULER_MUTEX_ADDRESS: usize = 0x08a7_7d00;

#[cfg(not(target_os = "none"))]
static mut HOST_SCHEDULER_MUTEX: CountedMutex = CountedMutex {
    mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
    hold_count: 0,
};

#[inline(always)]
unsafe fn scheduler_mutex() -> *mut CountedMutex {
    #[cfg(target_os = "none")]
    {
        SCHEDULER_MUTEX_ADDRESS as *mut CountedMutex
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_SCHEDULER_MUTEX)
    }
}

#[cfg(test)]
static mut KERNEL_RUNNING: unsafe extern "C" fn() -> i32 = kernel_running;
#[cfg(test)]
static mut LOCK_COUNTED: unsafe extern "C" fn(*mut CountedMutex) = mutex_lock_counted;
#[cfg(test)]
static mut UNLOCK_COUNTED: unsafe extern "C" fn(*mut CountedMutex) = mutex_unlock_counted;

#[inline(always)]
unsafe fn scheduler_kernel_running() -> i32 {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(KERNEL_RUNNING))()
    }
    #[cfg(not(test))]
    {
        kernel_running()
    }
}

#[inline(always)]
unsafe fn scheduler_mutex_lock(lock: *mut CountedMutex) {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(LOCK_COUNTED))(lock);
    }
    #[cfg(not(test))]
    {
        mutex_lock_counted(lock);
    }
}

#[inline(always)]
unsafe fn scheduler_mutex_unlock(lock: *mut CountedMutex) {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(UNLOCK_COUNTED))(lock);
    }
    #[cfg(not(test))]
    {
        mutex_unlock_counted(lock);
    }
}

/// scheduler_lock — original: `FUN_08148cc8` @ 0x08148cc8 (28 bytes;
/// 24-byte instruction body plus literal pool at 0x08148ce4; 5 direct
/// inbound `bl` call sites, all plain; 0 predicated `bl` call sites).
///
/// Calls `kernel_running` first. A zero result returns without touching the
/// scheduler mutex. A nonzero result loads the global `CountedMutex` at
/// 0x08a77d00 and tail-calls `mutex_lock_counted`, which waits then increments
/// its +8 hold count.
///
/// # Deliberate deviations
///
/// Host builds use private callback seams and a local `CountedMutex` because
/// the firmware global is not mapped there. Target builds directly call the
/// two ported callees and use the fixed load address.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scheduler_lock() {
    if scheduler_kernel_running() != 0 {
        scheduler_mutex_lock(scheduler_mutex());
    }
}

/// scheduler_unlock — original: `FUN_08148dd4` @ 0x08148dd4 (28 bytes;
/// 28-byte instruction body; 3 direct inbound `bl` call sites, all plain;
/// 0 predicated `bl` call sites).
///
/// Calls `kernel_running` first. A zero result returns without touching the
/// scheduler mutex. A nonzero result loads the global `CountedMutex` at
/// 0x08a77d00 and tail-calls `mutex_unlock_counted`, decrementing its +8 hold
/// count before signalling its semaphore.
///
/// # Deliberate deviations
///
/// Host builds use private callback seams and a local `CountedMutex` because
/// the firmware global is not mapped there. Target builds directly call the
/// two ported callees and use the fixed load address.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scheduler_unlock() {
    if scheduler_kernel_running() != 0 {
        scheduler_mutex_unlock(scheduler_mutex());
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex as TestMutex;
    use std::sync::LazyLock;

    static TEST_LOCK: LazyLock<TestMutex<()>> = LazyLock::new(|| TestMutex::new(()));
    static mut RUNNING_RESULT: i32 = 0;
    static mut LOCK_CALLS: u32 = 0;
    static mut LOCK_ARGUMENT: *mut CountedMutex = core::ptr::null_mut();
    static mut UNLOCK_CALLS: u32 = 0;
    static mut UNLOCK_ARGUMENT: *mut CountedMutex = core::ptr::null_mut();

    unsafe extern "C" fn mock_kernel_running() -> i32 { RUNNING_RESULT }
    unsafe extern "C" fn mock_mutex_lock(lock: *mut CountedMutex) {
        LOCK_CALLS += 1;
        LOCK_ARGUMENT = lock;
    }
    unsafe extern "C" fn mock_mutex_unlock(lock: *mut CountedMutex) {
        UNLOCK_CALLS += 1;
        UNLOCK_ARGUMENT = lock;
    }

    fn install_mocks(running: i32) {
        unsafe {
            RUNNING_RESULT = running;
            LOCK_CALLS = 0;
            LOCK_ARGUMENT = core::ptr::null_mut();
            UNLOCK_CALLS = 0;
            UNLOCK_ARGUMENT = core::ptr::null_mut();
            KERNEL_RUNNING = mock_kernel_running;
            LOCK_COUNTED = mock_mutex_lock;
            UNLOCK_COUNTED = mock_mutex_unlock;
        }
    }

    #[test]
    fn scheduler_lock_skips_the_mutex_before_kernel_start() {
        let _guard = TEST_LOCK.lock();
        install_mocks(0);
        unsafe { scheduler_lock() };
        assert_eq!(unsafe { LOCK_CALLS }, 0);
    }

    #[test]
    fn scheduler_lock_locks_the_global_after_kernel_start() {
        let _guard = TEST_LOCK.lock();
        install_mocks(-1);
        unsafe { scheduler_lock() };
        assert_eq!(unsafe { LOCK_CALLS }, 1);
        assert_eq!(unsafe { LOCK_ARGUMENT }, unsafe { scheduler_mutex() });
    }

    #[test]
    fn scheduler_unlock_skips_the_mutex_before_kernel_start() {
        let _guard = TEST_LOCK.lock();
        install_mocks(0);
        unsafe { scheduler_unlock() };
        assert_eq!(unsafe { UNLOCK_CALLS }, 0);
    }

    #[test]
    fn scheduler_unlock_unlocks_the_global_after_kernel_start() {
        let _guard = TEST_LOCK.lock();
        install_mocks(1);
        unsafe { scheduler_unlock() };
        assert_eq!(unsafe { UNLOCK_CALLS }, 1);
        assert_eq!(unsafe { UNLOCK_ARGUMENT }, unsafe { scheduler_mutex() });
    }
}
