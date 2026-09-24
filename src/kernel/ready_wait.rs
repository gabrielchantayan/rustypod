//! Waits for an opaque object's ready byte while holding its embedded mutex.


use super::condvar::{condvar_wait_forever, CondVar};
use super::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// Target layout of the synchronization tail used by [`wait_for_ready`].
///
/// On the ARM target `Mutex` is eight bytes and `condvar` begins at +0x48.
/// Host pointers are wider, so [`wait_for_ready`] uses the target offsets
/// directly rather than this type's host offsets.
#[repr(C)]
pub struct ReadyWait {
    _prefix: [u8; 0x3d],
    pub ready: u8,
    _padding: [u8; 2],
    pub mutex: Mutex,
    pub condvar: CondVar,
}

/// wait_for_ready — original: `FUN_081066e8` @ 0x081066e8 (52 bytes; three
/// verified inbound `bl` call sites: two unconditional and one predicated).
///
/// Locks the embedded mutex at +0x40, waits on the embedded condition variable
/// at +0x48 until the ready byte at +0x3d becomes nonzero, then unlocks that
/// mutex. The raw body is thirteen ARM words from `stmdb sp!,{r4,lr}` through
/// the tail `b` to the ROM semaphore-signal veneer. Its two direct internal
/// calls are unconditional `bl` to `mutex_lock` and `condvar_wait_forever`; it
/// has no predicated `bl` and tail-branches to `rom_sem_signal` for the final
/// unlock. Deliberate deviation: the tail branch is expressed as the existing
/// `mutex_unlock` port, which performs the veneer-equivalent NULL and zero
/// handle guards before signaling.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn wait_for_ready(wait: *mut ReadyWait) {
    let base = wait as *mut u8;
    let mutex = base.add(0x40) as *mut Mutex;
    let condvar = base.add(0x48) as *mut CondVar;

    mutex_lock(mutex);
    while *base.add(0x3d) == 0 {
        condvar_wait_forever(condvar);
    }
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{wait_for_ready, ReadyWait};
    use crate::kernel::sync_mutex::Mutex;
    use core::ptr::null_mut;

    #[test]
    fn ready_wait_returns_for_a_ready_object_with_no_semaphore_cell() {
        let mut object: ReadyWait = unsafe { core::mem::zeroed() };
        object.ready = 1;
        object.mutex.sem_cell = null_mut();

        unsafe { wait_for_ready(&mut object) };
        assert_eq!(object.ready, 1);
        assert!(object.mutex.sem_cell.is_null());
    }

    #[test]
    fn ready_wait_returns_for_a_ready_object_with_a_zero_handle() {
        let mut object: ReadyWait = unsafe { core::mem::zeroed() };
        let mut semaphore_cell = 0_u32;
        object.ready = 1;
        object.mutex = Mutex {
            sem_cell: core::ptr::addr_of_mut!(semaphore_cell),
            unused: 0,
        };

        unsafe { wait_for_ready(&mut object) };
        assert_eq!(semaphore_cell, 0);
    }
}
