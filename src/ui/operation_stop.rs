//! Mark a UI operation stopped and wake its waiters.

use super::super::kernel::condvar::{condvar_broadcast, CondVar};
use super::super::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const UI_OPERATION_MUTEX: *mut Mutex = 0x089c_a318 as *mut Mutex;
const UI_OPERATION_STOP_CONDVAR: *mut CondVar = 0x08a1_070c as *mut CondVar;
const STOP_OPERATION_TAG: u32 = 0x7374_6f70;
const OPERATION_TAG_OFFSET: usize = 0x18;

/// ui_operation_stop — original: `FUN_0808e25c` @ `0x0808e25c` (44 bytes).
///
/// Raw ARM establishes the true extent as `0x0808e25c..0x0808e288`: the
/// following words are this function's literal pool, and the next real
/// function begins with `push {r4,lr}` at `0x0808e294`. Decoding every A32
/// branch-with-link word in `osos.dec` finds four direct callers, all
/// unconditional `bl` (`0x0811f5e0`, `0x0812c408`, `0x082280f4`, and
/// `0x08295ed4`); no predicated `bl` forms exist. This body has two direct
/// calls and tail-branches to `mutex_unlock`.
///
/// It locks the UI-operation mutex at `0x089ca318`, writes the literal
/// `"stop"` tag to operation `+0x18`, broadcasts the condition variable at
/// `0x08a1070c`, then unlocks the mutex.
///
/// Deliberate deviation: host tests inject typed local mutex and condition
/// variable objects into the private helper because host pointers are
/// eight-byte values; target builds use the original four-byte-addressed
/// globals unchanged.
///
/// # Safety
///
/// `operation` must be writable through `+0x1b`. The retail function has no
/// NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_operation_stop")]
#[inline(never)]
pub unsafe extern "C" fn ui_operation_stop(operation: *mut u8) {
    ui_operation_stop_inner(operation, UI_OPERATION_MUTEX, UI_OPERATION_STOP_CONDVAR);
}

unsafe fn ui_operation_stop_inner(
    operation: *mut u8,
    mutex: *mut Mutex,
    condvar: *mut CondVar,
) {
    mutex_lock(mutex);
    operation.add(OPERATION_TAG_OFFSET).cast::<u32>().write(STOP_OPERATION_TAG);
    condvar_broadcast(condvar);
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::condvar::ListHead;

    #[test]
    fn writes_stop_tag_at_operation_offset_and_handles_empty_waiters() {
        let mut operation = [0u32; 7];
        let mut mutex = Mutex {
            sem_cell: core::ptr::null_mut(),
            unused: 0,
        };
        let mut condvar = CondVar {
            lock_obj: core::ptr::null_mut(),
            waiters: ListHead {
                head: core::ptr::null_mut(),
                tail: core::ptr::null_mut(),
            },
        };

        unsafe {
            ui_operation_stop_inner(
                operation.as_mut_ptr().cast::<u8>(),
                &mut mutex,
                &mut condvar,
            );
        }

        assert_eq!(operation[6], STOP_OPERATION_TAG);
        assert_eq!(operation[..6], [0; 6]);
        assert!(condvar.waiters.head.is_null());
        assert!(condvar.waiters.tail.is_null());
    }
}
