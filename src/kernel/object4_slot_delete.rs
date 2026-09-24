//! Delete a class-4 RTXC kernel object held in a caller-owned slot.
//!
//! The three ROM services are exposed as hooks because their mask-ROM bodies
//! are not part of osos. Device defaults preserve the retail thunk calls;
//! host tests install deterministic stand-ins.

/// RTXC object class selected by `mov r0, #4`.
const KERNEL_OBJECT4_OP: u32 = 4;

/// Mask-ROM operations used by [`kernel_object4_slot_delete`].
#[derive(Clone, Copy)]
pub struct KernelObject4Hooks {
    pub task_lock: unsafe extern "C" fn(u32) -> u32,
    pub task_unlock: unsafe extern "C" fn(u32),
    pub object_delete: unsafe extern "C" fn(u32, *mut u32) -> u32,
}

unsafe extern "C" fn default_task_lock(id: u32) -> u32 {
    crate::kernel::task_lock::task_lock(id as usize) as u32
}

unsafe extern "C" fn default_task_unlock(id: u32) {
    let _ = crate::kernel::task_lock::task_unlock(id);
}

unsafe extern "C" fn default_object_delete(op: u32, slot: *mut u32) -> u32 {
    crate::kernel::task_lock::kernel_op_dispatch(op as usize, slot as usize) as u32
}

pub const DEFAULT_KERNEL_OBJECT4_HOOKS: KernelObject4Hooks = KernelObject4Hooks {
    task_lock: default_task_lock,
    task_unlock: default_task_unlock,
    object_delete: default_object_delete,
};

/// Written once during target initialization; host tests serialize replacement.
pub static mut KERNEL_OBJECT4_HOOKS: KernelObject4Hooks = DEFAULT_KERNEL_OBJECT4_HOOKS;

#[inline(always)]
fn hooks() -> KernelObject4Hooks {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(KERNEL_OBJECT4_HOOKS)) }
}

/// kernel_object4_slot_delete — original: `FUN_0809c79c` @ `0x0809c79c`.
///
/// Verified extent: **76 bytes**, `0x0809c79c..0x0809c7e8`; the next real
/// function starts with `stmdb sp!, {r4, lr}` at `0x0809c7ec`. Raw A32 words
/// decode **3 plain `bl` calls** (`0x0809c7b4`, `0x0809c7c8`, `0x0809c7d4`)
/// and **0 predicated `bl` calls**. A zero slot value returns `0x1a`. Otherwise
/// lookup the object id; only lookup results zero or `0xffffffff` permit the
/// unlock and class-4 delete. A zero delete result returns zero; every other
/// path returns `0x14`.
///
/// Deliberate deviation: mask-ROM calls through the retail literal veneers are
/// represented by volatile hook-table loads. The input slot is passed directly
/// to the delete hook, as the original keeps it in r4 rather than making a
/// stack copy.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kernel_object4_slot_delete(slot: *mut u32) -> u32 {
    let id = *slot;
    if id == 0 {
        return 0x1a;
    }

    let h = hooks();
    let lookup = (h.task_lock)(id);
    if lookup != 0 && lookup != u32::MAX {
        return 0x14;
    }

    (h.task_unlock)(id);
    if (h.object_delete)(KERNEL_OBJECT4_OP, slot) == 0 {
        0
    } else {
        0x14
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::{Mutex, MutexGuard};
    use std::vec::Vec;

    static HOOKS_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: Mutex<Vec<(u8, u32, usize)>> = Mutex::new(Vec::new());
    static mut LOOKUP_RESULT: u32 = 0;
    static mut DELETE_RESULT: u32 = 0;

    unsafe extern "C" fn mock_lock(id: u32) -> u32 {
        CALLS.lock().push((1, id, 0));
        LOOKUP_RESULT
    }

    unsafe extern "C" fn mock_unlock(id: u32) {
        CALLS.lock().push((2, id, 0));
    }

    unsafe extern "C" fn mock_delete(op: u32, slot: *mut u32) -> u32 {
        CALLS.lock().push((3, op, slot as usize));
        DELETE_RESULT
    }

    struct HookRestore(KernelObject4Hooks);
    impl Drop for HookRestore {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(KERNEL_OBJECT4_HOOKS).write(self.0) }
        }
    }

    fn mock_hooks() -> (MutexGuard<'static, ()>, HookRestore) {
        let guard = HOOKS_LOCK.lock();
        unsafe {
            let saved = KERNEL_OBJECT4_HOOKS;
            core::ptr::addr_of_mut!(KERNEL_OBJECT4_HOOKS).write(KernelObject4Hooks {
                task_lock: mock_lock,
                task_unlock: mock_unlock,
                object_delete: mock_delete,
            });
            CALLS.lock().clear();
            LOOKUP_RESULT = 0;
            DELETE_RESULT = 0;
            (guard, HookRestore(saved))
        }
    }

    #[test]
    fn zero_slot_rejects_without_calling_rom() {
        let (_guard, _restore) = mock_hooks();
        let mut slot = 0;
        assert_eq!(unsafe { kernel_object4_slot_delete(&mut slot) }, 0x1a);
        assert!(CALLS.lock().is_empty());
    }

    #[test]
    fn zero_and_minus_one_lookup_results_delete_the_original_slot() {
        for lookup in [0, u32::MAX] {
            let (_guard, _restore) = mock_hooks();
            unsafe { LOOKUP_RESULT = lookup; }
            let mut slot = 0x55aa_1234;
            assert_eq!(unsafe { kernel_object4_slot_delete(&mut slot) }, 0);
            assert_eq!(slot, 0x55aa_1234);
            assert_eq!(CALLS.lock().as_slice(), &[
                (1, 0x55aa_1234, 0),
                (2, 0x55aa_1234, 0),
                (3, KERNEL_OBJECT4_OP, &mut slot as *mut u32 as usize),
            ]);
        }
    }

    #[test]
    fn other_lookup_or_delete_failure_returns_kernel_error() {
        let (_guard, _restore) = mock_hooks();
        unsafe { LOOKUP_RESULT = 1; }
        let mut slot = 7;
        assert_eq!(unsafe { kernel_object4_slot_delete(&mut slot) }, 0x14);
        assert_eq!(CALLS.lock().as_slice(), &[(1, 7, 0)]);

        unsafe {
            CALLS.lock().clear();
            LOOKUP_RESULT = 0;
            DELETE_RESULT = 1;
        }
        assert_eq!(unsafe { kernel_object4_slot_delete(&mut slot) }, 0x14);
        assert_eq!(CALLS.lock().as_slice(), &[
            (1, 7, 0),
            (2, 7, 0),
            (3, KERNEL_OBJECT4_OP, &mut slot as *mut u32 as usize),
        ]);
    }
}
