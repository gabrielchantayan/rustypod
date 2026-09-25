//! Kernel semaphore wait — `FUN_08003fd0` @ 0x08003fd0 (180 bytes).
//!
//! Raw ARM ends at the next function boundary 0x0800408c; its body has five
//! unconditional `bl` instructions (three unique destinations) and no
//! predicated `bl`: enter at 0x080034f8, leave at 0x08003500 (three paths),
//! and dispatch at 0x08003660. It indexes the 32-byte semaphore table at
//! 0x08a1be28 by id. A free record takes ownership by the current task,
//! initializes its u16 recursion count to one, and returns zero. Recursive
//! ownership increments both the u32 acquisition counter at +24 and u16
//! recursion count at +4, returning ten. Another owner causes a service-14
//! request `{14, 0, id, 1, 0}` to be dispatched after leaving the table lock;
//! its rewritten status word is returned.
//!
//! Deliberate deviations: the two undocumented lock veneers are represented
//! by installable volatile seams (their raw literal targets are entered
//! through 0x080034f8/0x08003500); the foreign RTXC dispatcher uses its
//! established `message_dispatch_veneer` seam. Host table/current-task words
//! replace target fixed addresses without changing target-width offsets.

use crate::runtime::message_dispatch_veneer::message_dispatch_veneer;

const SEMAPHORE_TABLE: *mut u8 = 0x08a1_be28 as *mut u8;
const CURRENT_TASK_SLOT: *const u32 = 0x2200_acf4 as *const u32;
const RECORD_SIZE: usize = 32;
const RECURSION_OFFSET: usize = 4;
const ACQUISITIONS_OFFSET: usize = 24;

type TableLockFn = unsafe extern "C" fn();

#[derive(Clone, Copy)]
pub struct SemaphoreWaitOps {
    pub enter: TableLockFn,
    pub leave: TableLockFn,
}

unsafe extern "C" fn rom_enter() {
    let enter: TableLockFn = core::mem::transmute(0x0800_34f8usize);
    enter();
}

unsafe extern "C" fn rom_leave() {
    let leave: TableLockFn = core::mem::transmute(0x0800_3500usize);
    leave();
}

pub static mut SEMAPHORE_WAIT_OPS: SemaphoreWaitOps = SemaphoreWaitOps {
    enter: rom_enter,
    leave: rom_leave,
};

#[cfg(not(target_os = "none"))]
static mut HOST_SEMAPHORE_TABLE: *mut u8 = core::ptr::null_mut();
#[cfg(not(target_os = "none"))]
static mut HOST_CURRENT_TASK: u32 = 0;

#[inline(always)]
unsafe fn semaphore_table() -> *mut u8 {
    #[cfg(target_os = "none")]
    { SEMAPHORE_TABLE }
    #[cfg(not(target_os = "none"))]
    { HOST_SEMAPHORE_TABLE }
}

#[inline(always)]
unsafe fn current_task() -> u32 {
    #[cfg(target_os = "none")]
    { CURRENT_TASK_SLOT.read_volatile() }
    #[cfg(not(target_os = "none"))]
    { HOST_CURRENT_TASK }
}

#[inline(always)]
unsafe fn wait_ops() -> SemaphoreWaitOps {
    core::ptr::addr_of!(SEMAPHORE_WAIT_OPS).read_volatile()
}

/// kernel_semaphore_wait — original: `FUN_08003fd0` @ 0x08003fd0 (180 bytes;
/// five plain `bl`, three unique callees, zero predicated `bl`).
///
/// # Safety
/// On target, `semaphore_id` must select a valid 32-byte record in the fixed
/// kernel semaphore table. The caller must obey the kernel's semaphore ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn kernel_semaphore_wait(semaphore_id: u32) -> u32 {
    let record = semaphore_table().add(semaphore_id as usize * RECORD_SIZE);
    let ops = wait_ops();
    (ops.enter)();

    let owner = record.cast::<u32>().read();
    if owner == 0 {
        record.add(ACQUISITIONS_OFFSET).cast::<u32>().write(
            record.add(ACQUISITIONS_OFFSET).cast::<u32>().read().wrapping_add(1),
        );
        record.cast::<u32>().write(current_task());
        record.add(RECURSION_OFFSET).cast::<u16>().write(1);
        (ops.leave)();
        0
    } else if owner == current_task() {
        record.add(ACQUISITIONS_OFFSET).cast::<u32>().write(
            record.add(ACQUISITIONS_OFFSET).cast::<u32>().read().wrapping_add(1),
        );
        record.add(RECURSION_OFFSET).cast::<u16>().write(
            record.add(RECURSION_OFFSET).cast::<u16>().read().wrapping_add(1),
        );
        (ops.leave)();
        10
    } else {
        (ops.leave)();
        let mut request = [14u32, 0, semaphore_id, 1, 0];
        message_dispatch_veneer(request.as_mut_ptr());
        request[1]
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::message_dispatch_veneer::{
        tests::DISPATCH_OPS_LOCK, MessageDispatchVeneerOps, MESSAGE_DISPATCH_VENEER_OPS,
    };
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ENTERS: u32 = 0;
    static mut LEAVES: u32 = 0;
    static mut REQUEST: [u32; 5] = [0; 5];
    static mut STATUS: u32 = 0;

    unsafe extern "C" fn enter() { ENTERS += 1; }
    unsafe extern "C" fn leave() { LEAVES += 1; }
    unsafe extern "C" fn dispatch(request: *mut u32) {
        REQUEST.copy_from_slice(core::slice::from_raw_parts(request, 5));
        request.add(1).write(STATUS);
    }

    struct Seams {
        _ops_lock: MutexGuard<'static, ()>,
        _dispatch_lock: MutexGuard<'static, ()>,
        ops: SemaphoreWaitOps,
        dispatch: MessageDispatchVeneerOps,
        table: *mut u8,
        task: u32,
    }

    impl Seams {
        unsafe fn install(table: *mut u8, task: u32) -> Self {
            let ops_lock = OPS_LOCK.lock();
            let dispatch_lock = DISPATCH_OPS_LOCK.lock();
            let saved = SEMAPHORE_WAIT_OPS;
            let saved_dispatch = MESSAGE_DISPATCH_VENEER_OPS;
            let saved_table = HOST_SEMAPHORE_TABLE;
            let saved_task = HOST_CURRENT_TASK;
            SEMAPHORE_WAIT_OPS = SemaphoreWaitOps { enter, leave };
            MESSAGE_DISPATCH_VENEER_OPS = MessageDispatchVeneerOps { dispatch };
            HOST_SEMAPHORE_TABLE = table;
            HOST_CURRENT_TASK = task;
            ENTERS = 0;
            LEAVES = 0;
            REQUEST = [0; 5];
            STATUS = 0;
            Self { _ops_lock: ops_lock, _dispatch_lock: dispatch_lock, ops: saved, dispatch: saved_dispatch, table: saved_table, task: saved_task }
        }
    }

    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe {
                SEMAPHORE_WAIT_OPS = self.ops;
                MESSAGE_DISPATCH_VENEER_OPS = self.dispatch;
                HOST_SEMAPHORE_TABLE = self.table;
                HOST_CURRENT_TASK = self.task;
            }
        }
    }

    fn fixture() -> Option<*mut u8> {
        let table = try_map_u32_slab(hints::KERNEL_SEMAPHORE_WAIT, 0x100)?;
        unsafe { table.write_bytes(0, 0x100); }
        Some(table.cast())
    }

    #[test]
    fn claims_a_free_record_with_target_width_offsets() {
        let Some(table) = fixture() else { return; };
        let _seams = unsafe { Seams::install(table, 0x1234_5678) };
        unsafe {
            assert_eq!(kernel_semaphore_wait(2), 0);
            let record = table.add(64);
            assert_eq!(record.cast::<u32>().read(), 0x1234_5678);
            assert_eq!(record.add(RECURSION_OFFSET).cast::<u16>().read(), 1);
            assert_eq!(record.add(ACQUISITIONS_OFFSET).cast::<u32>().read(), 1);
            assert_eq!((ENTERS, LEAVES), (1, 1));
            assert_eq!(REQUEST, [0; 5]);
        }
    }

    #[test]
    fn recursively_acquires_without_dispatching() {
        let Some(table) = fixture() else { return; };
        unsafe {
            let record = table.add(32);
            record.cast::<u32>().write(0xabcd);
            record.add(RECURSION_OFFSET).cast::<u16>().write(u16::MAX);
            record.add(ACQUISITIONS_OFFSET).cast::<u32>().write(u32::MAX);
            let _seams = Seams::install(table, 0xabcd);
            assert_eq!(kernel_semaphore_wait(1), 10);
            assert_eq!(record.add(RECURSION_OFFSET).cast::<u16>().read(), 0);
            assert_eq!(record.add(ACQUISITIONS_OFFSET).cast::<u32>().read(), 0);
            assert_eq!((ENTERS, LEAVES), (1, 1));
            assert_eq!(REQUEST, [0; 5]);
        }
    }

    #[test]
    fn blocks_foreign_owner_through_service_fourteen() {
        let Some(table) = fixture() else { return; };
        unsafe {
            table.cast::<u32>().write(0xaaaa);
            let _seams = Seams::install(table, 0xbbbb);
            STATUS = 0x55;
            assert_eq!(kernel_semaphore_wait(0), 0x55);
            assert_eq!((ENTERS, LEAVES), (1, 1));
            assert_eq!(REQUEST, [14, 0, 0, 1, 0]);
        }
    }
}
