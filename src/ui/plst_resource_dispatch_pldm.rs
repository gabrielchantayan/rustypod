//! 'plst' resource callback and `pldm` message dispatch.
//!
//! - `plst_resource_dispatch_pldm` — original: `FUN_080487ac` @
//!   `0x080487ac` (88 bytes including literals; 2 plain `bl`, 0 predicated
//!   `bl`).

use core::ptr;

use crate::app::resource::cache::resource_callback_dispatch;

use super::plst_class_check::ui_element_is_plst_class;
use super::tdat_message_dispatch::tdat_dispatch_message;

const TASK_RESOURCE_ROOT_OFFSET: usize = 0x40;
const TASK_READY_OFFSET: usize = 0x190;
const RESOURCE_STATE_OFFSET: usize = 0x14;
const RESOURCE_CALLBACK: usize = 0x080d_43e4;
const PLDM_MESSAGE: u32 = 0x706c_646d;
const TDAT_MESSAGE: u32 = 0x7464_7070;
const DISPATCH_REJECTED: u32 = 0xffff_ffce;

/// ABI boundaries reached after the task readiness check.
///
/// `0x0804424c` is deliberately not named: it has no `names.yaml` entry. Raw
/// instructions establish that it zeroes `{task, PLDM_MESSAGE, 0, 0}` and
/// dispatches `TDAT_MESSAGE` to task+0x0c, which is represented here by the
/// already ported message dispatcher.
#[derive(Clone, Copy)]
pub struct PlstResourceDispatchPldmOps {
    pub resource_dispatch: unsafe extern "C" fn(*mut u8, usize, *mut u8) -> i32,
    pub message_dispatch: unsafe extern "C" fn(*mut u8, u32, *mut u8) -> u32,
}

pub const DEFAULT_PLST_RESOURCE_DISPATCH_PLDM_OPS: PlstResourceDispatchPldmOps =
    PlstResourceDispatchPldmOps {
        resource_dispatch: resource_callback_dispatch,
        message_dispatch: tdat_dispatch_message,
    };

pub static mut PLST_RESOURCE_DISPATCH_PLDM_OPS: PlstResourceDispatchPldmOps =
    DEFAULT_PLST_RESOURCE_DISPATCH_PLDM_OPS;

#[inline(always)]
fn dispatch_ops() -> PlstResourceDispatchPldmOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(PLST_RESOURCE_DISPATCH_PLDM_OPS)) }
}
/// plst_resource_dispatch_pldm — original: `FUN_080487ac` @ `0x080487ac`
/// (88 bytes including two trailing literal words).
///
/// Raw `osos.dec` words establish the extent from `0x080487ac` through the
/// second literal at `0x08048800`; the next push-prologue starts at
/// `0x08048804`. The 80 instruction bytes through the tail branch at
/// `0x080487f8` have two plain `bl` calls
/// (`ui_element_is_plst_class` and `resource_callback_dispatch`) and no
/// predicated `bl` calls; the final `b 0x0804424c` is a tail branch. The
/// function rejects a non-'plst' task or zero task+0x190 with -50. On success
/// it clears resource-root+0x14, dispatches callback `0x080d43e4` with a NULL
/// context (ignoring its status), then tail-dispatches `pldm` through the
/// verified behavior of 0x0804424c.
///
/// Deliberate deviation: the unregistered 0x0804424c helper is expressed by
/// its raw-verified 16-byte argument record and the ported Tdat dispatcher,
/// rather than inventing a callee identity. The two externally observable
/// calls remain replaceable volatile boundaries for host tests.
///
/// # Safety
///
/// `task` may be NULL. A non-NULL task must be readable through +0x193; a
/// successful task requires valid target-width pointers at +0x0c and +0x40.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plst_resource_dispatch_pldm(task: *mut u8) -> u32 {
    if ui_element_is_plst_class(task) == 0
        || task.add(TASK_READY_OFFSET).cast::<u32>().read() == 0
    {
        return DISPATCH_REJECTED;
    }

    let resource_root = task
        .add(TASK_RESOURCE_ROOT_OFFSET)
        .cast::<u32>()
        .read() as usize as *mut u8;
    resource_root.add(RESOURCE_STATE_OFFSET).cast::<u32>().write(0);

    let ops = dispatch_ops();
    (ops.resource_dispatch)(resource_root, RESOURCE_CALLBACK, ptr::null_mut());

    let mut arguments = [task as usize as u32, PLDM_MESSAGE, 0, 0];
    let element = task.add(0x0c).cast::<u32>().read() as usize as *mut u8;
    (ops.message_dispatch)(element, TDAT_MESSAGE, arguments.as_mut_ptr().cast())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    const PLST_CLASS_TAG: u32 = 0x706c_7374;
    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut RESOURCE_CALLS: u32 = 0;
    static mut RESOURCE_ROOT: usize = 0;
    static mut RESOURCE_CALLBACK_VALUE: usize = 0;
    static mut MESSAGE_CALLS: u32 = 0;
    static mut MESSAGE_ELEMENT: usize = 0;
    static mut MESSAGE_VALUE: u32 = 0;
    static mut ARGUMENTS: [u32; 4] = [0; 4];
    static mut MESSAGE_RESULT: u32 = 0;

    unsafe extern "C" fn record_resource(root: *mut u8, callback: usize, context: *mut u8) -> i32 {
        assert!(context.is_null());
        RESOURCE_CALLS += 1;
        RESOURCE_ROOT = root as usize;
        RESOURCE_CALLBACK_VALUE = callback;
        -7
    }

    unsafe extern "C" fn record_message(element: *mut u8, message: u32, arguments: *mut u8) -> u32 {
        MESSAGE_CALLS += 1;
        MESSAGE_ELEMENT = element as usize;
        MESSAGE_VALUE = message;
        ARGUMENTS = arguments.cast::<[u32; 4]>().read();
        MESSAGE_RESULT
    }

    struct OpsGuard(PlstResourceDispatchPldmOps);
    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { PLST_RESOURCE_DISPATCH_PLDM_OPS = self.0; }
        }
    }

    unsafe fn install_recorders(result: u32) -> OpsGuard {
        let previous = PLST_RESOURCE_DISPATCH_PLDM_OPS;
        PLST_RESOURCE_DISPATCH_PLDM_OPS = PlstResourceDispatchPldmOps {
            resource_dispatch: record_resource,
            message_dispatch: record_message,
        };
        RESOURCE_CALLS = 0;
        RESOURCE_ROOT = 0;
        RESOURCE_CALLBACK_VALUE = 0;
        MESSAGE_CALLS = 0;
        MESSAGE_ELEMENT = 0;
        MESSAGE_VALUE = 0;
        ARGUMENTS = [0; 4];
        MESSAGE_RESULT = result;
        OpsGuard(previous)
    }

    #[test]
    fn rejects_null_wrong_class_and_unready_tasks_without_side_effects() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorders(0) };
        let mut wrong = [0u32; 0x194 / 4];
        wrong[1] = TDAT_CLASS_TAG;
        let mut unready = [0u32; 0x194 / 4];
        unready[1] = PLST_CLASS_TAG;

        assert_eq!(unsafe { plst_resource_dispatch_pldm(ptr::null_mut()) }, DISPATCH_REJECTED);
        assert_eq!(unsafe { plst_resource_dispatch_pldm(wrong.as_mut_ptr().cast()) }, DISPATCH_REJECTED);
        assert_eq!(unsafe { plst_resource_dispatch_pldm(unready.as_mut_ptr().cast()) }, DISPATCH_REJECTED);
        assert_eq!(unsafe { RESOURCE_CALLS }, 0);
        assert_eq!(unsafe { MESSAGE_CALLS }, 0);
    }

    #[test]
    fn clears_dispatches_and_forwards_the_zeroed_argument_record() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PLST_RESOURCE_DISPATCH_PLDM,
            0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let _ops = unsafe { install_recorders(0xc0de_cafe) };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let task = slab;
            let element = slab.add(0x400);
            let root = slab.add(0x800);
            task.add(4).cast::<u32>().write(PLST_CLASS_TAG);
            task.add(TASK_READY_OFFSET).cast::<u32>().write(1);
            task.add(0x0c).cast::<u32>().write(element as usize as u32);
            task.add(TASK_RESOURCE_ROOT_OFFSET).cast::<u32>().write(root as usize as u32);
            root.add(RESOURCE_STATE_OFFSET).cast::<u32>().write(0xdead_beef);

            assert_eq!(plst_resource_dispatch_pldm(task), 0xc0de_cafe);
            assert_eq!(root.add(RESOURCE_STATE_OFFSET).cast::<u32>().read(), 0);
            assert_eq!(RESOURCE_CALLS, 1);
            assert_eq!(RESOURCE_ROOT, root as usize);
            assert_eq!(RESOURCE_CALLBACK_VALUE, RESOURCE_CALLBACK);
            assert_eq!(MESSAGE_CALLS, 1);
            assert_eq!(MESSAGE_ELEMENT, element as usize);
            assert_eq!(MESSAGE_VALUE, TDAT_MESSAGE);
            assert_eq!(ARGUMENTS, [task as usize as u32, PLDM_MESSAGE, 0, 0]);
        }
    }
}
