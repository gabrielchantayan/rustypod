//! 'plst' task message forwarding.
//!
//! - `plst_task_message` — original: `FUN_0804424c` @ `0x0804424c`
//!   (80 bytes including its trailing message literal; 3 plain outbound `bl`,
//!   0 predicated; 3 plain inbound `bl`, 0 predicated).

use core::ptr;

use crate::libc::bzero::bzero;

use super::plst_class_check::ui_element_is_plst_class;
use super::tdat_message_dispatch::tdat_dispatch_message;

const TASK_TDAT_ELEMENT_OFFSET: usize = 0x0c;
const TASK_READY_OFFSET: usize = 0x190;
const TDAT_TASK_MESSAGE: u32 = 0x7464_7070;
const DISPATCH_REJECTED: u32 = 0xffff_ffce;

/// ABI boundary for the final `bl 0x080442a0`.
pub type PlstTaskMessageDispatch = unsafe extern "C" fn(*mut u8, u32, *mut u8) -> u32;

/// Production dispatch target for the task's 'tdat' element.
pub const DEFAULT_PLST_TASK_MESSAGE_DISPATCH: PlstTaskMessageDispatch = tdat_dispatch_message;

/// Active final-dispatch boundary. Host tests replace this because target element
/// pointers are 32-bit words, while target builds call the ported dispatcher.
pub static mut PLST_TASK_MESSAGE_DISPATCH: PlstTaskMessageDispatch = DEFAULT_PLST_TASK_MESSAGE_DISPATCH;

#[inline(always)]
fn message_dispatch() -> PlstTaskMessageDispatch {
    unsafe { ptr::read_volatile(ptr::addr_of!(PLST_TASK_MESSAGE_DISPATCH)) }
}

/// plst_task_message — original: `FUN_0804424c` @ `0x0804424c` (80 bytes).
///
/// Raw ARM words establish the exact `0x0804424c..0x0804429c` extent, including
/// the trailing `0x74647070` literal; the next push-prologue begins at
/// `0x080442a0`. The 76 instruction bytes make three plain `bl` calls
/// (plst-class predicate, bzero, and Tdat dispatcher), with no predicated
/// calls. Independent full-image decoding finds three plain inbound `bl` calls
/// (`0x08049278`, `0x0805455c`, and `0x080d35dc`) and none predicated. It
/// rejects a non-'plst' task or a zero task+0x190 with -50; otherwise it
/// zeroes a four-word local record, fills `{task, message, arguments, 0}`, and
/// dispatches message `0x74647070` to task+0x0c.
///
/// Deliberate deviations: the stack record is a Rust `[u32; 4]`, and the
/// dynamic target dispatcher is a replaceable function-pointer boundary for
/// host tests. Its four target-width words and call arguments are unchanged.
///
/// # Safety
///
/// `task` may be NULL. A matching task must be readable through +0x193 and
/// contain a valid target-width pointer at +0x0c; `arguments` is forwarded
/// under the selected handler's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plst_task_message(
    task: *mut u8,
    message: u32,
    arguments: *mut u8,
) -> u32 {
    if ui_element_is_plst_class(task) == 0
        || task.add(TASK_READY_OFFSET).cast::<u32>().read() == 0
    {
        return DISPATCH_REJECTED;
    }

    let mut record = [0u32; 4];
    bzero(record.as_mut_ptr().cast(), 16);
    record[0] = task as usize as u32;
    record[1] = message;
    record[2] = arguments as usize as u32;

    let element = task.add(TASK_TDAT_ELEMENT_OFFSET).cast::<u32>().read() as usize as *mut u8;
    (message_dispatch())(element, TDAT_TASK_MESSAGE, record.as_mut_ptr().cast())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    const PLST_CLASS_TAG: u32 = 0x706c_7374;
    const OTHER_CLASS_TAG: u32 = 0x7464_6174;
    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ELEMENT: usize = 0;
    static mut MESSAGE: u32 = 0;
    static mut RECORD: [u32; 4] = [0; 4];
    static mut RESULT: u32 = 0;

    unsafe extern "C" fn record_dispatch(element: *mut u8, message: u32, record: *mut u8) -> u32 {
        CALLS += 1;
        ELEMENT = element as usize;
        MESSAGE = message;
        RECORD = record.cast::<[u32; 4]>().read();
        RESULT
    }

    struct DispatchGuard(PlstTaskMessageDispatch);

    impl Drop for DispatchGuard {
        fn drop(&mut self) {
            unsafe { PLST_TASK_MESSAGE_DISPATCH = self.0; }
        }
    }

    unsafe fn install_recorder(result: u32) -> DispatchGuard {
        let previous = PLST_TASK_MESSAGE_DISPATCH;
        PLST_TASK_MESSAGE_DISPATCH = record_dispatch;
        CALLS = 0;
        ELEMENT = 0;
        MESSAGE = 0;
        RECORD = [0; 4];
        RESULT = result;
        DispatchGuard(previous)
    }

    #[test]
    fn rejects_null_wrong_class_and_unready_tasks_without_dispatch() {
        let _lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _dispatch = unsafe { install_recorder(0) };
        let mut wrong = [0u32; 0x194 / 4];
        wrong[1] = OTHER_CLASS_TAG;
        let mut unready = [0u32; 0x194 / 4];
        unready[1] = PLST_CLASS_TAG;

        assert_eq!(unsafe { plst_task_message(ptr::null_mut(), 0, ptr::null_mut()) }, DISPATCH_REJECTED);
        assert_eq!(unsafe { plst_task_message(wrong.as_mut_ptr().cast(), 0, ptr::null_mut()) }, DISPATCH_REJECTED);
        assert_eq!(unsafe { plst_task_message(unready.as_mut_ptr().cast(), 0, ptr::null_mut()) }, DISPATCH_REJECTED);
        assert_eq!(unsafe { CALLS }, 0);
    }

    #[test]
    fn forwards_zero_terminated_four_word_message_record() {
        let _lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PLST_TASK_MESSAGE,
            0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let _dispatch = unsafe { install_recorder(0xc0de_cafe) };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let task = slab;
            let element = slab.add(0x400);
            let arguments = slab.add(0x800);
            task.add(4).cast::<u32>().write(PLST_CLASS_TAG);
            task.add(TASK_READY_OFFSET).cast::<u32>().write(1);
            task.add(TASK_TDAT_ELEMENT_OFFSET).cast::<u32>().write(element as usize as u32);

            assert_eq!(plst_task_message(task, 0x706c_646d, arguments), 0xc0de_cafe);
            assert_eq!(CALLS, 1);
            assert_eq!(ELEMENT, element as usize);
            assert_eq!(MESSAGE, TDAT_TASK_MESSAGE);
            assert_eq!(RECORD, [task as usize as u32, 0x706c_646d, arguments as usize as u32, 0]);
        }
    }
}
