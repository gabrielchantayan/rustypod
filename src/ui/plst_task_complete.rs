//! 'plst' task completion.
//!
//! - `plst_task_complete` — original: `FUN_08048a0c` @ `0x08048a0c`
//!   (160 bytes, including the literal event key at `0x08048aac`). Verified
//!   inbound call count: 6 direct `bl` calls, all unconditional.

use core::ptr;

use super::plst_class_check::ui_element_is_plst_class;

/// Raw FourCC event key held in the literal pool at `0x08048aac`.
/// Its semantic identity is not recovered.
const COMPLETE_NOTIFY_TAG: u32 = 0x6470_6c69;
const TASK_ELEMENT_WORD: usize = 0;
const TASK_CHILD_LIST_WORD: usize = 1;
const TASK_ACTIVE_LINK_WORD: usize = 4;
const TASK_FLAGS_OFFSET: usize = 0x1d;
const ELEMENT_NOTIFY_LIST_OFFSET: usize = 0x48;
const ELEMENT_RESOURCE_WORD: usize = 0x3c / core::mem::size_of::<u32>();
const ELEMENT_ACTIVITY_FLAGS_OFFSET: usize = 0x1ac;
const ELEMENT_ACTIVITY_NONZERO_OFFSET: usize = 0x1b0;

/// Recovered `0x08061650` gate shared by PLST task ports.
pub(crate) unsafe fn plst_task_is_active(task: *mut u32) -> u32 {
    if task.is_null() {
        return 0;
    }
    let element = task.add(TASK_ELEMENT_WORD).read() as usize as *const u8;
    (ui_element_is_plst_class(element) != 0 && task.add(TASK_ACTIVE_LINK_WORD).read() != 0) as u32
}

/// Boundaries for the four unported calls made by this routine.
pub type PlstTaskNotify = unsafe extern "C" fn(*mut u8, u32, *mut u32, u32, u32);
pub type PlstTaskFlaggedHandler = unsafe extern "C" fn(*mut u32);
pub type PlstTaskDetachChildren = unsafe extern "C" fn(*mut u32, u32);
pub type PlstTaskRemove = unsafe extern "C" fn(*mut u32, u32, u32);
pub type PlstTaskResourceRelease = unsafe extern "C" fn(*mut u8, *mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_task_notify(list: *mut u8, tag: u32, task: *mut u32, flags: u32, stack_arg: u32) {
    let call: PlstTaskNotify = core::mem::transmute(0x0806_6bb8usize);
    call(list, tag, task, flags, stack_arg)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_task_notify(_: *mut u8, _: u32, _: *mut u32, _: u32, _: u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_flagged_handler(task: *mut u32) {
    let call: PlstTaskFlaggedHandler = core::mem::transmute(0x080d_8678usize);
    call(task)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_flagged_handler(_: *mut u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_detach_children(task: *mut u32, notify: u32) {
    let call: PlstTaskDetachChildren = core::mem::transmute(0x080a_7b60usize);
    call(task, notify)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_detach_children(_: *mut u32, _: u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_remove(task: *mut u32, first: u32, second: u32) {
    let call: PlstTaskRemove = core::mem::transmute(0x080d_a878usize);
    call(task, first, second)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_remove(_: *mut u32, _: u32, _: u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_resource_release(resource: *mut u8, task: *mut u32) {
    let call: PlstTaskResourceRelease = core::mem::transmute(0x0804_8eb8usize);
    call(resource, task)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_resource_release(_: *mut u8, _: *mut u32) {}

/// Calls outside this one-function port. Target builds preserve each retail
/// boundary; host tests replace this table to observe the exact sequence.
#[derive(Clone, Copy)]
pub struct PlstTaskCompleteOps {
    pub notify: PlstTaskNotify,
    pub flagged_handler: PlstTaskFlaggedHandler,
    pub detach_children: PlstTaskDetachChildren,
    pub remove: PlstTaskRemove,
    pub resource_release: PlstTaskResourceRelease,
}

pub const DEFAULT_PLST_TASK_COMPLETE_OPS: PlstTaskCompleteOps = PlstTaskCompleteOps {
    notify: retail_task_notify,
    flagged_handler: retail_flagged_handler,
    detach_children: retail_detach_children,
    remove: retail_remove,
    resource_release: retail_resource_release,
};

/// Active dispatch boundary for unported `0x08066bb8`, `0x080d8678`,
/// `0x080a7b60`, `0x080da878`, and `0x08048eb8`.
pub static mut PLST_TASK_COMPLETE_OPS: PlstTaskCompleteOps = DEFAULT_PLST_TASK_COMPLETE_OPS;

#[inline(always)]
fn ops() -> PlstTaskCompleteOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(PLST_TASK_COMPLETE_OPS)) }
}

/// Completes a 'plst' task — original: `FUN_08048a0c` @ `0x08048a0c`
/// (160 bytes).
///
/// The raw ARM first calls `0x08061650`: `task` must be non-NULL, its element
/// word must pass the existing 'plst' predicate, and task word +0x10 must be
/// nonzero. It returns `-50` on that gate. Otherwise it notifies the element's
/// +0x48 handler list with literal key `0x64706c69`; an unflagged task marks
/// element byte +0x1ac bit 1 when bits +0x1ac.0 and +0x1b0 are both set, while
/// a flagged task calls `0x080d8678`. A nonzero task word +4 is detached, then
/// the task is removed and its element's +0x3c resource is released.
///
/// Raw bytes end with `pop {r3,r4,r5,pc}` at `0x08048aa8`; the literal at
/// `0x08048aac` makes the verified extent 160 bytes and the next independent
/// function begins at `0x08048ab0`. Every B/BL in `osos.dec` finds six
/// inbound calls, all unconditional `bl`: 0x080477f0, 0x08064650,
/// 0x080646a4, 0x080c5fd8, 0x080d8690, and 0x08283f18.
///
/// Deliberate deviations: the small unported gate `0x08061650` is expressed
/// directly with the already-ported class predicate and its observed +0x10
/// test. The remaining unported callees dispatch through
/// [`PLST_TASK_COMPLETE_OPS`], whose target defaults retain their verified
/// retail addresses; no callee identity beyond the observed role is claimed.
///
/// # Safety
/// `task` may be NULL. A non-NULL task must be aligned and readable through
/// byte +0x1d; its first word is a target-width element pointer. A passing
/// task requires its element readable through +0x1b0 and valid arguments for
/// the installed operation table.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.plst_task_complete")]
pub unsafe extern "C" fn plst_task_complete(task: *mut u32) -> i32 {
    if plst_task_is_active(task) == 0 {
        return -50;
    }
    let element = task.read() as usize as *mut u8;

    let active_ops = ops();
    (active_ops.notify)(
        element.add(ELEMENT_NOTIFY_LIST_OFFSET),
        COMPLETE_NOTIFY_TAG,
        task,
        0,
        0,
    );

    if *task.cast::<u8>().add(TASK_FLAGS_OFFSET) & 1 == 0 {
        let activity_flags = element.add(ELEMENT_ACTIVITY_FLAGS_OFFSET).read();
        if activity_flags & 1 != 0 && element.add(ELEMENT_ACTIVITY_NONZERO_OFFSET).read() != 0 {
            element.add(ELEMENT_ACTIVITY_FLAGS_OFFSET).write(activity_flags | 2);
        }
    } else {
        (active_ops.flagged_handler)(task);
    }

    if task.add(TASK_CHILD_LIST_WORD).read() != 0 {
        (active_ops.detach_children)(task, 1);
    }
    (active_ops.remove)(task, 1, 1);
    let resource = element.cast::<u32>().add(ELEMENT_RESOURCE_WORD).read() as usize as *mut u8;
    (active_ops.resource_release)(resource, task);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const TASK_OFFSET: usize = 0;
    const ELEMENT_OFFSET: usize = 0x200;
    const PLST_CLASS_TAG: u32 = 0x706c_7374;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::PLST_TASK_COMPLETE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ORDER: [u32; 5] = [0; 5];
    static mut ORDER_LEN: usize = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_CONTEXT: usize = 0;
    static mut RESOURCE: usize = 0;

    unsafe fn record(step: u32) { ORDER[ORDER_LEN] = step; ORDER_LEN += 1; }
    unsafe extern "C" fn record_notify(list: *mut u8, tag: u32, task: *mut u32, flags: u32, stack: u32) {
        assert_eq!((flags, stack), (0, 0));
        NOTIFY_LIST = list as usize; NOTIFY_TAG = tag; NOTIFY_CONTEXT = task as usize; record(1);
    }
    unsafe extern "C" fn record_flagged(_: *mut u32) { record(2); }
    unsafe extern "C" fn record_detach(_: *mut u32, notify: u32) { assert_eq!(notify, 1); record(3); }
    unsafe extern "C" fn record_remove(_: *mut u32, first: u32, second: u32) { assert_eq!((first, second), (1, 1)); record(4); }
    unsafe extern "C" fn record_release(resource: *mut u8, _: *mut u32) { RESOURCE = resource as usize; record(5); }

    struct OpsGuard(PlstTaskCompleteOps);
    impl Drop for OpsGuard { fn drop(&mut self) { unsafe { PLST_TASK_COMPLETE_OPS = self.0 }; } }
    unsafe fn install_recorder() -> OpsGuard {
        let previous = PLST_TASK_COMPLETE_OPS;
        PLST_TASK_COMPLETE_OPS = PlstTaskCompleteOps { notify: record_notify, flagged_handler: record_flagged, detach_children: record_detach, remove: record_remove, resource_release: record_release };
        ORDER = [0; 5]; ORDER_LEN = 0; NOTIFY_LIST = 0; NOTIFY_TAG = 0; NOTIFY_CONTEXT = 0; RESOURCE = 0;
        OpsGuard(previous)
    }
    unsafe fn fixture() -> Option<(*mut u32, *mut u8)> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        let task = base.add(TASK_OFFSET).cast::<u32>();
        let element = base.add(ELEMENT_OFFSET);
        task.write(element as usize as u32);
        element.cast::<u32>().add(1).write(PLST_CLASS_TAG);
        task.add(TASK_ACTIVE_LINK_WORD).write(1);
        Some((task, element))
    }

    #[test]
    fn rejects_null_foreign_and_inactive_tasks_without_calls() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder() };
        assert_eq!(unsafe { plst_task_complete(core::ptr::null_mut()) }, -50);
        let Some((task, element)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("ui/plst_task_complete")); return; };
        unsafe { element.cast::<u32>().add(1).write(0); }
        assert_eq!(unsafe { plst_task_complete(task) }, -50);
        unsafe { element.cast::<u32>().add(1).write(PLST_CLASS_TAG); task.add(TASK_ACTIVE_LINK_WORD).write(0); }
        assert_eq!(unsafe { plst_task_complete(task) }, -50);
        unsafe { assert_eq!(ORDER_LEN, 0); }
    }

    #[test]
    fn unflagged_task_notifies_marks_detaches_removes_and_releases() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder() };
        let Some((task, element)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("ui/plst_task_complete")); return; };
        unsafe { task.add(TASK_CHILD_LIST_WORD).write(1); element.add(ELEMENT_ACTIVITY_FLAGS_OFFSET).write(1); element.add(ELEMENT_ACTIVITY_NONZERO_OFFSET).write(1); element.cast::<u32>().add(ELEMENT_RESOURCE_WORD).write(0x1234_5000); }
        assert_eq!(unsafe { plst_task_complete(task) }, 0);
        unsafe {
            assert_eq!(ORDER, [1, 3, 4, 5, 0]);
            assert_eq!(NOTIFY_LIST, element as usize + ELEMENT_NOTIFY_LIST_OFFSET);
            assert_eq!(NOTIFY_TAG, COMPLETE_NOTIFY_TAG); assert_eq!(NOTIFY_CONTEXT, task as usize);
            assert_eq!(*element.add(ELEMENT_ACTIVITY_FLAGS_OFFSET), 3); assert_eq!(RESOURCE, 0x1234_5000);
        }
    }

    #[test]
    fn flagged_task_uses_handler_and_skips_activity_mark_and_detach() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder() };
        let Some((task, element)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("ui/plst_task_complete")); return; };
        unsafe { *task.cast::<u8>().add(TASK_FLAGS_OFFSET) = 1; element.add(ELEMENT_ACTIVITY_FLAGS_OFFSET).write(1); element.add(ELEMENT_ACTIVITY_NONZERO_OFFSET).write(1); }
        assert_eq!(unsafe { plst_task_complete(task) }, 0);
        unsafe { assert_eq!(ORDER, [1, 2, 4, 5, 0]); assert_eq!(*element.add(ELEMENT_ACTIVITY_FLAGS_OFFSET), 1); }
    }
}
