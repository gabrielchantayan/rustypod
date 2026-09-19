//! 'plst' task resource-callback completion.
//!
//! - `plst_task_resource_callback` — original: `FUN_0805cde4` @
//!   `0x0805cde4` (80 bytes). Verified inbound call count: 4 direct `bl`
//!   calls, all unconditional.

use core::ptr;

use crate::app::resource::cache::resource_callback_dispatch;

use super::plst_task_complete::plst_task_is_active;

const TASK_FLAGS_OFFSET: usize = 0x1d;
const TASK_RESULT_WORD: usize = 5;
const ELEMENT_SELF_WORD: usize = 0x40 / core::mem::size_of::<u32>();
/// Callback literal held at `0x0805ce34`; no semantic identity is recovered.
const RESOURCE_CALLBACK: usize = 0x080c_c284;

/// Boundary for the callback dispatcher invoked for flagged tasks.
pub type PlstTaskResourceCallbackDispatch = unsafe extern "C" fn(*mut u8, usize, *mut u8) -> i32;

/// Active dispatcher seam. Target builds use the recovered callback dispatcher;
/// host tests replace it without manufacturing a callable ARM literal.
pub static mut PLST_TASK_RESOURCE_CALLBACK_DISPATCH: PlstTaskResourceCallbackDispatch = resource_callback_dispatch;

#[inline(always)]
unsafe fn callback_dispatch() -> PlstTaskResourceCallbackDispatch {
    ptr::read_volatile(ptr::addr_of!(PLST_TASK_RESOURCE_CALLBACK_DISPATCH))
}

/// plst_task_resource_callback — original: `FUN_0805cde4` @ `0x0805cde4`
/// (80 bytes).
///
/// Raw bytes run through the `pop {r4,pc}` at `0x0805ce30`; the following
/// `0x080cc284` callback literal is outside the function and the next real
/// prologue is at `0x0805ce38`. There are two direct calls in the body, both
/// plain `bl` (`0x08061650` and `0x0806b604`); no predicated `bl` occurs.
/// Inbound references are four plain `bl` calls (`0x08048210`, `0x0806d440`,
/// `0x0806d500`, and `0x0806d690`); no predicated form occurs.
/// If the task is inactive, no field changes. An active unflagged task stores
/// one at +0x14. An active flagged task dispatches literal `0x080cc284` with
/// context one, then stores zero at +0x14 only if element +0x40 still points
/// at that task.
///
/// Deliberate deviation: the already-ported activity predicate replaces the
/// stock call at `0x08061650`. The callback dispatcher uses a volatile seam so
/// host tests can observe the call without assigning an identity to literal
/// `0x080cc284`; target builds retain that exact callback address.
///
/// # Safety
/// `task` may be NULL. A non-NULL task must satisfy
/// [`plst_task_is_active`]'s readable-layout requirements. A flagged active
/// task additionally requires a valid resource callback tree and an element
/// readable through +0x43.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plst_task_resource_callback(task: *mut u32) {
    if plst_task_is_active(task) == 0 {
        return;
    }

    if task.cast::<u8>().add(TASK_FLAGS_OFFSET).read() & 1 == 0 {
        task.add(TASK_RESULT_WORD).write(1);
        return;
    }

    callback_dispatch()(task.cast(), RESOURCE_CALLBACK, 1usize as *mut u8);
    let element = task.read() as usize as *mut u32;
    if element.add(ELEMENT_SELF_WORD).read() == task as usize as u32 {
        task.add(TASK_RESULT_WORD).write(0);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    const ELEMENT_OFFSET: usize = 0x200;
    const PLST_CLASS_TAG: u32 = 0x706c_7374;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::PLST_TASK_RESOURCE_CALLBACK, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALLS: u32 = 0;
    static mut DISPATCH_ROOT: usize = 0;
    static mut DISPATCH_CALLBACK: usize = 0;
    static mut DISPATCH_CONTEXT: usize = 0;

    unsafe extern "C" fn record_dispatch(root: *mut u8, callback: usize, context: *mut u8) -> i32 {
        DISPATCH_CALLS += 1;
        DISPATCH_ROOT = root as usize;
        DISPATCH_CALLBACK = callback;
        DISPATCH_CONTEXT = context as usize;
        0
    }

    struct OpsGuard(PlstTaskResourceCallbackDispatch);
    impl Drop for OpsGuard {
        fn drop(&mut self) { unsafe { PLST_TASK_RESOURCE_CALLBACK_DISPATCH = self.0 }; }
    }
    unsafe fn install_recorder() -> OpsGuard {
        let previous = PLST_TASK_RESOURCE_CALLBACK_DISPATCH;
        PLST_TASK_RESOURCE_CALLBACK_DISPATCH = record_dispatch;
        DISPATCH_CALLS = 0;
        DISPATCH_ROOT = 0;
        DISPATCH_CALLBACK = 0;
        DISPATCH_CONTEXT = 0;
        OpsGuard(previous)
    }
    unsafe fn fixture() -> Option<(*mut u32, *mut u32)> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, FIXTURE_LEN);
        let task = base.cast::<u32>();
        let element = base.add(ELEMENT_OFFSET).cast::<u32>();
        task.write(element as usize as u32);
        task.add(4).write(1);
        element.add(1).write(PLST_CLASS_TAG);
        element.add(ELEMENT_SELF_WORD).write(task as usize as u32);
        Some((task, element))
    }

    #[test]
    fn inactive_tasks_leave_result_and_dispatch_unchanged() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder() };
        assert_eq!(unsafe { plst_task_resource_callback(core::ptr::null_mut()) }, ());
        let Some((task, element)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("ui/plst_task_resource_callback")); return; };
        unsafe { task.add(TASK_RESULT_WORD).write(0xfeed_beef); element.add(1).write(0); plst_task_resource_callback(task); }
        unsafe { assert_eq!(task.add(TASK_RESULT_WORD).read(), 0xfeed_beef); assert_eq!(DISPATCH_CALLS, 0); }
    }

    #[test]
    fn unflagged_active_task_sets_result_without_dispatch() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder() };
        let Some((task, _)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("ui/plst_task_resource_callback")); return; };
        unsafe { plst_task_resource_callback(task); assert_eq!(task.add(TASK_RESULT_WORD).read(), 1); assert_eq!(DISPATCH_CALLS, 0); }
    }

    #[test]
    fn flagged_task_dispatches_then_clears_only_when_still_owned() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder() };
        let Some((task, element)) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("ui/plst_task_resource_callback")); return; };
        unsafe {
            task.cast::<u8>().add(TASK_FLAGS_OFFSET).write(1);
            task.add(TASK_RESULT_WORD).write(0xfeed_beef);
            plst_task_resource_callback(task);
            assert_eq!((DISPATCH_CALLS, DISPATCH_ROOT, DISPATCH_CALLBACK, DISPATCH_CONTEXT), (1, task as usize, RESOURCE_CALLBACK, 1));
            assert_eq!(task.add(TASK_RESULT_WORD).read(), 0);
            element.add(ELEMENT_SELF_WORD).write(0);
            task.add(TASK_RESULT_WORD).write(0xfeed_beef);
            plst_task_resource_callback(task);
            assert_eq!(task.add(TASK_RESULT_WORD).read(), 0xfeed_beef);
        }
    }
}
