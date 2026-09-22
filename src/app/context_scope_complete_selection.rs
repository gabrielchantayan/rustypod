//! Completes the selected item held by a context scope.
//!
//! `context_scope_complete_selection` — original: `FUN_08283ed0` @
//! **0x08283ed0** (108 bytes). Raw ARM runs through `pop {r4-r8,pc}` at
//! 0x08283f38; the distinct `cmp r1,#0` at 0x08283f3c begins
//! `context_scope_capture`. Decoding every aligned B/BL word in `osos.dec`
//! finds three inbound direct calls, all plain `bl` (0x080484e4, 0x0816ebf4,
//! and 0x0817a798), and no predicated calls. Its body has two plain `bl`
//! calls plus one `blx` through the scope's vtable slot +0x0c.
//!
//! # Algorithm
//!
//! Call the scope's vtable slot +0x0c. If it returns nonzero, fetch the
//! requested item from subject+0x04 using `ui_plst_slot_item_at`; if that
//! returns nonzero and `plst_task_complete` returns zero, notify teardown for
//! the same subject and return one. Every other path returns zero.
//! # Deliberate deviations
//!
//! The scope vtable target has no recovered semantic name in `names.yaml`, so
//! it is a volatile seam named only for its proven availability role. The
//! two named callees use their Rust ports by default; tests replace all three
//! boundaries with recording functions. Target pointers stay u32 words, so
//! host pointer width never changes the +0x04 field offset.

use core::ptr;

/// ABI of the scope's unported vtable slot +0x0c.
pub type ContextScopeSubjectAvailable = unsafe extern "C" fn(*mut u8) -> i32;
pub type PlstSlotItemAt = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32;
pub type PlstTaskComplete = unsafe extern "C" fn(*mut u32) -> i32;
pub type PlstElementNotifyTeardown = unsafe extern "C" fn(*mut u8);

#[derive(Clone, Copy)]
pub struct ContextScopeCompleteSelectionOps {
    pub subject_available: ContextScopeSubjectAvailable,
    pub slot_item_at: PlstSlotItemAt,
    pub task_complete: PlstTaskComplete,
    pub notify_teardown: PlstElementNotifyTeardown,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_subject_available(scope: *mut u8) -> i32 {
    let vtable = unsafe { (scope as *const u32).read_volatile() };
    let address = unsafe { ((vtable as usize + 0x0c) as *const u32).read_volatile() };
    let available: ContextScopeSubjectAvailable = unsafe { core::mem::transmute(address as usize) };
    unsafe { available(scope) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_subject_available(_scope: *mut u8) -> i32 { 0 }

unsafe extern "C" fn ported_slot_item_at(subject: *mut u8, selector: u32, reverse_flag: u32, index: u32) -> u32 {
    unsafe { crate::ui::plst_slot_item::ui_plst_slot_item_at(subject, selector, reverse_flag, index) }
}

unsafe extern "C" fn ported_task_complete(task: *mut u32) -> i32 {
    unsafe { crate::ui::plst_task_complete::plst_task_complete(task) }
}

unsafe extern "C" fn ported_notify_teardown(subject: *mut u8) {
    unsafe { crate::ui::plst_element_teardown::plst_element_notify_teardown(subject) }
}

#[cfg(target_os = "none")]
pub static mut CONTEXT_SCOPE_COMPLETE_SELECTION_OPS: ContextScopeCompleteSelectionOps = ContextScopeCompleteSelectionOps {
    subject_available: firmware_subject_available,
    slot_item_at: ported_slot_item_at,
    task_complete: ported_task_complete,
    notify_teardown: ported_notify_teardown,
};
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_SCOPE_COMPLETE_SELECTION_OPS: ContextScopeCompleteSelectionOps = ContextScopeCompleteSelectionOps {
    subject_available: missing_subject_available,
    slot_item_at: ported_slot_item_at,
    task_complete: ported_task_complete,
    notify_teardown: ported_notify_teardown,
};

#[inline(always)]
fn complete_selection_ops() -> ContextScopeCompleteSelectionOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(CONTEXT_SCOPE_COMPLETE_SELECTION_OPS)) }
}

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_scope_complete_selection(scope: *mut u8, index: u32, selector: u32, reverse_flag: u32) -> i32 {
    let ops = complete_selection_ops();
    if unsafe { (ops.subject_available)(scope) } == 0 {
        return 0;
    }
    let subject = unsafe { (scope.add(4) as *const u32).read() as usize as *mut u8 };
    let task = unsafe { (ops.slot_item_at)(subject, selector, reverse_flag, index) };
    if task == 0 || unsafe { (ops.task_complete)(task as usize as *mut u32) } != 0 {
        return 0;
    }
    unsafe { (ops.notify_teardown)(subject) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut AVAILABLE: i32 = 0;
    static mut SLOT_RESULT: u32 = 0;
    static mut COMPLETE_RESULT: i32 = 0;
    static mut SLOT_ARGS: (*mut u8, u32, u32, u32) = (ptr::null_mut(), 0, 0, 0);
    static mut COMPLETED_TASK: *mut u32 = ptr::null_mut();
    static mut NOTIFIED_SUBJECT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn available(_scope: *mut u8) -> i32 { unsafe { AVAILABLE } }
    unsafe extern "C" fn slot_item(subject: *mut u8, selector: u32, reverse: u32, index: u32) -> u32 {
        unsafe { SLOT_ARGS = (subject, selector, reverse, index); SLOT_RESULT }
    }
    unsafe extern "C" fn complete(task: *mut u32) -> i32 {
        unsafe { COMPLETED_TASK = task; COMPLETE_RESULT }
    }
    unsafe extern "C" fn notify(subject: *mut u8) { unsafe { NOTIFIED_SUBJECT = subject } }

    fn install_mocks() {
        unsafe {
            AVAILABLE = 0;
            SLOT_RESULT = 0;
            COMPLETE_RESULT = 0;
            SLOT_ARGS = (ptr::null_mut(), 0, 0, 0);
            COMPLETED_TASK = ptr::null_mut();
            NOTIFIED_SUBJECT = ptr::null_mut();
            CONTEXT_SCOPE_COMPLETE_SELECTION_OPS = ContextScopeCompleteSelectionOps {
                subject_available: available, slot_item_at: slot_item,
                task_complete: complete, notify_teardown: notify,
            };
        }
    }

    fn scope_with_subject(subject: u32) -> [u32; 5] { [0, subject, 0, 0, 0] }

    #[test]
    fn unavailable_subject_skips_all_later_calls() {
        let _guard = OPS_LOCK.lock();
        install_mocks();
        let mut scope = scope_with_subject(0x1234_5000);
        assert_eq!(unsafe { context_scope_complete_selection(scope.as_mut_ptr().cast(), 7, 2, 1) }, 0);
        unsafe { assert_eq!(SLOT_ARGS, (ptr::null_mut(), 0, 0, 0)); assert_eq!(NOTIFIED_SUBJECT, ptr::null_mut()); }
    }

    #[test]
    fn missing_item_and_failed_completion_do_not_notify() {
        let _guard = OPS_LOCK.lock();
        install_mocks();
        unsafe { AVAILABLE = 1; }
        let mut scope = scope_with_subject(0x1234_5000);
        assert_eq!(unsafe { context_scope_complete_selection(scope.as_mut_ptr().cast(), 7, 2, 1) }, 0);
        unsafe { SLOT_RESULT = 0x2345_6000; COMPLETE_RESULT = -1; }
        assert_eq!(unsafe { context_scope_complete_selection(scope.as_mut_ptr().cast(), 7, 2, 1) }, 0);
        unsafe { assert_eq!(COMPLETED_TASK as usize, 0x2345_6000); assert_eq!(NOTIFIED_SUBJECT, ptr::null_mut()); }
    }

    #[test]
    fn completes_selected_task_then_notifies_subject() {
        let _guard = OPS_LOCK.lock();
        install_mocks();
        unsafe { AVAILABLE = 1; SLOT_RESULT = 0x2345_6000; }
        let mut scope = scope_with_subject(0x1234_5000);
        assert_eq!(unsafe { context_scope_complete_selection(scope.as_mut_ptr().cast(), 9, 3, 1) }, 1);
        unsafe {
            assert_eq!(SLOT_ARGS, (0x1234_5000usize as *mut u8, 3, 1, 9));
            assert_eq!(COMPLETED_TASK as usize, 0x2345_6000);
            assert_eq!(NOTIFIED_SUBJECT as usize, 0x1234_5000);
        }
    }
}
