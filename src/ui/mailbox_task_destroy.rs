//! `ui_mailbox_task_destroy` — retailOS `thunk_FUN_0813b254` @ `0x0811f8b8`.
//!
//! Raw extent: 4 bytes (`0x0811f8b8..0x0811f8bc`): an unconditional `b`
//! to `0x0813b254`, whose next real function boundary is `0x0813b280`.
//! Three plain `bl` call sites target this thunk; none are predicated. The
//! delegated 40-byte implementation restores the vtable literal, deletes the
//! mailbox slot at `+0x8`, invokes the no-op hook with `task + 4`, and returns
//! `task`.
//!
//! Deliberate host deviation: the target mailbox slot is one 32-bit word,
//! while a host pointer is wider. Host tests clear that word directly rather
//! than pass an invalid widened slot to `mailbox_slot_delete`; target builds
//! call the real helper.

use crate::kernel::kobj::{mailbox_slot_delete, Mailbox};
use crate::ui::mailbox_task_construct::UiMailboxTask;
use crate::ui::noop_f7f4::ui_noop_f7f4;

const UI_MAILBOX_TASK_VTABLE: u32 = 0x0898_4dcc;

#[cfg(not(test))]
#[inline(always)]
unsafe fn delete_mailbox(slot: *mut u32) {
    unsafe { mailbox_slot_delete(slot.cast::<*mut Mailbox>()) };
}

#[cfg(test)]
#[inline(always)]
unsafe fn delete_mailbox(slot: *mut u32) {
    unsafe { slot.write(0) };
}

/// Restores the task vtable, tears down its mailbox slot, and returns `task`.
///
/// `task` must identify a writable 20-byte target-layout record. It is not
/// NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_mailbox_task_destroy(
    task: *mut UiMailboxTask,
) -> *mut UiMailboxTask {
    unsafe {
        (*task).vtable = UI_MAILBOX_TASK_VTABLE;
        delete_mailbox(core::ptr::addr_of_mut!((*task).mailbox));
        ui_noop_f7f4();
    }
    task
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(mailbox: u32) -> UiMailboxTask {
        UiMailboxTask {
            vtable: 0xdead_beef,
            copied_byte: 0x12,
            initialized: 0x34,
            mailbox,
            payload: 0x5678_9abc,
            state: 0xde,
            padding: [0xf0, 0x0d, 0xca],
        }
    }

    #[test]
    fn restores_vtable_clears_installed_mailbox_and_returns_task() {
        let mut value = task(1);
        let returned = unsafe { ui_mailbox_task_destroy(&mut value) };

        assert_eq!(returned, core::ptr::addr_of_mut!(value));
        assert_eq!(value.vtable, UI_MAILBOX_TASK_VTABLE);
        assert_eq!(value.mailbox, 0);
        assert_eq!(value.copied_byte, 0x12);
        assert_eq!(value.initialized, 0x34);
        assert_eq!(value.payload, 0x5678_9abc);
        assert_eq!(value.state, 0xde);
        assert_eq!(value.padding, [0xf0, 0x0d, 0xca]);
    }

    #[test]
    fn clears_an_empty_mailbox_slot() {
        let mut value = task(0);

        unsafe { ui_mailbox_task_destroy(&mut value) };

        assert_eq!(value.mailbox, 0);
        assert_eq!(value.vtable, UI_MAILBOX_TASK_VTABLE);
    }
}
