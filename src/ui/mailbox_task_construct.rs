//! `ui_mailbox_task_construct` — retailOS `FUN_0813b214` @ `0x0813b214`.
//!
//! Raw extent: 64 bytes (`0x0813b214..0x0813b254`), comprising 60 bytes of
//! instructions and the required literal word at `0x0813b250`; the next
//! function starts with `push {r4, lr}` at `0x0813b254`. It has two direct,
//! unpredicated `bl` instructions (`ui_copy_byte` @ `0x0811f7e8` and
//! `mailbox_slot_create` @ `0x0808e294`), and no predicated `bl`.
//!
//! Installs the opaque vtable literal, copies one caller-supplied byte into
//! `+0x4`, sets state bytes `+0x5 = 1` and `+0x10 = 2`, creates the mailbox
//! in the target-word slot at `+0x8`, and stores `payload` at `+0xc`.
//!
//! Deliberate host deviation: target mailbox pointers occupy one 32-bit word,
//! whereas host pointers are wider. Test builds write a nonzero mailbox-word
//! sentinel instead of invoking the real mailbox allocator; target builds use
//! `mailbox_slot_create` directly.

use crate::kernel::kobj::{mailbox_slot_create, Mailbox};
use crate::ui::byte_store::ui_copy_byte;

const UI_MAILBOX_TASK_VTABLE: u32 = 0x0898_4dcc;
const HOST_MAILBOX_SENTINEL: u32 = 1;

/// Target layout of the 20-byte opaque mailbox-task record.
#[repr(C)]
pub struct UiMailboxTask {
    pub vtable: u32,
    pub copied_byte: u8,
    pub initialized: u8,
    pub mailbox: u32,
    pub payload: u32,
    pub state: u8,
    pub padding: [u8; 3],
}

#[cfg(not(test))]
#[inline(always)]
unsafe fn create_mailbox(slot: *mut u32) {
    unsafe { mailbox_slot_create(slot.cast::<*mut Mailbox>()) };
}

#[cfg(test)]
#[inline(always)]
unsafe fn create_mailbox(slot: *mut u32) {
    unsafe { slot.write(HOST_MAILBOX_SENTINEL) };
}

/// Initializes a UI mailbox-task record and returns `task`.
///
/// The source must identify one readable byte; `task` must identify a writable
/// 20-byte target-layout record. Neither argument is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_mailbox_task_construct(
    task: *mut UiMailboxTask,
    source: *const u8,
    payload: u32,
) -> *mut UiMailboxTask {
    unsafe {
        (*task).vtable = UI_MAILBOX_TASK_VTABLE;
        ui_copy_byte(core::ptr::addr_of_mut!((*task).copied_byte), source);
        (*task).initialized = 1;
        create_mailbox(core::ptr::addr_of_mut!((*task).mailbox));
        (*task).payload = payload;
        (*task).state = 2;
    }
    task
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_every_defined_target_word_and_byte() {
        let mut source = 0xa5u8;
        let mut task = UiMailboxTask {
            vtable: 0xdead_beef,
            copied_byte: 0,
            initialized: 0,
            mailbox: 0,
            payload: 0,
            state: 0,
            padding: [0x5a; 3],
        };

        let returned = unsafe { ui_mailbox_task_construct(&mut task, &mut source, 0x1234_5678) };

        assert_eq!(returned, core::ptr::addr_of_mut!(task));
        assert_eq!(task.vtable, UI_MAILBOX_TASK_VTABLE);
        assert_eq!(task.copied_byte, 0xa5);
        assert_eq!(task.initialized, 1);
        assert_eq!(task.mailbox, HOST_MAILBOX_SENTINEL);
        assert_eq!(task.payload, 0x1234_5678);
        assert_eq!(task.state, 2);
        assert_eq!(task.padding, [0x5a; 3]);
    }

    #[test]
    fn reads_source_before_overwriting_the_adjacent_state_byte() {
        let mut task = UiMailboxTask {
            vtable: 0,
            copied_byte: 0,
            initialized: 0x73,
            mailbox: 0,
            payload: 0,
            state: 0,
            padding: [0; 3],
        };
        let source = core::ptr::addr_of!(task.initialized);

        unsafe { ui_mailbox_task_construct(&mut task, source, 0) };

        assert_eq!(task.copied_byte, 0x73);
        assert_eq!(task.initialized, 1);
    }
}
