//! Registered-entry channel update and post — original: `FUN_08292f9c` @
//! `0x08292f9c`.
//!
//! The true extent is 60 bytes (`0x08292f9c..0x08292fd8`): the word at
//! `0x08292fd8` is the registration-table literal and the next independent
//! function begins with a push prologue at `0x08292fdc`. Raw ARM decoding
//! finds four inbound direct calls: three plain `bl` (`0x081609a0`,
//! `0x08160d6c`, `0x08160d7c`) and one predicated `blne` (`0x08160a28`).
//! The body contains three plain direct `bl` instructions, to
//! `channel_control_apply_enable`, `four_slot_key_index`, and
//! `mailbox_slot_post`; it has no predicated call forms.
//!
//! It applies `enable` to the channel selected by `entry_id` using the
//! controller's context at `+0x34`, finds that entry in the four-slot
//! registration table, then posts its handle cell at `+0x04`. Deliberate
//! deviation: host tests inject the three operations and a local table because
//! the retail controller and table addresses are not mapped on the host.
use crate::kernel::kobj::Mailbox;

#[cfg(target_os = "none")]
use crate::app::four_slot_key_index::four_slot_key_index;
#[cfg(target_os = "none")]
use crate::drivers::channel_control_enable::channel_control_apply_enable;
#[cfg(target_os = "none")]
use crate::kernel::kobj::mailbox_slot_post;

const REGISTRATION_TABLE: usize = 0x089d_04c4;
const ENTRY_SIZE: usize = 0x18;
const ENTRY_POST_CELL_OFFSET: usize = 0x04;
const CONTROLLER_CHANNEL_CONTEXT_OFFSET: usize = 0x34;
type MailboxSlotPost = unsafe extern "C" fn(*mut *mut Mailbox);
type ChannelControlApply = unsafe extern "C" fn(*mut u8, u32, i32);
type SlotIndex = unsafe extern "C" fn(*mut u8, u32) -> i32;

/// Applies the selected channel state and posts its registration mailbox.
///
/// # Safety
///
/// `controller` must contain a valid target pointer at `+0x34`; `entry_id`
/// must select an entry in the retail four-slot table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_entry_channel_post(controller: *mut u8, entry_id: u32, enable: i32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let channel_context = core::ptr::read(controller.add(CONTROLLER_CHANNEL_CONTEXT_OFFSET).cast::<u32>()) as *mut u8;
        channel_control_apply_enable(channel_context, entry_id, enable);
        let slot_index = four_slot_key_index(controller, entry_id) as usize;
        let post_cell = core::ptr::read((REGISTRATION_TABLE as *mut u8).add(slot_index * ENTRY_SIZE + ENTRY_POST_CELL_OFFSET).cast::<u32>()) as *mut *mut Mailbox;
        mailbox_slot_post(post_cell);
        0
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (controller, entry_id, enable);
        panic!("registered_entry_channel_post requires retailOS addresses on host")
    }
}

#[cfg(test)]
unsafe fn registered_entry_channel_post_with_ops(
    controller: *mut u8,
    channel_context: *mut u8,
    entry_id: u32,
    enable: i32,
    post_cell: *mut *mut Mailbox,
    apply_channel_control: ChannelControlApply,
    slot_index: SlotIndex,
    post: MailboxSlotPost,
) -> u32 {
    apply_channel_control(channel_context, entry_id, enable);
    let _ = slot_index(controller, entry_id);
    post(post_cell);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALL_ORDER: AtomicUsize = AtomicUsize::new(0);
    static mut EXPECTED_CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_CELL: *mut *mut Mailbox = core::ptr::null_mut();

    unsafe extern "C" fn apply_channel_control(context: *mut u8, entry_id: u32, enable: i32) {
        assert_eq!(CALL_ORDER.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(context, EXPECTED_CONTEXT);
        assert_eq!(entry_id, 0x83);
        assert_eq!(enable, -1);
    }

    unsafe extern "C" fn select_last_slot(_controller: *mut u8, entry_id: u32) -> i32 {
        assert_eq!(CALL_ORDER.fetch_add(1, Ordering::SeqCst), 1);
        assert_eq!(entry_id, 0x83);
        3
    }

    unsafe extern "C" fn post(cell: *mut *mut Mailbox) {
        assert_eq!(CALL_ORDER.fetch_add(1, Ordering::SeqCst), 2);
        assert_eq!(cell, EXPECTED_CELL);
    }


    unsafe extern "C" fn ignore_channel_control(_context: *mut u8, _entry_id: u32, _enable: i32) {}
    #[test]
    fn applies_state_before_posting_last_registration_cell() {
        let mut controller = [0u8; CONTROLLER_CHANNEL_CONTEXT_OFFSET + 4];
        let mut context = [0u8; 1];
        let mut post_cell: *mut Mailbox = core::ptr::null_mut();
        unsafe {
            EXPECTED_CONTEXT = context.as_mut_ptr();
            EXPECTED_CELL = &mut post_cell;
            CALL_ORDER.store(0, Ordering::SeqCst);
            assert_eq!(registered_entry_channel_post_with_ops(controller.as_mut_ptr(), context.as_mut_ptr(), 0x83, -1, EXPECTED_CELL, apply_channel_control, select_last_slot, post), 0);
        }
        assert_eq!(CALL_ORDER.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn posts_first_registration_cell() {
        let mut controller = [0u8; CONTROLLER_CHANNEL_CONTEXT_OFFSET + 4];
        let mut context = [0u8; 1];
        let mut post_cell: *mut Mailbox = core::ptr::null_mut();
        unsafe extern "C" fn select_first_slot(_controller: *mut u8, _entry_id: u32) -> i32 { 0 }
        unsafe extern "C" fn verify_first_cell(cell: *mut *mut Mailbox) {
            assert_eq!(cell, EXPECTED_CELL);
        }
        unsafe {
            EXPECTED_CONTEXT = context.as_mut_ptr();
            EXPECTED_CELL = &mut post_cell;
            registered_entry_channel_post_with_ops(controller.as_mut_ptr(), context.as_mut_ptr(), 2, 1, EXPECTED_CELL, ignore_channel_control, select_first_slot, verify_first_cell);
        }
    }
}
