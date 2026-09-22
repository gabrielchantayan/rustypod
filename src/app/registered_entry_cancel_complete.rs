//! Registered-entry cancellation completion — original: `FUN_082931e4` @
//! `0x082931e4`.
//!
//! The raw body is exactly 124 bytes (`0x082931e4..0x08293260`), followed by
//! the registration-table literal `0x089d04c4`; `0x08293264` begins a distinct
//! `push` prologue. A complete A32 decode finds three inbound plain `bl` sites
//! and no predicated `bl` sites. The body has five plain `bl` instructions and
//! two tail `b` dispatches.
//!
//! It locks the controller's leading mutex, invokes the unrecovered retail
//! channel operation at `0x081073f8` with its `+0x34` context and entry key,
//! and finds that key's 24-byte registration record. An inactive record unlocks
//! and tail-posts its `+0x04` mailbox cell. An active record repeatedly invokes
//! the unrecovered drain operation at `0x082938f8` until it returns zero, then
//! unlocks. Deliberate deviation: the two unrecovered operations are expressed
//! as typed retail-address calls on target and injected callbacks in host tests;
//! target tail branches become ordinary Rust returns.

#[cfg(target_os = "none")]
use crate::app::four_slot_key_index::four_slot_key_index;
#[cfg(target_os = "none")]
use crate::kernel::kobj::{mailbox_slot_post, Mailbox};
#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const REGISTRATION_TABLE: usize = 0x089d_04c4;
const ENTRY_SIZE: usize = 0x18;
const ENTRY_POST_CELL_OFFSET: usize = 0x04;
const ENTRY_ACTIVE_OFFSET: usize = 0x11;
const CONTROLLER_CHANNEL_CONTEXT_OFFSET: usize = 0x34;
const RETAIL_CHANNEL_OPERATION: usize = 0x0810_73f8;
const RETAIL_ENTRY_DRAIN: usize = 0x0829_38f8;

type EntryOperation = unsafe extern "C" fn(*mut u8, u32);
type EntryDrain = unsafe extern "C" fn(*mut u8, u32, u32) -> i32;
type MailboxPost = unsafe extern "C" fn(u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_channel_operation(context: *mut u8, entry_id: u32) {
    let operation: EntryOperation = core::mem::transmute(RETAIL_CHANNEL_OPERATION);
    operation(context, entry_id);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_entry_drain(controller: *mut u8, entry_id: u32) -> i32 {
    let drain: EntryDrain = core::mem::transmute(RETAIL_ENTRY_DRAIN);
    drain(controller, entry_id, 1)
}

/// Completes cancellation for the registered entry selected by `entry_id`.
///
/// # Safety
///
/// `controller` must begin with a target `Mutex`, contain a valid target pointer
/// at `+0x34`, and `entry_id` must select an entry in the four-slot table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn registered_entry_cancel_complete(controller: *mut u8, entry_id: u32) {
    #[cfg(target_os = "none")]
    {
        mutex_lock(controller.cast::<Mutex>());
        let channel_context = core::ptr::read(controller.add(CONTROLLER_CHANNEL_CONTEXT_OFFSET).cast::<u32>()) as *mut u8;
        retail_channel_operation(channel_context, entry_id);
        let slot_index = four_slot_key_index(controller, entry_id) as usize;
        let entry = (REGISTRATION_TABLE as *mut u8).add(slot_index * ENTRY_SIZE);
        if core::ptr::read(entry.add(ENTRY_ACTIVE_OFFSET)) == 0 {
            mutex_unlock(controller.cast::<Mutex>());
            mailbox_slot_post(core::ptr::read(entry.add(ENTRY_POST_CELL_OFFSET).cast::<u32>()) as *mut *mut Mailbox);
            return;
        }
        while retail_entry_drain(controller, core::ptr::read_volatile(entry) as u32) != 0 {}
        mutex_unlock(controller.cast::<Mutex>());
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (controller, entry_id);
        panic!("registered_entry_cancel_complete requires retailOS addresses on host");
    }
}

#[cfg(test)]
unsafe fn registered_entry_cancel_complete_with_ops(
    controller: *mut u8,
    channel_context: *mut u8,
    entry_id: u32,
    entry: *mut u8,
    lock: EntryOperation,
    channel_operation: EntryOperation,
    drain: EntryDrain,
    unlock: EntryOperation,
    post: MailboxPost,
) {
    lock(controller, 0);
    channel_operation(channel_context, entry_id);
    if core::ptr::read(entry.add(ENTRY_ACTIVE_OFFSET)) == 0 {
        unlock(controller, 0);
        post(core::ptr::read(entry.add(ENTRY_POST_CELL_OFFSET).cast::<u32>()));
        return;
    }
    while drain(controller, core::ptr::read_volatile(entry) as u32, 1) != 0 {}
    unlock(controller, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static DRAINS: AtomicUsize = AtomicUsize::new(0);
    static mut CONTROLLER: *mut u8 = core::ptr::null_mut();
    static mut CONTEXT: *mut u8 = core::ptr::null_mut();
    static mut POST_CELL: u32 = 0;

    unsafe extern "C" fn lock(controller: *mut u8, _: u32) {
        assert_eq!(controller, CONTROLLER);
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 0);
    }
    unsafe extern "C" fn channel_operation(context: *mut u8, entry_id: u32) {
        assert_eq!(context, CONTEXT);
        assert_eq!(entry_id, 0x83);
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 1);
    }
    unsafe extern "C" fn drain(controller: *mut u8, entry_id: u32, one: u32) -> i32 {
        assert_eq!(controller, CONTROLLER);
        assert_eq!(entry_id, 0x83);
        assert_eq!(one, 1);
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 2 + DRAINS.load(Ordering::SeqCst));
        let call = DRAINS.fetch_add(1, Ordering::SeqCst);
        (call < 2) as i32
    }
    unsafe extern "C" fn unlock(controller: *mut u8, _: u32) {
        assert_eq!(controller, CONTROLLER);
    }
    unsafe extern "C" fn post(cell: u32) {
        assert_eq!(cell, POST_CELL);
    }

    #[test]
    fn inactive_entry_unlocks_before_posting_its_mailbox_cell() {
        let mut controller = [0u8; CONTROLLER_CHANNEL_CONTEXT_OFFSET + 4];
        let mut context = [0u8; 1];
        let mut entry = [0u8; ENTRY_SIZE];
        entry[ENTRY_POST_CELL_OFFSET..ENTRY_POST_CELL_OFFSET + 4]
            .copy_from_slice(&0x1234_5678u32.to_ne_bytes());
        unsafe {
            CONTROLLER = controller.as_mut_ptr();
            CONTEXT = context.as_mut_ptr();
            POST_CELL = 0x1234_5678;
            CALLS.store(0, Ordering::SeqCst);
            DRAINS.store(0, Ordering::SeqCst);
            registered_entry_cancel_complete_with_ops(CONTROLLER, CONTEXT, 0x83, entry.as_mut_ptr(), lock, channel_operation, drain, unlock, post);
        }
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(DRAINS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn active_entry_drains_until_zero_then_unlocks_without_posting() {
        let mut controller = [0u8; CONTROLLER_CHANNEL_CONTEXT_OFFSET + 4];
        let mut context = [0u8; 1];
        let mut entry = [0u8; ENTRY_SIZE];
        entry[0] = 0x83;
        entry[ENTRY_ACTIVE_OFFSET] = 1;
        unsafe {
            CONTROLLER = controller.as_mut_ptr();
            CONTEXT = context.as_mut_ptr();
            POST_CELL = 0;
            CALLS.store(0, Ordering::SeqCst);
            DRAINS.store(0, Ordering::SeqCst);
            registered_entry_cancel_complete_with_ops(CONTROLLER, CONTEXT, 0x83, entry.as_mut_ptr(), lock, channel_operation, drain, unlock, post);
        }
        assert_eq!(DRAINS.load(Ordering::SeqCst), 3);
        assert_eq!(CALLS.load(Ordering::SeqCst), 5);
    }
}
