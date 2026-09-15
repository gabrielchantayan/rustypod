//! `resource_handle_pair_reset_notify` — original: `FUN_08113ea4` @
//! `0x08113ea4` (**152 bytes**, `0x08113ea4..0x08113f3c`).
//!
//! Raw ARM establishes a 140-byte instruction body followed by the three-word
//! literal pool at `0x08113f30..0x08113f3c`; the next separately linked
//! function begins at `0x08113f3c`. It contains six unconditional direct `bl`
//! instructions at `0x08113eb8`, `0x08113ec4`, `0x08113ecc`, `0x08113edc`,
//! `0x08113eec`, and `0x08113ef4`, zero predicated `bl` instructions, and two
//! indirect `blx r3` vtable calls.
//! Scanning the full image for inbound ARM branches finds five direct call
//! sites: four unconditional `bl` at `0x08068f70`, `0x08113bc4`,
//! `0x08114364`, and `0x08211fdc`, plus `bleq` at `0x08212138`.
//!
//! It constructs an empty temporary refcounted handle twice, copy-assigns it
//! into the receiver's handle slots at `+0x540` and `+0x544`, thereby releasing
//! their old retain-count bodies, then sends resource identifiers `0x63c8` and
//! `0x63c9` through vtable slot `+0x58` with category `0x44726177`.
//!
//! Deliberate host deviation: target pointer slots are four bytes apart while
//! host pointers are wider. Host tests replace both target-word reset calls and
//! the raw `+0x58` dispatch with seams.

#[cfg(target_arch = "arm")]
use crate::cxx::handle::{
    refcounted_body_release_retain_count, refcounted_ptr_construct_tertiary_variant,
    refcounted_ptr_copy_assign_retain_count, RefcountedBody,
};

const FIRST_HANDLE_OFFSET: usize = 0x540;
const SECOND_HANDLE_OFFSET: usize = 0x544;
const MESSAGE_CATEGORY: u32 = 0x4472_6177;
const FIRST_RESOURCE_ID: u32 = 0x63c8;
const SECOND_RESOURCE_ID: u32 = 0x63c9;

pub type ResourceHandlePairMessageDispatch = unsafe extern "C" fn(*mut u8, u32, u32);
pub type ResourceHandlePairResetHandle = unsafe extern "C" fn(*mut u8, usize);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_resource_handle_pair_message_dispatch(_: *mut u8, _: u32, _: u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_resource_handle_pair_reset_handle(_: *mut u8, _: usize) {}

/// Host replacement for a target-width refcounted-handle reset.
#[cfg(not(target_arch = "arm"))]
pub static mut RESOURCE_HANDLE_PAIR_RESET_HANDLE: ResourceHandlePairResetHandle =
    missing_resource_handle_pair_reset_handle;
/// Host replacement for the receiver vtable's `+0x58` message-dispatch slot.
#[cfg(not(target_arch = "arm"))]
pub static mut RESOURCE_HANDLE_PAIR_MESSAGE_DISPATCH: ResourceHandlePairMessageDispatch =
    missing_resource_handle_pair_message_dispatch;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn reset_handle(receiver: *mut u8, offset: usize) {
    let mut empty: *mut RefcountedBody = core::ptr::null_mut();
    refcounted_ptr_construct_tertiary_variant(&mut empty, 0, 0);
    refcounted_ptr_copy_assign_retain_count(receiver.add(offset).cast(), &empty);
    refcounted_body_release_retain_count(&mut empty);
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn reset_handle(receiver: *mut u8, offset: usize) {
    core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_HANDLE_PAIR_RESET_HANDLE))(receiver, offset);
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn dispatch_resource_handle_pair_message(receiver: *mut u8, resource_id: u32) {
    let vtable = receiver.cast::<*const u32>().read();
    let dispatch: ResourceHandlePairMessageDispatch = core::mem::transmute(vtable.add(0x58 / 4).read() as usize);
    dispatch(receiver, MESSAGE_CATEGORY, resource_id);
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn dispatch_resource_handle_pair_message(receiver: *mut u8, resource_id: u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(RESOURCE_HANDLE_PAIR_MESSAGE_DISPATCH))(
        receiver,
        MESSAGE_CATEGORY,
        resource_id,
    );
}

/// Clears two receiver-owned refcounted handles and notifies their resources.
///
/// # Safety
///
/// `receiver` must be non-NULL and have valid aligned refcounted-handle slots
/// at `+0x540` and `+0x544`. Any non-NULL bodies must meet the release helper's
/// requirements. On ARM, its first word must be a valid vtable whose `+0x58`
/// slot accepts `(receiver, category, resource_id)`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn resource_handle_pair_reset_notify(receiver: *mut u8) {
    reset_handle(receiver, FIRST_HANDLE_OFFSET);
    reset_handle(receiver, SECOND_HANDLE_OFFSET);
    dispatch_resource_handle_pair_message(receiver, FIRST_RESOURCE_ID);
    dispatch_resource_handle_pair_message(receiver, SECOND_RESOURCE_ID);
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECEIVER_BYTES: usize = SECOND_HANDLE_OFFSET + 4;
    #[repr(align(4))]
    struct Receiver([u8; RECEIVER_BYTES]);

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut MESSAGES: [(*mut u8, u32, u32); 2] = [(core::ptr::null_mut(), 0, 0); 2];
    static mut MESSAGE_COUNT: usize = 0;
    static mut RESET_OFFSETS: [usize; 2] = [0; 2];
    static mut RESET_COUNT: usize = 0;

    unsafe extern "C" fn record_message(receiver: *mut u8, category: u32, resource_id: u32) {
        MESSAGES[MESSAGE_COUNT] = (receiver, category, resource_id);
        MESSAGE_COUNT += 1;
    }

    unsafe extern "C" fn record_reset(_: *mut u8, offset: usize) {
        RESET_OFFSETS[RESET_COUNT] = offset;
        RESET_COUNT += 1;
    }

    #[test]
    fn resets_both_target_word_slots_and_notifies_each_resource() {
        let _lock = TEST_LOCK.lock();
        let mut receiver = Receiver([0; RECEIVER_BYTES]);
        unsafe {
            RESET_COUNT = 0;
            MESSAGE_COUNT = 0;
            RESOURCE_HANDLE_PAIR_RESET_HANDLE = record_reset;
            RESOURCE_HANDLE_PAIR_MESSAGE_DISPATCH = record_message;
            resource_handle_pair_reset_notify(receiver.0.as_mut_ptr());
            assert_eq!(RESET_COUNT, 2);
            assert_eq!(RESET_OFFSETS, [FIRST_HANDLE_OFFSET, SECOND_HANDLE_OFFSET]);
            assert_eq!(MESSAGE_COUNT, 2);
            assert_eq!(MESSAGES, [
                (receiver.0.as_mut_ptr(), MESSAGE_CATEGORY, FIRST_RESOURCE_ID),
                (receiver.0.as_mut_ptr(), MESSAGE_CATEGORY, SECOND_RESOURCE_ID),
            ]);
        }
    }

    #[test]
    fn null_handles_still_notify_in_order() {
        let _lock = TEST_LOCK.lock();
        let mut receiver = Receiver([0; RECEIVER_BYTES]);
        unsafe {
            RESET_COUNT = 0;
            MESSAGE_COUNT = 0;
            RESOURCE_HANDLE_PAIR_RESET_HANDLE = record_reset;
            RESOURCE_HANDLE_PAIR_MESSAGE_DISPATCH = record_message;
            resource_handle_pair_reset_notify(receiver.0.as_mut_ptr());
            assert_eq!(RESET_OFFSETS, [FIRST_HANDLE_OFFSET, SECOND_HANDLE_OFFSET]);
            assert_eq!(MESSAGES[0].2, FIRST_RESOURCE_ID);
            assert_eq!(MESSAGES[1].2, SECOND_RESOURCE_ID);
        }
    }
}
