//! `notes_view_reset_resources` — original: `FUN_0828a678` @ `0x0828a678`
//! (**104 bytes**, `0x0828a678..0x0828a6e0`).
//!
//! Raw ARM establishes a 104-byte instruction body followed by the three-word
//! literal pool at `0x0828a6e0..0x0828a6e8`; `0x0828a6ec` is the next
//! independently entered function. It has one unconditional direct `bl`
//! (`0x0828a684`) and no predicated direct `bl` instructions, plus three
//! indirect `blx` calls: release through the owned object's vtable `+0x04`
//! and two message dispatches through the receiver vtable `+0x58`. Full-image
//! A32 decoding finds three inbound plain `bl` call sites and no predicated
//! inbound forms.
//!
//! It destroys the embedded state at `+0x58` through the unported retail
//! helper `0x08178d64`, releases and clears the nullable owned object at
//! `+0xd8`, then posts `Str ` resources `0x419c` and `0x419d` through vtable
//! slot `+0x58` in that order.
//!
//! Deliberate deviations: the direct helper has no established semantic
//! identity, so target code calls its verified retail address rather than
//! inventing a seam. Host tests substitute all three external calls; target
//! vtable slots remain target-width words.

use core::ptr;

const EMBEDDED_STATE_OFFSET: usize = 0x58;
const OWNED_OBJECT_OFFSET: usize = 0xd8;
const RETAIL_EMBEDDED_STATE_DESTROY: usize = 0x0817_8d64;
const MESSAGE_CATEGORY: u32 = 0x5374_7220;
const FIRST_RESOURCE_ID: u32 = 0x419c;
const SECOND_RESOURCE_ID: u32 = 0x419d;

type EmbeddedStateDestroy = unsafe extern "C" fn(*mut u8);
type OwnedObjectRelease = unsafe extern "C" fn(*mut u8);
type MessageDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_embedded_state_destroy(_: *mut u8) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_owned_object_release(_: *mut u8) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_message_dispatch(_: *mut u8, _: u32, _: u32) {}

#[cfg(not(target_arch = "arm"))]
pub static mut NOTES_VIEW_EMBEDDED_STATE_DESTROY: EmbeddedStateDestroy = missing_embedded_state_destroy;
#[cfg(not(target_arch = "arm"))]
pub static mut NOTES_VIEW_OWNED_OBJECT_RELEASE: OwnedObjectRelease = missing_owned_object_release;
#[cfg(not(target_arch = "arm"))]
pub static mut NOTES_VIEW_MESSAGE_DISPATCH: MessageDispatch = missing_message_dispatch;

#[inline(always)]
unsafe fn destroy_embedded_state(receiver: *mut u8) {
    #[cfg(target_arch = "arm")]
    let destroy: EmbeddedStateDestroy = core::mem::transmute(RETAIL_EMBEDDED_STATE_DESTROY);
    #[cfg(not(target_arch = "arm"))]
    let destroy = ptr::read_volatile(ptr::addr_of!(NOTES_VIEW_EMBEDDED_STATE_DESTROY));
    destroy(receiver.add(EMBEDDED_STATE_OFFSET));
}

#[inline(always)]
unsafe fn release_owned_object(object: *mut u8) {
    #[cfg(target_arch = "arm")]
    {
        let vtable = ptr::read_volatile(object.cast::<*const u32>());
        let release: OwnedObjectRelease = core::mem::transmute(ptr::read_volatile(vtable.add(1)) as usize);
        release(object);
    }
    #[cfg(not(target_arch = "arm"))]
    ptr::read_volatile(ptr::addr_of!(NOTES_VIEW_OWNED_OBJECT_RELEASE))(object);
}

#[inline(always)]
unsafe fn dispatch_message(receiver: *mut u8, resource_id: u32) {
    #[cfg(target_arch = "arm")]
    {
        let vtable = ptr::read_volatile(receiver.cast::<*const u32>());
        let dispatch: MessageDispatch = core::mem::transmute(ptr::read_volatile(vtable.add(0x58 / 4)) as usize);
        dispatch(receiver, MESSAGE_CATEGORY, resource_id);
    }
    #[cfg(not(target_arch = "arm"))]
    ptr::read_volatile(ptr::addr_of!(NOTES_VIEW_MESSAGE_DISPATCH))(receiver, MESSAGE_CATEGORY, resource_id);
}

/// Resets embedded notes-view state, releases the nullable owned object, and
/// sends both resource notifications.
///
/// # Safety
///
/// `receiver` must be non-NULL, writable through its target-width word at
/// `+0xd8`, and valid for the retail helper's embedded state at `+0x58`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn notes_view_reset_resources(receiver: *mut u8) {
    destroy_embedded_state(receiver);
    let owned_object = ptr::read_volatile(receiver.add(OWNED_OBJECT_OFFSET).cast::<u32>()) as usize as *mut u8;
    if !owned_object.is_null() {
        release_owned_object(owned_object);
        ptr::write_volatile(receiver.add(OWNED_OBJECT_OFFSET).cast::<u32>(), 0);
    }
    dispatch_message(receiver, FIRST_RESOURCE_ID);
    dispatch_message(receiver, SECOND_RESOURCE_ID);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const RECEIVER_BYTES: usize = OWNED_OBJECT_OFFSET + 4;
    #[repr(align(4))]
    struct Receiver([u8; RECEIVER_BYTES]);

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut DESTROYED_STATE: *mut u8 = ptr::null_mut();
    static mut RELEASED_OBJECT: *mut u8 = ptr::null_mut();
    static mut MESSAGES: [(u32, u32); 2] = [(0, 0); 2];
    static mut MESSAGE_COUNT: usize = 0;

    unsafe extern "C" fn record_destroy(state: *mut u8) { DESTROYED_STATE = state; }
    unsafe extern "C" fn record_release(object: *mut u8) { RELEASED_OBJECT = object; }
    unsafe extern "C" fn record_message(_: *mut u8, category: u32, resource_id: u32) {
        MESSAGES[MESSAGE_COUNT] = (category, resource_id);
        MESSAGE_COUNT += 1;
    }

    #[test]
    fn destroys_embedded_state_releases_owned_object_and_notifies_in_order() {
        let _lock = TEST_LOCK.lock();
        let mut receiver = Receiver([0; RECEIVER_BYTES]);
        let Some(owned_object) = try_map_u32_slab(hints::NOTES_VIEW_RESET_RESOURCES, 0x1000) else {
            assert!(note_missing_u32_fixture("app/notes_view_reset_resources"));
            return;
        };
        unsafe {
            DESTROYED_STATE = ptr::null_mut();
            RELEASED_OBJECT = ptr::null_mut();
            MESSAGE_COUNT = 0;
            NOTES_VIEW_EMBEDDED_STATE_DESTROY = record_destroy;
            NOTES_VIEW_OWNED_OBJECT_RELEASE = record_release;
            NOTES_VIEW_MESSAGE_DISPATCH = record_message;
            ptr::write_unaligned(receiver.0.as_mut_ptr().add(OWNED_OBJECT_OFFSET).cast::<u32>(), owned_object as usize as u32);
            notes_view_reset_resources(receiver.0.as_mut_ptr());
            assert_eq!(DESTROYED_STATE, receiver.0.as_mut_ptr().add(EMBEDDED_STATE_OFFSET));
            assert_eq!(RELEASED_OBJECT, owned_object);
            assert_eq!(ptr::read_unaligned(receiver.0.as_ptr().add(OWNED_OBJECT_OFFSET).cast::<u32>()), 0);
            assert_eq!(MESSAGES, [(MESSAGE_CATEGORY, FIRST_RESOURCE_ID), (MESSAGE_CATEGORY, SECOND_RESOURCE_ID)]);
        }
    }

    #[test]
    fn null_owned_object_skips_release_but_still_notifies() {
        let _lock = TEST_LOCK.lock();
        let mut receiver = Receiver([0; RECEIVER_BYTES]);
        unsafe {
            RELEASED_OBJECT = ptr::null_mut();
            MESSAGE_COUNT = 0;
            NOTES_VIEW_EMBEDDED_STATE_DESTROY = record_destroy;
            NOTES_VIEW_OWNED_OBJECT_RELEASE = record_release;
            NOTES_VIEW_MESSAGE_DISPATCH = record_message;
            notes_view_reset_resources(receiver.0.as_mut_ptr());
            assert!(RELEASED_OBJECT.is_null());
            assert_eq!(MESSAGE_COUNT, 2);
            assert_eq!(MESSAGES, [(MESSAGE_CATEGORY, FIRST_RESOURCE_ID), (MESSAGE_CATEGORY, SECOND_RESOURCE_ID)]);
        }
    }
}
