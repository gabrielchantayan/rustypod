//! `byte_state_set_and_notify` — original: `FUN_081ccc78` @ `0x081ccc78`
//! (**52 bytes**, `0x081ccc78..0x081cccab`).
//!
//! Raw ARM establishes a 44-byte instruction body followed by the two-word
//! literal pool at `0x081ccca4..0x081cccab`; `0x081cccac` starts the next
//! independently entered function. It has no direct `bl` instructions and one
//! predicated indirect `blxne` through receiver vtable slot `+0x58`. A
//! full-image A32 decode finds three inbound plain `bl` call sites
//! (`0x0810cce0`, `0x0810cd3c`, and `0x0810d1f0`) and no predicated forms.
//!
//! It replaces the state byte at `+0x8e0`, returning the old zero-extended
//! byte. When that byte differs from the untruncated `u32` input, it notifies
//! vtable slot `+0x58` with category `0x424d6170` and resource `0x848f`.
//!
//! Deliberate deviation: the virtual callee has no established semantic
//! identity. ARM retains the target-width dispatch; host tests use a recording
//! seam.

use core::ptr;

const STATE_BYTE_OFFSET: usize = 0x8e0;
const MESSAGE_CATEGORY: u32 = 0x424d_6170;
const RESOURCE_ID: u32 = 0x848f;

type MessageDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_message_dispatch(_: *mut u8, _: u32, _: u32) {}

#[cfg(not(target_arch = "arm"))]
pub static mut BYTE_STATE_MESSAGE_DISPATCH: MessageDispatch = missing_message_dispatch;

#[inline(always)]
unsafe fn dispatch_message(receiver: *mut u8) {
    #[cfg(target_arch = "arm")]
    {
        let vtable = ptr::read_volatile(receiver.cast::<*const u32>());
        let dispatch: MessageDispatch = core::mem::transmute(
            ptr::read_volatile((vtable as usize as *const u32).add(0x58 / 4)) as usize,
        );
        dispatch(receiver, MESSAGE_CATEGORY, RESOURCE_ID);
    }
    #[cfg(not(target_arch = "arm"))]
    ptr::read_volatile(ptr::addr_of!(BYTE_STATE_MESSAGE_DISPATCH))(
        receiver,
        MESSAGE_CATEGORY,
        RESOURCE_ID,
    );
}

/// Stores a state byte and notifies the receiver when its full input differs
/// from the previous byte.
///
/// # Safety
///
/// `receiver` must be non-NULL and writable through byte offset `+0x8e0`.
/// On ARM, its first word must be a valid vtable with a callable `+0x58` slot
/// when notification is required.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_state_set_and_notify(receiver: *mut u8, new_state: u32) -> u32 {
    let old_state = ptr::read_volatile(receiver.add(STATE_BYTE_OFFSET));
    ptr::write_volatile(receiver.add(STATE_BYTE_OFFSET), new_state as u8);
    if u32::from(old_state) != new_state {
        dispatch_message(receiver);
    }
    u32::from(old_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECEIVER_BYTES: usize = STATE_BYTE_OFFSET + 1;
    #[repr(align(4))]
    struct Receiver([u8; RECEIVER_BYTES]);

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: [(usize, u32, u32); 1] = [(0, 0, 0); 1];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_message(receiver: *mut u8, category: u32, resource_id: u32) {
        CALLS[CALL_COUNT] = (receiver as usize, category, resource_id);
        CALL_COUNT += 1;
    }

    #[test]
    fn unchanged_byte_is_returned_without_notification() {
        let _lock = TEST_LOCK.lock();
        let mut receiver = Receiver([0; RECEIVER_BYTES]);
        unsafe {
            CALL_COUNT = 0;
            BYTE_STATE_MESSAGE_DISPATCH = record_message;
            receiver.0[STATE_BYTE_OFFSET] = 0x41;
            assert_eq!(byte_state_set_and_notify(receiver.0.as_mut_ptr(), 0x41), 0x41);
            assert_eq!(receiver.0[STATE_BYTE_OFFSET], 0x41);
            assert_eq!(CALL_COUNT, 0);
        }
    }

    #[test]
    fn changed_byte_notifies_with_verified_message_words() {
        let _lock = TEST_LOCK.lock();
        let mut receiver = Receiver([0; RECEIVER_BYTES]);
        unsafe {
            CALL_COUNT = 0;
            BYTE_STATE_MESSAGE_DISPATCH = record_message;
            receiver.0[STATE_BYTE_OFFSET] = 7;
            assert_eq!(byte_state_set_and_notify(receiver.0.as_mut_ptr(), 9), 7);
            assert_eq!(receiver.0[STATE_BYTE_OFFSET], 9);
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(CALLS[0], (receiver.0.as_mut_ptr() as usize, MESSAGE_CATEGORY, RESOURCE_ID));
        }
    }

    #[test]
    fn high_input_word_notifies_even_when_its_low_byte_matches() {
        let _lock = TEST_LOCK.lock();
        let mut receiver = Receiver([0; RECEIVER_BYTES]);
        unsafe {
            CALL_COUNT = 0;
            BYTE_STATE_MESSAGE_DISPATCH = record_message;
            receiver.0[STATE_BYTE_OFFSET] = 0;
            assert_eq!(byte_state_set_and_notify(receiver.0.as_mut_ptr(), 0x100), 0);
            assert_eq!(receiver.0[STATE_BYTE_OFFSET], 0);
            assert_eq!(CALL_COUNT, 1);
        }
    }
}
