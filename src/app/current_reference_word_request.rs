//! `current_reference_word_request` — FUN_08189198 @ 0x08189198.
//! True extent 84 bytes [0x08189198,0x081891ec): 80 code bytes and the
//! 0x66000012 literal. Raw whole-image decoding verifies two incoming plain
//! BLs (0x082c6d98, 0x082c6dc0), zero predicated; body has four plain BLs.
//! Test owner+0x60 with ui_element_reference_is_current. On rejection return
//! zero without modifying state. Otherwise store the supplied word at +0x18,
//! allocate 12 bytes, construct an owned four-byte message, submit it through
//! receiver+4, and return one regardless of submission's discarded result.
//! Deviations: repr(C) pointer fields widen on hosts; target offsets stay exact.
//! The unported 0x0810007c callee retains only its observed submission role;
//! no guessed class identity or substitution with queued_message_post.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use crate::app::message_arena::message_arena_alloc;
use crate::app::queued_message::{queued_message_construct, QueuedMessage};
use crate::ui::element_reference::ui_element_reference_is_current;

#[repr(C)]
pub struct CurrentReferenceWordRequest {
    pub reference_owner: *const u8,
    pub submission_receiver: *mut u8,
    pub unresolved_words: [u32; 4],
    pub requested_word: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x18] = [(); core::mem::offset_of!(CurrentReferenceWordRequest, requested_word)];

type Submit = unsafe extern "C" fn(*mut u8, *mut QueuedMessage);

unsafe fn request_with<Current, Allocate, Construct, SubmitMessage>(
    request: *mut CurrentReferenceWordRequest,
    word: u32,
    current: Current,
    allocate: Allocate,
    construct: Construct,
    submit: SubmitMessage,
) -> u32
where
    Current: Fn(*const u8) -> u32,
    Allocate: Fn(usize) -> *mut u8,
    Construct: Fn(*mut QueuedMessage, u32, *const u8, u32) -> *mut QueuedMessage,
    SubmitMessage: Fn(*mut u8, *mut QueuedMessage),
{
    let owner = read_volatile(addr_of!((*request).reference_owner));
    if current(owner.add(0x60)) == 0 {
        return 0;
    }
    write_volatile(addr_of_mut!((*request).requested_word), word);
    let storage = allocate(12).cast();
    let message = construct(storage, 0x6600_0012, addr_of!(word).cast(), 4);
    let receiver = read_volatile(addr_of!((*request).submission_receiver));
    submit(receiver, message);
    1
}

/// Store and submit a word only while the owner's UI reference is current.
///
/// # Safety
/// `request` is a writable recovered object prefix; its owner contains a valid
/// UI reference at +0x60. Arena and message-construction preconditions apply.
/// Its submission receiver must be valid for firmware routine 0x0810007c.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_reference_word_request(
    request: *mut CurrentReferenceWordRequest,
    word: u32,
) -> u32 {
    request_with(request, word,
        |reference| ui_element_reference_is_current(reference),
        |size| message_arena_alloc(size),
        |storage, code, bytes, count| queued_message_construct(storage, code, bytes, count),
        |receiver, message| {
            let submit: Submit = core::mem::transmute(0x0810_007cusize);
            submit(receiver, message);
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn rejected_reference_preserves_state_and_never_uses_receiver() {
        let owner = [0u32; 28];
        let mut request = CurrentReferenceWordRequest {
            reference_owner: owner.as_ptr().cast(), submission_receiver: core::ptr::null_mut(),
            unresolved_words: [0xfeed_beef; 4], requested_word: 0x1234_5678,
        };
        let result = unsafe { request_with(&mut request, u32::MAX, |_| 0,
            |_| panic!("rejected request allocated"),
            |_, _, _, _| panic!("rejected request constructed"),
            |_, _| panic!("rejected request submitted")) };
        assert_eq!(result, 0);
        assert_eq!(request.requested_word, 0x1234_5678);
        assert_eq!(request.unresolved_words, [0xfeed_beef; 4]);
    }

    #[test]
    fn nonzero_gate_stores_before_allocation_and_preserves_payload_snapshot() {
        let owner = [0u32; 28];
        let mut receiver = 0u32;
        let mut request = CurrentReferenceWordRequest {
            reference_owner: owner.as_ptr().cast(), submission_receiver: (&mut receiver as *mut u32).cast(),
            unresolved_words: [0xfeed_beef; 4], requested_word: 0,
        };
        let request_ptr = &mut request as *mut CurrentReferenceWordRequest;
        for word in [0, 0x8000_0000, u32::MAX] {
            let payload = Cell::new(0);
            let result = unsafe { request_with(request_ptr, word, |_| 0x8000_0000,
                |_| {
                    assert_eq!((*request_ptr).requested_word, word);
                    (*request_ptr).requested_word = 7;
                    core::ptr::null_mut()
                },
                |_, _, bytes, _| {
                    payload.set(bytes.cast::<u32>().read());
                    core::ptr::null_mut()
                },
                |_, _| { (*request_ptr).requested_word = 9; }) };
            assert_eq!(result, 1);
            assert_eq!(payload.get(), word);
            assert_eq!(request.requested_word, 9);
            assert_eq!(request.unresolved_words, [0xfeed_beef; 4]);
        }
    }
}
