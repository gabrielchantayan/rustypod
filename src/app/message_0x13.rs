//! `message_0x13_construct` — original: `FUN_081cd7b8` @ 0x081cd7b8
//! (36 bytes of instructions, 0x081cd7b8..0x081cd7dc, plus the 4-byte
//! literal-pool word @ 0x081cd7e0 holding the vtable address, so 44 bytes of
//! true extent; **4 plain `bl` call sites and 0 predicated `bl` call sites**
//! from raw A32 decoding). The next real function starts at 0x081cd7e4.
//!
//! Constructs a 16-byte message-code-0x13 object in caller-provided storage:
//! calls [`message_kind_construct`] with kind 0x13, replaces the base vtable
//! with 0x0898db3c, and stores the two opaque payload words at +0x08/+0x0c.
//!
//! Deliberate deviations: none. The base constructor is already ported and is
//! called directly; its intermediate root and message-base vtable writes are
//! preserved before this constructor's derived-vtable overwrite.

use crate::app::message_kind::{message_kind_construct, MessageKind};

/// The literal-pool vtable word at 0x081cd7e0.
pub const MESSAGE_0X13_VTABLE: u32 = 0x0898_db3c;

/// A message-code-0x13 object. The two payload words are opaque: raw callers
/// pass values originating in registers and stack slots, without enough type
/// evidence to assign them a narrower meaning.
#[repr(C)]
pub struct Message0x13 {
    pub base: MessageKind,
    pub first_payload: u32,
    pub second_payload: u32,
}

/// Target byte size of [`Message0x13`].
pub const MESSAGE_0X13_SIZE: usize = 0x10;

const _: [u8; 0x00] = [0; core::mem::offset_of!(Message0x13, base)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(Message0x13, first_payload)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Message0x13, second_payload)];
const _: [u8; MESSAGE_0X13_SIZE] = [0; core::mem::size_of::<Message0x13>()];

/// message_0x13_construct — original: `FUN_081cd7b8` @ 0x081cd7b8
/// (44 bytes of true extent; 4 plain `bl` callers, 0 predicated).
///
/// Constructs `storage` in place as a message-code-0x13 object and returns it.
/// The raw ARM saves `first_payload`/`second_payload` across the base
/// constructor call, then stores them at +0x08/+0x0c after replacing the
/// vtable.
///
/// # Safety
///
/// `storage` must point to at least [`MESSAGE_0X13_SIZE`] writable,
/// word-aligned bytes. Like the original, this performs no NULL check.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_0x13_construct(
    storage: *mut Message0x13,
    first_payload: u32,
    second_payload: u32,
) -> *mut Message0x13 {
    let message = message_kind_construct(storage.cast(), 0x13).cast::<Message0x13>();

    core::ptr::addr_of_mut!((*message).base.base.vtable).write_volatile(MESSAGE_0X13_VTABLE);
    core::ptr::addr_of_mut!((*message).first_payload).write_volatile(first_payload);
    core::ptr::addr_of_mut!((*message).second_payload).write_volatile(second_payload);

    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::message_kind::MESSAGE_KIND_VTABLE;

    #[test]
    fn constructs_all_target_words_and_returns_storage() {
        let mut storage = [0xa5a5_a5a5u32; 4];
        let message = unsafe {
            message_0x13_construct(storage.as_mut_ptr().cast(), 0x1234_5678, 0xdead_beef)
        };

        assert_eq!(message.cast::<u32>(), storage.as_mut_ptr());
        assert_eq!(storage, [MESSAGE_0X13_VTABLE, 0x13, 0x1234_5678, 0xdead_beef]);
        assert_ne!(storage[0], MESSAGE_KIND_VTABLE, "derived vtable replaces base vtable");
    }

    #[test]
    fn overwrites_every_word_of_the_sixteen_byte_object() {
        let mut storage = [0u32; 4];
        unsafe { message_0x13_construct(storage.as_mut_ptr().cast(), 0, u32::MAX) };

        assert_eq!(storage, [MESSAGE_0X13_VTABLE, 0x13, 0, u32::MAX]);
    }
}
