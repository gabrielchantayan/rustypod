//! `kind_0x1f_message_construct` — original: `FUN_0827ea20` @ 0x0827ea20
//! (64 bytes, 0x0827ea20..0x0827ea60). The next independent function starts
//! at 0x0827ea64; the word at 0x0827ea60 is this constructor's vtable literal.
//! Raw A32 decoding finds **4 unconditional plain `bl` call sites** and zero
//! predicated `bl` call sites.
//!
//! # Algorithm
//!
//! Runs the already-ported kind-message base constructor with kind `0x1f`,
//! overwrites its vtable with `0x089a630c`, then copies five opaque payload
//! values into the derived 28-byte message at offsets +0x08, +0x0c, +0x10,
//! +0x14, and +0x18. The +0x10 store is byte-wide; its upper three bytes are
//! deliberately retained.
//!
//! # Deliberate deviations
//!
//! None. The port directly calls the already-ported base constructor instead
//! of creating a seam; its intermediate vtable store is overwritten exactly
//! as it is in retailOS.

use crate::app::message_kind::{message_kind_construct, MessageKind};

pub const KIND_0X1F: u32 = 0x1f;
pub const KIND_0X1F_MESSAGE_SIZE: usize = 0x1c;
pub const KIND_0X1F_MESSAGE_VTABLE: u32 = 0x089a_630c;

/// The target's 28-byte derived message. Pointer-like payloads remain `u32`
/// so host layout retains the target's four-byte field spacing.
#[repr(C)]
pub struct Kind0x1fMessage {
    pub base: MessageKind,
    pub first_payload: u32,
    pub second_payload: u32,
    pub byte_payload: u8,
    pub byte_payload_tail: [u8; 3],
    pub fourth_payload: u32,
    pub fifth_payload: u32,
}

const _: [u8; 0x08] = [0; core::mem::offset_of!(Kind0x1fMessage, first_payload)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Kind0x1fMessage, second_payload)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(Kind0x1fMessage, byte_payload)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(Kind0x1fMessage, fourth_payload)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(Kind0x1fMessage, fifth_payload)];
const _: [u8; KIND_0X1F_MESSAGE_SIZE] = [0; core::mem::size_of::<Kind0x1fMessage>()];

/// Constructs a kind-0x1f message in caller-provided storage.
///
/// # Safety
///
/// `storage` must point to at least [`KIND_0X1F_MESSAGE_SIZE`] writable,
/// word-aligned bytes. The original performs no NULL or bounds checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kind_0x1f_message_construct(
    storage: *mut Kind0x1fMessage,
    first_payload: u32,
    second_payload: u32,
    byte_payload: u32,
    fourth_payload: u32,
    fifth_payload: u32,
) -> *mut Kind0x1fMessage {
    let message = message_kind_construct(storage.cast(), KIND_0X1F).cast::<Kind0x1fMessage>();

    core::ptr::addr_of_mut!((*message).base.base.vtable).write_volatile(KIND_0X1F_MESSAGE_VTABLE);
    core::ptr::addr_of_mut!((*message).first_payload).write_volatile(first_payload);
    core::ptr::addr_of_mut!((*message).second_payload).write_volatile(second_payload);
    core::ptr::addr_of_mut!((*message).byte_payload).write_volatile(byte_payload as u8);
    core::ptr::addr_of_mut!((*message).fourth_payload).write_volatile(fourth_payload);
    core::ptr::addr_of_mut!((*message).fifth_payload).write_volatile(fifth_payload);

    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct GuardedStorage {
        before: u32,
        message: Kind0x1fMessage,
        after: u32,
    }

    #[test]
    fn constructs_full_layout_and_preserves_byte_tail() {
        let mut storage: GuardedStorage = unsafe { core::mem::zeroed() };
        storage.before = 0xa5a5_a5a5;
        storage.after = 0x5a5a_5a5a;
        storage.message.byte_payload_tail = [0xa1, 0xb2, 0xc3];
        let message = core::ptr::addr_of_mut!(storage.message);

        let returned = unsafe {
            kind_0x1f_message_construct(message, 0x1111_2222, 0x3333_4444, 0xdead_beef, 0x5555_6666, 0x7777_8888)
        };

        assert_eq!(returned, message);
        assert_eq!(storage.before, 0xa5a5_a5a5);
        assert_eq!(storage.after, 0x5a5a_5a5a);
        assert_eq!(storage.message.base.base.vtable, KIND_0X1F_MESSAGE_VTABLE);
        assert_eq!(storage.message.base.kind, KIND_0X1F);
        assert_eq!(storage.message.first_payload, 0x1111_2222);
        assert_eq!(storage.message.second_payload, 0x3333_4444);
        assert_eq!(storage.message.byte_payload, 0xef);
        assert_eq!(storage.message.byte_payload_tail, [0xa1, 0xb2, 0xc3]);
        assert_eq!(storage.message.fourth_payload, 0x5555_6666);
        assert_eq!(storage.message.fifth_payload, 0x7777_8888);
    }
}
