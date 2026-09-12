//! `event_payload_message_construct` — original: `FUN_08275b40` @ 0x08275b40
//! (48 bytes of code, 0x08275b40..0x08275b70, plus the 4-byte literal-pool
//! word @ 0x08275b70, so 52 bytes of true extent; **8 plain `bl` call sites,
//! 0 predicated `bl`, and 0 tail `b`** — verified by decoding every ARM B/BL
//! word in `osos.dec`).
//!
//! Constructs the 20-byte message sent to event handlers: initializes its
//! [`MessageKind`] base with the caller's kind, installs the derived vtable,
//! copies two payload words, and stores the event code. The eight callers all
//! invoke it unconditionally; seven are the 0x0811065c..0x08110d68
//! handler-notification family and one is 0x08100044.
//!
//! # Deviations
//!
//! Ghidra declares the original `void`, but its r0 stays live across the base
//! constructor and is returned in the final `pop {..,pc}`; every caller uses
//! that pointer. The port returns `storage` for that ABI contract. The derived
//! vtable is an address constant only: its target data is not modeled and this
//! constructor does not dispatch through it.

use crate::app::message_kind::{message_kind_construct, MessageKind};

/// The derived message vtable loaded from the literal-pool word at 0x08275b70.
pub const EVENT_PAYLOAD_MESSAGE_VTABLE: u32 = 0x089a_5fb4;

/// A 20-byte event-handler message, including its 8-byte kind-tagged base.
#[repr(C)]
pub struct EventPayloadMessage {
    /// +0x00..+0x07: base vtable and caller-supplied kind.
    pub base: MessageKind,
    /// +0x08 and +0x0c: the two words copied from constructor argument r2.
    pub payload: [u32; 2],
    /// +0x10: the event code supplied in r3.
    pub event_code: u32,
}

/// Target byte size of [`EventPayloadMessage`].
pub const EVENT_PAYLOAD_MESSAGE_SIZE: usize = 0x14;

const _: [u8; 0x00] = [0; core::mem::offset_of!(EventPayloadMessage, base)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(EventPayloadMessage, payload)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(EventPayloadMessage, event_code)];
const _: [u8; EVENT_PAYLOAD_MESSAGE_SIZE] = [0; core::mem::size_of::<EventPayloadMessage>()];

/// event_payload_message_construct — original: `FUN_08275b40` @ 0x08275b40
/// (48 bytes of code plus the 4-byte literal pool word at 0x08275b70;
/// **8 unconditional `bl` call sites, no predicated calls or tail branches**).
///
/// Initializes the `MessageKind` base, replaces its vtable with
/// [`EVENT_PAYLOAD_MESSAGE_VTABLE`], then copies `payload_words[0]`,
/// `payload_words[1]`, and `event_code` in the exact load/store order of the
/// ARM body. There is no NULL guard: both pointers must be valid, aligned
/// storage just as they must be for the original `ldr`/`str` instructions.
///
/// # Safety
///
/// `storage` must designate at least [`EVENT_PAYLOAD_MESSAGE_SIZE`] writable,
/// word-aligned bytes. `payload_words` must designate two readable,
/// word-aligned `u32`s. They may alias `storage`; the ordered volatile accesses
/// preserve the original's observable aliasing behavior.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn event_payload_message_construct(
    storage: *mut EventPayloadMessage,
    kind: u32,
    payload_words: *const u32,
    event_code: u32,
) -> *mut EventPayloadMessage {
    let this = message_kind_construct(storage.cast(), kind).cast::<EventPayloadMessage>();

    core::ptr::addr_of_mut!((*this).base.base.vtable).write_volatile(EVENT_PAYLOAD_MESSAGE_VTABLE);
    let first_payload_word = payload_words.read_volatile();
    core::ptr::addr_of_mut!((*this).payload[0]).write_volatile(first_payload_word);
    let second_payload_word = payload_words.add(1).read_volatile();
    core::ptr::addr_of_mut!((*this).payload[1]).write_volatile(second_payload_word);
    core::ptr::addr_of_mut!((*this).event_code).write_volatile(event_code);

    this
}

#[cfg(test)]
mod tests {
    use super::{event_payload_message_construct, EventPayloadMessage, EVENT_PAYLOAD_MESSAGE_VTABLE};

    #[test]
    fn constructs_all_five_message_words_without_overrunning_storage() {
        let mut words = [0xa5a5_a5a5; 7];
        let payload = [0x1020_3040, 0x5060_7080];
        let storage = words.as_mut_ptr().cast::<EventPayloadMessage>();

        let result = unsafe {
            event_payload_message_construct(storage, 0x0000_000d, payload.as_ptr(), 0x0000_0059)
        };

        assert_eq!(result, storage, "the base constructor's r0 is returned");
        assert_eq!(
            words,
            [
                EVENT_PAYLOAD_MESSAGE_VTABLE,
                0x0000_000d,
                0x1020_3040,
                0x5060_7080,
                0x0000_0059,
                0xa5a5_a5a5,
                0xa5a5_a5a5,
            ],
            "writes exactly the five target words in ARM order"
        );
    }

    #[test]
    fn aliases_payload_reads_after_base_and_derived_vtable_writes() {
        let mut words = [0xfeed_face; 5];
        let storage = words.as_mut_ptr().cast::<EventPayloadMessage>();

        unsafe {
            event_payload_message_construct(storage, 0x0000_0006, words.as_ptr(), 0x0000_0010);
        }

        assert_eq!(
            words,
            [
                EVENT_PAYLOAD_MESSAGE_VTABLE,
                0x0000_0006,
                EVENT_PAYLOAD_MESSAGE_VTABLE,
                0x0000_0006,
                0x0000_0010,
            ],
            "source loads observe the preceding derived-vtable and kind stores"
        );
    }
}
