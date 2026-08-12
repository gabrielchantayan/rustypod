//! `queued_message_construct` — a factory for the framework's standard
//! queued-message envelope and its owned payload.
//!
//! Original: `FUN_08103464` @ 0x08103464 (72 bytes exactly,
//! 0x08103464..0x081034ac; 56 `bl` call sites, no tail branches).
//!
//! # Algorithm
//!
//! ```text
//! message = FUN_08266a48(storage, 0x16)       // base/message-kind ctor
//! message->vtable = 0x08980744                 // derived envelope vtable
//! payload = FUN_081b9248(operator_new(0x10),
//!                         message_code, bytes, byte_count)
//! message->payload = payload                    // +0x08
//! return message
//! ```
//!
//! The object is the standard **queued-message envelope**. Every call site
//! constructs it from arena storage (usually `FUN_08103400` followed by
//! `FUN_0826c0d8(..., 0xc)`) and hands it directly to `FUN_08110fdc`, which
//! posts it to a task queue. The nested 16-byte payload stores the caller's
//! message code, byte count, and, for non-zero byte counts, an owned
//! `0x27`-tagged copy of the supplied bytes. Its destructor
//! (`FUN_081b92ac`) frees that copy; the outer destructor (`FUN_0810351c`)
//! virtual-dispatches the payload destructor through its +0x04 slot.
//!
//! `FUN_08266a48` is not an allocator: its five-instruction body runs the
//! framework root constructor, plants its own base vtable, and stores its
//! second argument at +0x04. Thus the `0x16` immediate is this envelope's
//! message kind/class tag, while `storage` is caller-provided arena memory.
//! This factory then overwrites the vtable with its derived literal
//! `DAT_081034ac = 0x08980744`.
//!
//! The base/message-kind constructor is now ported
//! ([`crate::app::message_kind::message_kind_construct`]) and is the wired
//! default for the base slot; only the payload constructor still rides
//! [`QUEUED_MESSAGE_OPS`]. `operator_new(0x10)` is already ported and is
//! called directly. The payload host default panics, so test callers must
//! install an explicit recording payload op.

use core::ptr::addr_of_mut;

/// The fixed message kind/class argument to `FUN_08266a48`
/// (`mov r1, #0x16`). It is a tag, not an allocation size: the caller
/// has already supplied the 12-byte envelope storage.
pub const QUEUED_MESSAGE_KIND: u32 = 0x16;
/// Derived queued-message-envelope vtable from the literal pool word
/// `DAT_081034ac` @ 0x081034ac.
pub const QUEUED_MESSAGE_VTABLE: u32 = 0x0898_0744;
/// Heap allocation passed to the nested payload constructor.
pub const QUEUED_MESSAGE_PAYLOAD_SIZE: usize = 0x10;

/// The 12-byte target envelope. Keeping the pointer as a pointer (rather
/// than a `u32`) preserves the target +0x08 offset while avoiding pointer
/// truncation in host behavioral tests.
#[repr(C)]
#[derive(Debug)]
pub struct QueuedMessage {
    /// Derived vtable (`+0x00`).
    pub vtable: u32,
    /// Base constructor's kind/tag word (`+0x04`).
    pub kind: u32,
    /// The constructed nested payload (`+0x08`).
    pub payload: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x00] = [0; core::mem::offset_of!(QueuedMessage, vtable)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(QueuedMessage, kind)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(QueuedMessage, payload)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::size_of::<QueuedMessage>()];

/// The two unported constructors the factory invokes.
#[derive(Clone, Copy)]
pub struct QueuedMessageOps {
    /// `FUN_08266a48(storage, 0x16)`: runs the message-kind base
    /// constructor over caller-owned storage and returns its object.
    /// Ported as [`crate::app::message_kind::message_kind_construct`];
    /// the slot remains replaceable for host-side recording.
    pub construct_base: unsafe extern "C" fn(*mut QueuedMessage, u32) -> *mut QueuedMessage,
    /// `FUN_081b9248(block, code, bytes, byte_count)`: constructs and
    /// possibly copies the payload, returning the nested object.
    pub construct_payload: unsafe extern "C" fn(*mut u8, u32, *const u8, u32) -> *mut u8,
}

/// Wired default for the base-constructor slot: the ported
/// [`crate::app::message_kind::message_kind_construct`] @ 0x08266a48,
/// adapted to this module's envelope pointer type (ABI-identical).
unsafe extern "C" fn ported_construct_base(
    storage: *mut QueuedMessage,
    kind: u32,
) -> *mut QueuedMessage {
    unsafe { crate::app::message_kind::message_kind_construct(storage.cast(), kind) }.cast()
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_construct_payload(
    block: *mut u8,
    code: u32,
    bytes: *const u8,
    byte_count: u32,
) -> *mut u8 {
    let f: unsafe extern "C" fn(*mut u8, u32, *const u8, u32) -> *mut u8 =
        unsafe { core::mem::transmute(0x081b_9248usize) };
    unsafe { f(block, code, bytes, byte_count) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_construct_payload(
    _block: *mut u8,
    _code: u32,
    _bytes: *const u8,
    _byte_count: u32,
) -> *mut u8 {
    panic!("queued_message_construct requires payload constructor 0x081b9248")
}

#[cfg(target_os = "none")]
const DEFAULT_QUEUED_MESSAGE_OPS: QueuedMessageOps = QueuedMessageOps {
    construct_base: ported_construct_base,
    construct_payload: firmware_construct_payload,
};

#[cfg(not(target_os = "none"))]
const DEFAULT_QUEUED_MESSAGE_OPS: QueuedMessageOps = QueuedMessageOps {
    construct_base: ported_construct_base,
    construct_payload: missing_construct_payload,
};

/// Active construction operations. Host tests replace these slots; the
/// base-constructor default is the ported 0x08266a48, while the payload
/// default still calls the firmware address on target (panics on host).
pub static mut QUEUED_MESSAGE_OPS: QueuedMessageOps = DEFAULT_QUEUED_MESSAGE_OPS;

/// queued_message_construct — original: `FUN_08103464` @ 0x08103464
/// (72 bytes; 56 `bl` call sites).
///
/// Builds a kind-0x16 queued-message envelope in caller-provided storage,
/// installs its derived vtable, constructs a 16-byte owned payload with the
/// three caller arguments in r1/r2/r3 order, stores that returned payload at
/// +0x08, and returns the base constructor's object pointer.
///
/// # Safety
///
/// `storage` must name writable arena storage for a 12-byte target envelope;
/// its base constructor and the payload constructor must be installed before
/// host use. All requirements mirror the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queued_message_construct(
    storage: *mut QueuedMessage,
    message_code: u32,
    bytes: *const u8,
    byte_count: u32,
) -> *mut QueuedMessage {
    let construct_base = unsafe { addr_of_mut!(QUEUED_MESSAGE_OPS).read_volatile().construct_base };
    let message = unsafe { construct_base(storage, QUEUED_MESSAGE_KIND) };

    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*message).vtable), QUEUED_MESSAGE_VTABLE) };

    let payload_block = unsafe { crate::heap::veneers::operator_new(QUEUED_MESSAGE_PAYLOAD_SIZE) };
    let construct_payload =
        unsafe { addr_of_mut!(QUEUED_MESSAGE_OPS).read_volatile().construct_payload };
    let payload = unsafe { construct_payload(payload_block, message_code, bytes, byte_count) };
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*message).payload), payload) };

    message
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};
    use std::sync::{Mutex, MutexGuard};

    /// Serializes swaps of [`QUEUED_MESSAGE_OPS`].
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    static mut BASE_STORAGE: *mut QueuedMessage = core::ptr::null_mut();
    static mut BASE_KIND: u32 = 0;
    static mut BASE_RESULT: *mut QueuedMessage = core::ptr::null_mut();
    static mut PAYLOAD_BLOCK: *mut u8 = core::ptr::null_mut();
    static mut PAYLOAD_CODE: u32 = 0;
    static mut PAYLOAD_BYTES: *const u8 = core::ptr::null();
    static mut PAYLOAD_BYTE_COUNT: u32 = 0;
    static mut PAYLOAD_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_construct_base(
        storage: *mut QueuedMessage,
        kind: u32,
    ) -> *mut QueuedMessage {
        unsafe {
            BASE_STORAGE = storage;
            BASE_KIND = kind;
            BASE_RESULT
        }
    }

    unsafe extern "C" fn recording_construct_payload(
        block: *mut u8,
        code: u32,
        bytes: *const u8,
        byte_count: u32,
    ) -> *mut u8 {
        unsafe {
            PAYLOAD_BLOCK = block;
            PAYLOAD_CODE = code;
            PAYLOAD_BYTES = bytes;
            PAYLOAD_BYTE_COUNT = byte_count;
            PAYLOAD_RESULT
        }
    }

    fn install_mocks() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            QUEUED_MESSAGE_OPS = QueuedMessageOps {
                construct_base: recording_construct_base,
                construct_payload: recording_construct_payload,
            };
            BASE_STORAGE = core::ptr::null_mut();
            BASE_KIND = 0;
            BASE_RESULT = core::ptr::null_mut();
            PAYLOAD_BLOCK = core::ptr::null_mut();
            PAYLOAD_CODE = 0;
            PAYLOAD_BYTES = core::ptr::null();
            PAYLOAD_BYTE_COUNT = 0;
            PAYLOAD_RESULT = core::ptr::null_mut();
        }
        (ops_guard, heap_guard)
    }

    fn restore_mocks(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe { QUEUED_MESSAGE_OPS = DEFAULT_QUEUED_MESSAGE_OPS };
        drop(guards);
    }

    #[test]
    fn constructs_tagged_envelope_and_routes_payload_arguments_in_order() {
        let guards = install_mocks();
        let mut storage = QueuedMessage {
            vtable: 0,
            kind: 0,
            payload: core::ptr::null_mut(),
        };
        let mut envelope = QueuedMessage {
            vtable: 0,
            kind: 0,
            payload: core::ptr::null_mut(),
        };
        let mut payload_storage = [0u8; QUEUED_MESSAGE_PAYLOAD_SIZE];
        let payload_result = 0xA110_0040usize as *mut u8;
        let bytes = [0x13u8, 0x37, 0xc0, 0xde];
        unsafe {
            set_alloc_ret(payload_storage.as_mut_ptr());
            BASE_RESULT = &mut envelope;
            PAYLOAD_RESULT = payload_result;

            let result = queued_message_construct(
                &mut storage,
                0x6600_0014,
                bytes.as_ptr(),
                bytes.len() as u32,
            );

            assert_eq!(result, &mut envelope as *mut QueuedMessage, "returns the outer constructor result");
            assert_eq!(BASE_STORAGE, &mut storage as *mut QueuedMessage, "caller arena storage enters base ctor");
            assert_eq!(BASE_KIND, QUEUED_MESSAGE_KIND, "r1 is the literal 0x16 tag");
            assert_eq!(envelope.vtable, QUEUED_MESSAGE_VTABLE, "derived vtable at +0");
            assert_eq!(envelope.payload, payload_result, "nested ctor result at +8");
            assert_eq!(PAYLOAD_BLOCK, payload_storage.as_mut_ptr(), "operator_new(0x10) feeds nested ctor");
            assert_eq!(PAYLOAD_CODE, 0x6600_0014, "message code is nested r1");
            assert_eq!(PAYLOAD_BYTES, bytes.as_ptr(), "bytes pointer is nested r2");
            assert_eq!(PAYLOAD_BYTE_COUNT, bytes.len() as u32, "byte count is nested r3");
            assert_eq!(alloc_log(), (1, QUEUED_MESSAGE_PAYLOAD_SIZE, 2), "one tag-2 operator_new(0x10)");
        }
        restore_mocks(guards);
    }

    #[test]
    fn forwards_zero_length_payload_verbatim() {
        let guards = install_mocks();
        let mut envelope = QueuedMessage {
            vtable: 0,
            kind: 0,
            payload: core::ptr::null_mut(),
        };
        let mut payload_storage = [0u8; QUEUED_MESSAGE_PAYLOAD_SIZE];
        unsafe {
            set_alloc_ret(payload_storage.as_mut_ptr());
            BASE_RESULT = &mut envelope;
            PAYLOAD_RESULT = 0xA110_0080usize as *mut u8;
            queued_message_construct(&mut envelope, 0x20001, core::ptr::null(), 0);

            assert_eq!(PAYLOAD_CODE, 0x20001);
            assert!(PAYLOAD_BYTES.is_null(), "the nullable bytes argument is unmodified");
            assert_eq!(PAYLOAD_BYTE_COUNT, 0, "zero is forwarded, not special-cased by the factory");
            assert_eq!(envelope.payload, PAYLOAD_RESULT);
        }
        restore_mocks(guards);
    }
}
