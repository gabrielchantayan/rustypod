//! The framework's standard queued-message envelope: the factory that
//! builds one and the poster that hands it to another object's task
//! queue.
//!
//! - [`queued_message_construct`] — original: `FUN_08103464` @
//!   0x08103464 (72 bytes exactly, 0x08103464..0x081034ac; 56 `bl` call
//!   sites, no tail branches).
//! - [`queued_message_post`] — original: `FUN_08110fdc` @ 0x08110fdc
//!   (164 bytes of true extent, 0x08110fdc..0x0811107f; 45 call sites —
//!   44 `bl` plus one `blne`). The consumer this module's header already
//!   named: it stamps the `'MsgS'` FourCC onto a stack message carrying
//!   the envelope, posts it to the destination task's queue, and
//!   releases the envelope through its own vtable `+0x04` slot on any
//!   failure.
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

// ---------------------------------------------------------------------------
// The poster: `queued_message_post` @ 0x08110fdc
// ---------------------------------------------------------------------------

/// The FourCC message tag this poster stamps into word 0 of the outgoing
/// task message: `'MsgS'` (`('M'<<24)|('s'<<16)|('g'<<8)|'S'`), the pool
/// literal @ 0x0811107c. Its near-twin @ 0x081251cc — the same shape one
/// level up, with a fifth byte field — stamps `'MsgB'` (0x4d736742), so
/// the low byte selects the flavor.
pub const TASK_MESSAGE_TAG_MSGS: u32 = 0x4d73_6753;

/// The tagged task message the poster builds on its stack, as the
/// message-post path consumes it.
///
/// Seven words, not five: the cell copy the post helper runs
/// (`FUN_0827210c` @ 0x0827210c) moves a **fixed 28 bytes** — three
/// single-word loads plus one `ldm`/`stm` of four — regardless of the
/// tag. The original reserves only 20 bytes (`sub sp, sp, #0x14`) and
/// lets that copy read two words of its own saved-register area; the
/// port reserves all seven so every byte the copy reads is defined
/// storage. See the deviations on [`queued_message_post`].
///
/// The pointer-valued fields are `u32` because they are wire words in a
/// message the kernel copies verbatim, not live Rust references.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostedTaskMessage {
    /// +0x00: the FourCC tag ([`TASK_MESSAGE_TAG_MSGS`]).
    pub tag: u32,
    /// +0x04, +0x08: never written by this poster (they belong to other
    /// tags' payloads).
    pub unused_04: [u32; 2],
    /// +0x0c: the message target (`str r5, [sp, #0xc]`).
    pub target: u32,
    /// +0x10: the queued-message envelope being posted
    /// (`str r4, [sp, #0x10]`).
    pub message: u32,
    /// +0x14, +0x18: outside this poster's writes, inside the copy.
    pub unused_14: [u32; 2],
}

// Exact on the 32-bit target: word 0 is the tag, words 3 and 4 are the
// two stores, and the whole struct is the 28 bytes the cell copy moves.
const _: [u8; 0x00] = [0; core::mem::offset_of!(PostedTaskMessage, tag)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(PostedTaskMessage, target)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(PostedTaskMessage, message)];
const _: [u8; 0x1c] = [0; core::mem::size_of::<PostedTaskMessage>()];

impl PostedTaskMessage {
    /// The uninitialized-but-reserved template: only the three words the
    /// original writes carry meaning.
    const BLANK: PostedTaskMessage = PostedTaskMessage {
        tag: 0,
        unused_04: [0; 2],
        target: 0,
        message: 0,
        unused_14: [0; 2],
    };
}

/// The part of the envelope vtable this poster dispatches: slot `+0x04`,
/// the release/destructor entry (`ldr r0,[r4]; ldr r1,[r0,#4]; blx r1`).
/// The same slot `FUN_0810351c` — the envelope destructor — occupies.
#[repr(C)]
pub struct QueuedMessageVtable {
    /// +0x00: not dispatched here.
    pub slot_00: u32,
    /// +0x04: release the envelope and its owned payload.
    pub release: unsafe extern "C" fn(*mut QueuedMessage),
}

/// The object a caller hands the poster as the message's destination.
/// Only its `+0x10` link is read.
#[repr(C)]
pub struct MessageTarget {
    /// +0x00..+0x10: untouched here.
    pub unused_00: [u32; 4],
    /// +0x10: the owner record carrying the destination task context.
    pub owner: *mut MessageTargetOwner,
}

/// The owner record reached through [`MessageTarget::owner`]. Only its
/// `+0x0c` link is read — the same `+0x0c` the twin poster @ 0x081251cc
/// reads straight off its first argument.
#[repr(C)]
pub struct MessageTargetOwner {
    /// +0x00..+0x0c: untouched here.
    pub unused_00: [u32; 3],
    /// +0x0c: the destination task's context block, whose `+0x1c` queue
    /// pool is the queue the message is posted to.
    pub task_ctx: *mut crate::kernel::task::TaskCtx,
}

/// queued_message_post — original: `FUN_08110fdc` @ **0x08110fdc**
/// (160 bytes of code + one pool word @ 0x0811107c = **164 bytes** of
/// true extent, 0x08110fdc..0x0811107f; **45 call sites — 44 `bl` and
/// one `blne` (@ 0x0814b080), no plain `b`**, binary-verified by
/// decoding every B/BL word in `work/firmware/osos.dec`. The next
/// function is the bare `bx lr` @ 0x08111080).
///
/// Posts a queued-message envelope to another object's task queue and
/// takes ownership of it: on any failure — no destination queue, no
/// reply queue, or a post the helper rejects — the envelope is released
/// through its own vtable `+0x04` slot rather than leaked.
///
/// ```text
/// target_queue = target->owner->task_ctx->queue_pool   // unguarded
/// posted       = 0
/// if reply_queue == 0 {
///     reply_queue = current_task_ctx_block()->queue_pool
///     if reply_queue == 0 { goto release }
/// }
/// if target_queue == 0 { goto release }
/// msg = { tag: 'MsgS', target, message }
/// posted = no_wait ? post(reply, target_queue, &msg, wait=0, flags)
///                  : task_message_post_sync(reply, target_queue, &msg, flags)
/// if posted != 0 { return posted }
/// release:
/// if message != NULL { message->vtable->release(message) }
/// return posted                                        // always 0 here
/// ```
///
/// `queued_message_construct` above builds the envelope every caller
/// passes as `message` — `FUN_08103550`/`FUN_08103464` then straight
/// into this `bl` (e.g. 0x08113f8c/0x08113fc0/0x08113ff4). `no_wait` is
/// 1 at every site inspected and `reply_queue`/`flags` are 0, i.e. the
/// hot path is fire-and-forget onto the destination queue with the
/// current task's own queue as the reply handle.
///
/// The single predicated site is the caller's guard, not ours: the
/// callee's own NULL guard covers only `message`.
///
/// # Deviations
///
/// - The two post shims are the sync/async pair 0x0812bf70 / 0x0812c628.
///   Only the sync one is ported
///   ([`crate::kernel::task_message::task_message_post_sync`]) and it is
///   called directly. 0x0812c628 is its 20-byte mirror whose entire body
///   is the same helper call with the wait flag forced to 0, so the
///   `no_wait` branch makes that call through the already-established
///   [`crate::kernel::task_message::TASK_MESSAGE_OPS`] slot instead of
///   re-stubbing a function that is one immediate away from a sibling.
/// - The outgoing message is 28 bytes of defined storage rather than the
///   original's 20 — see [`PostedTaskMessage`].
/// - `current_task_ctx_block()` may report NULL (no current task); the
///   original loads `+0x1c` off it unconditionally. The port reads a
///   NULL context as reply queue 0, which lands on exactly the edge the
///   original's `cmp r0,#0; beq` takes.
/// - Ghidra's C names five parameters but drops all four arguments from
///   the `FUN_0812c628` call; the arguments are the same ones the sync
///   branch passes, in the same registers.
///
/// # Safety
///
/// `target` must be a live destination object whose `+0x10` owner and
/// that owner's `+0x0c` context block are readable — the original
/// dereferences the whole chain before any test, so this is the
/// original's precondition, not an added one. `message` is nullable.
/// Its vtable word must address a readable [`QueuedMessageVtable`]
/// whenever `message` is non-NULL and the post does not succeed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queued_message_post(
    message: *mut QueuedMessage,
    target: *mut MessageTarget,
    no_wait: u32,
    reply_queue: usize,
    flags: u32,
) -> u32 {
    // Read first and unguarded, exactly where the original reads it:
    // three loads before the first compare.
    let target_queue = (unsafe { (*(*(*target).owner).task_ctx).queue_pool }) as usize;

    let reply_queue = if reply_queue != 0 {
        reply_queue
    } else {
        let ctx = unsafe { crate::kernel::task::current_task_ctx_block() };
        if ctx.is_null() {
            0
        } else {
            (unsafe { (*ctx).queue_pool }) as usize
        }
    };

    let posted = if reply_queue == 0 || target_queue == 0 {
        0
    } else {
        let mut outgoing = PostedTaskMessage::BLANK;
        outgoing.tag = TASK_MESSAGE_TAG_MSGS;
        outgoing.target = target as usize as u32;
        outgoing.message = message as usize as u32;
        let words = core::ptr::addr_of!(outgoing).cast::<u32>();

        if no_wait != 0 {
            let post = unsafe {
                core::ptr::addr_of!(crate::kernel::task_message::TASK_MESSAGE_OPS.post_message)
                    .read_volatile()
            };
            unsafe { post(reply_queue, target_queue, words, 0, flags) }
        } else {
            unsafe {
                crate::kernel::task_message::task_message_post_sync(
                    reply_queue,
                    target_queue,
                    words,
                    flags,
                )
            }
        }
    };

    if posted == 0 && !message.is_null() {
        let vtable = (unsafe { (*message).vtable }) as usize as *const QueuedMessageVtable;
        unsafe { ((*vtable).release)(message) };
    }
    posted
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

#[cfg(test)]
mod post_tests {
    extern crate std;

    use super::*;
    use crate::kernel::task::TaskCtx;
    use crate::kernel::task_message::{TaskMessageOps, DEFAULT_TASK_MESSAGE_OPS, TASK_MESSAGE_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, MutexGuard};
    use std::vec::Vec;

    /// One recorded call into the message-post helper.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PostCall {
        reply_queue: usize,
        target_queue: usize,
        message: PostedTaskMessage,
        wait: u32,
        flags: u32,
    }

    static mut POSTS: Vec<PostCall> = Vec::new();
    static mut RELEASED: Vec<usize> = Vec::new();
    static mut POST_RESULT: u32 = 0;

    unsafe extern "C" fn recording_post(
        reply_queue: usize,
        target_queue: usize,
        message: *const u32,
        wait: u32,
        flags: u32,
    ) -> u32 {
        unsafe {
            (*ptr::addr_of_mut!(POSTS)).push(PostCall {
                reply_queue,
                target_queue,
                // The helper copies a fixed 28 bytes, so the test reads
                // all seven words — the deviation this port exists to
                // make well-defined.
                message: message.cast::<PostedTaskMessage>().read(),
                wait,
                flags,
            });
            ptr::read_volatile(ptr::addr_of!(POST_RESULT))
        }
    }

    unsafe extern "C" fn recording_release(message: *mut QueuedMessage) {
        unsafe { (*ptr::addr_of_mut!(RELEASED)).push(message as usize) };
    }

    /// Fixture layout inside the low slab (offsets are private to the
    /// test, and every field is reached through its `#[repr(C)]` name).
    const SLAB_LEN: usize = 0x1000;
    const OFF_VTABLE: usize = 0x000;
    const OFF_MESSAGE: usize = 0x040;
    const OFF_TARGET: usize = 0x080;
    const OFF_OWNER: usize = 0x0c0;
    const OFF_CTX: usize = 0x100;

    static SLAB: LazyLock<Option<usize>> =
        LazyLock::new(|| try_map_u32_slab(hints::QUEUED_MESSAGE_POST, SLAB_LEN).map(|p| p as usize));

    struct Fixture {
        message: *mut QueuedMessage,
        target: *mut MessageTarget,
        ctx: *mut TaskCtx,
    }

    /// Installs the recording helper and builds a live envelope/target
    /// chain in the low slab. Holds `task_message`'s ops lock, the one
    /// lock guarding [`TASK_MESSAGE_OPS`] crate-wide.
    fn bench(target_queue: usize) -> Option<(MutexGuard<'static, ()>, Fixture)> {
        let guard = crate::kernel::task_message::tests::OPS_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let slab = (*SLAB)? as *mut u8;
        unsafe {
            (*ptr::addr_of_mut!(POSTS)).clear();
            (*ptr::addr_of_mut!(RELEASED)).clear();
            ptr::addr_of_mut!(TASK_MESSAGE_OPS).write_volatile(TaskMessageOps {
                post_message: recording_post,
            });

            let vtable = slab.add(OFF_VTABLE).cast::<QueuedMessageVtable>();
            vtable.write(QueuedMessageVtable { slot_00: 0, release: recording_release });

            let message = slab.add(OFF_MESSAGE).cast::<QueuedMessage>();
            message.write(QueuedMessage {
                vtable: vtable as usize as u32,
                kind: QUEUED_MESSAGE_KIND,
                payload: ptr::null_mut(),
            });

            let ctx = slab.add(OFF_CTX).cast::<TaskCtx>();
            let mut block = TaskCtx::ZERO;
            block.queue_pool = target_queue as *mut u8;
            ctx.write(block);

            let owner = slab.add(OFF_OWNER).cast::<MessageTargetOwner>();
            owner.write(MessageTargetOwner { unused_00: [0; 3], task_ctx: ctx });

            let target = slab.add(OFF_TARGET).cast::<MessageTarget>();
            target.write(MessageTarget { unused_00: [0; 4], owner });

            Some((guard, Fixture { message, target, ctx }))
        }
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe { ptr::addr_of_mut!(TASK_MESSAGE_OPS).write_volatile(DEFAULT_TASK_MESSAGE_OPS) };
        drop(guard);
    }

    fn posts() -> Vec<PostCall> {
        unsafe { (*ptr::addr_of!(POSTS)).clone() }
    }

    fn released() -> Vec<usize> {
        unsafe { (*ptr::addr_of!(RELEASED)).clone() }
    }

    /// `no_wait != 0` is the flavor every inspected call site uses.
    const NO_WAIT: u32 = 1;

    #[test]
    fn a_successful_no_wait_post_carries_the_msgs_tag_and_keeps_the_envelope() {
        let Some((guard, fixture)) = bench(0x089c_1000) else {
            assert!(note_missing_u32_fixture("app::queued_message"));
            return;
        };
        unsafe {
            ptr::addr_of_mut!(POST_RESULT).write_volatile(1);
            let ret = queued_message_post(fixture.message, fixture.target, NO_WAIT, 0x089c_2000, 0x55);
            assert_eq!(ret, 1, "the helper's result is returned verbatim");
            assert_eq!(
                posts(),
                std::vec![PostCall {
                    reply_queue: 0x089c_2000,
                    target_queue: 0x089c_1000,
                    message: PostedTaskMessage {
                        tag: TASK_MESSAGE_TAG_MSGS,
                        unused_04: [0; 2],
                        target: fixture.target as usize as u32,
                        message: fixture.message as usize as u32,
                        unused_14: [0; 2],
                    },
                    wait: 0,
                    flags: 0x55,
                }],
                "'MsgS' at word 0, target at +0xc, envelope at +0x10, wait forced to 0"
            );
            assert!(released().is_empty(), "a successful post transfers ownership");
        }
        restore(guard);
    }

    #[test]
    fn a_waiting_post_goes_through_the_ported_sync_shim_with_wait_forced_to_one() {
        let Some((guard, fixture)) = bench(0x089c_1000) else {
            assert!(note_missing_u32_fixture("app::queued_message"));
            return;
        };
        unsafe {
            ptr::addr_of_mut!(POST_RESULT).write_volatile(7);
            let ret = queued_message_post(fixture.message, fixture.target, 0, 0x089c_2000, 0);
            assert_eq!(ret, 7);
            assert_eq!(posts().len(), 1);
            assert_eq!(posts()[0].wait, 1, "0x0812bf70 forces the wait flag to 1");
            assert!(released().is_empty());
        }
        restore(guard);
    }

    #[test]
    fn a_rejected_post_releases_the_envelope_and_returns_zero() {
        let Some((guard, fixture)) = bench(0x089c_1000) else {
            assert!(note_missing_u32_fixture("app::queued_message"));
            return;
        };
        unsafe {
            ptr::addr_of_mut!(POST_RESULT).write_volatile(0);
            let ret = queued_message_post(fixture.message, fixture.target, NO_WAIT, 0x089c_2000, 0);
            assert_eq!(ret, 0);
            assert_eq!(posts().len(), 1, "the post is still attempted");
            assert_eq!(
                released(),
                std::vec![fixture.message as usize],
                "vtable slot +0x04 is dispatched exactly once, on the envelope"
            );
        }
        restore(guard);
    }

    #[test]
    fn a_target_without_a_queue_releases_the_envelope_without_posting() {
        let Some((guard, fixture)) = bench(0) else {
            assert!(note_missing_u32_fixture("app::queued_message"));
            return;
        };
        unsafe {
            ptr::addr_of_mut!(POST_RESULT).write_volatile(1);
            let ret = queued_message_post(fixture.message, fixture.target, NO_WAIT, 0x089c_2000, 0);
            assert_eq!(ret, 0);
            assert!(posts().is_empty(), "no queue, no post");
            assert_eq!(released(), std::vec![fixture.message as usize]);
        }
        restore(guard);
    }

    #[test]
    fn a_null_envelope_on_the_failure_path_is_neither_released_nor_dereferenced() {
        let Some((guard, fixture)) = bench(0) else {
            assert!(note_missing_u32_fixture("app::queued_message"));
            return;
        };
        unsafe {
            let ret = queued_message_post(ptr::null_mut(), fixture.target, NO_WAIT, 0x089c_2000, 0);
            assert_eq!(ret, 0);
            assert!(posts().is_empty());
            assert!(released().is_empty(), "the `cmp r4,#0` guard covers exactly this");
        }
        restore(guard);
    }

    #[test]
    fn the_destination_queue_is_read_through_the_target_owner_context_chain() {
        let Some((guard, fixture)) = bench(0x089c_1000) else {
            assert!(note_missing_u32_fixture("app::queued_message"));
            return;
        };
        unsafe {
            // Re-point only the innermost link: the queue must follow.
            (*fixture.ctx).queue_pool = 0x089c_3000usize as *mut u8;
            ptr::addr_of_mut!(POST_RESULT).write_volatile(1);
            queued_message_post(fixture.message, fixture.target, NO_WAIT, 0x089c_2000, 0);
            assert_eq!(posts()[0].target_queue, 0x089c_3000);
        }
        restore(guard);
    }

    #[test]
    fn the_outgoing_message_is_the_full_twenty_eight_byte_cell_the_copy_moves() {
        assert_eq!(
            core::mem::size_of::<PostedTaskMessage>(),
            0x1c,
            "FUN_0827210c moves 7 words regardless of tag"
        );
        assert_eq!(TASK_MESSAGE_TAG_MSGS.to_be_bytes(), *b"MsgS");
    }
}
