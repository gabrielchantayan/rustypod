//! `three_word_message_post` — original: `FUN_0820d98c` @ **0x0820d98c**
//! (**76 bytes**, 0x0820d98c..0x0820d9d7: 72 bytes of code plus the derived
//! vtable literal at 0x0820d9d4). The next function opens with `push {r4,
//! r5, r6, r7, r8, lr}` at 0x0820d9d8. Ghidra's 72-byte extent drops the
//! trailing literal-pool word. A binary-wide decode of every ARM B/BL word finds
//! **8 unconditional `bl` call sites**, no predicated calls, and one
//! unconditional tail `b` entry (@ 0x820dbe0); no aligned data word contains
//! this address.
//!
//! # Algorithm
//!
//! Allocates 24 bytes through the message-kind arena, initializes the
//! message base with kind 0x27, installs this derived class's vtable, copies
//! three payload words, stores the low byte of the fourth argument at +0x14,
//! then tail-dispatches the result with a NULL explicit target.
//!
//! # Deviation
//!
//! The tail dispatcher `FUN_08110e4c` is not ported (and has no ledger entry),
//! so it is an explicit target-only seam. On device the seam reaches its retail
//! load address; host tests install a recorder. Ghidra wrongly merges that
//! dispatcher body into this function. Its shown local-object iteration is not
//! part of the 72-byte code body plus its literal-pool word.

use crate::app::message_kind::{message_kind_construct, MessageKind};
use crate::app::message_kind_arena::message_kind_arena_pool;
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

/// Derived-message vtable from the literal-pool word at 0x0820d9d4.
pub const THREE_WORD_MESSAGE_VTABLE: u32 = 0x0898_b85c;

/// The fixed tag passed as r1 to `message_kind_construct`.
pub const THREE_WORD_MESSAGE_KIND: u32 = 0x27;

/// The exact `mov r1, #24` allocation request at 0x0820d9a4.
pub const THREE_WORD_MESSAGE_SIZE: usize = 0x18;

/// A 24-byte message with a three-word payload and trailing byte flag.
#[repr(C)]
pub struct ThreeWordMessage {
    /// +0x00..+0x07: derived message-kind base.
    pub base: MessageKind,
    /// +0x08..+0x13: copied verbatim from r0, r1, and r2.
    pub payload: [u32; 3],
    /// +0x14: low byte of r3. The remaining bytes are untouched by `strb`.
    pub payload_flag: u8,
    /// +0x15..+0x17: target-layout padding untouched by this function.
    pub padding: [u8; 3],
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(ThreeWordMessage, base)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ThreeWordMessage, payload)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(ThreeWordMessage, payload_flag)];
const _: [u8; THREE_WORD_MESSAGE_SIZE] = [0; core::mem::size_of::<ThreeWordMessage>()];

/// ABI of `FUN_08110e4c`, the unported tail dispatcher. This caller always
/// supplies a NULL second argument, so its otherwise opaque target type stays
/// an untyped pointer.
pub type ThreeWordMessageDispatch = unsafe extern "C" fn(*mut ThreeWordMessage, *mut u8) -> u32;

/// RetailOS load address of the unported dispatcher.
pub const THREE_WORD_MESSAGE_DISPATCH_ADDRESS: usize = 0x0811_0e4c;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_three_word_message_dispatch(
    message: *mut ThreeWordMessage,
    target: *mut u8,
) -> u32 {
    let dispatch: ThreeWordMessageDispatch = unsafe {
        core::mem::transmute(THREE_WORD_MESSAGE_DISPATCH_ADDRESS)
    };
    unsafe { dispatch(message, target) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_three_word_message_dispatch(
    _message: *mut ThreeWordMessage,
    _target: *mut u8,
) -> u32 {
    panic!("three_word_message_post requires dispatcher 0x08110e4c")
}

/// Active boundary for unported `FUN_08110e4c`; target code calls retailOS and
/// host tests replace it with a recording implementation.
#[cfg(target_os = "none")]
pub static mut THREE_WORD_MESSAGE_DISPATCH: ThreeWordMessageDispatch = retail_three_word_message_dispatch;

/// Active host boundary for unported `FUN_08110e4c`.
#[cfg(not(target_os = "none"))]
pub static mut THREE_WORD_MESSAGE_DISPATCH: ThreeWordMessageDispatch = missing_three_word_message_dispatch;

#[inline(always)]
fn three_word_message_dispatch() -> ThreeWordMessageDispatch {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(THREE_WORD_MESSAGE_DISPATCH)) }
}

macro_rules! three_word_message_post_body {
    ($first:expr, $second:expr, $third:expr, $flag:expr; $pool:path, $alloc:path, $construct:path, $dispatch:expr) => {{
        let storage = unsafe { $alloc($pool(), THREE_WORD_MESSAGE_SIZE) }.cast::<ThreeWordMessage>();
        let message = unsafe { $construct(storage.cast(), THREE_WORD_MESSAGE_KIND) }.cast::<ThreeWordMessage>();

        unsafe {
            core::ptr::addr_of_mut!((*message).base.base.vtable).write_volatile(THREE_WORD_MESSAGE_VTABLE);
            core::ptr::addr_of_mut!((*message).payload[0]).write_volatile($first);
            core::ptr::addr_of_mut!((*message).payload[1]).write_volatile($second);
            core::ptr::addr_of_mut!((*message).payload[2]).write_volatile($third);
            core::ptr::addr_of_mut!((*message).payload_flag).write_volatile($flag as u8);
            ($dispatch)(message, core::ptr::null_mut())
        }
    }};
}

/// three_word_message_post — original: `FUN_0820d98c` @ **0x0820d98c**
/// (**76 bytes; 8 unconditional `bl` call sites and one tail `b`** — see the
/// module header).
///
/// Allocates and initializes a kind-0x27, three-word message, then returns the
/// status from the tail dispatcher with its explicit target set to NULL. There
/// are no data-dependent branches or NULL guards: failed allocation is passed
/// directly to the base constructor, exactly as the retail body does.
///
/// # Safety
///
/// The message-kind arena and the retail dispatcher must be initialized. The
/// allocation result must name writable 24-byte, word-aligned storage; the
/// original makes the same unchecked assumption.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.three_word_message_post"))]
pub unsafe extern "C" fn three_word_message_post(
    first_payload_word: u32,
    second_payload_word: u32,
    third_payload_word: u32,
    payload_flag: u32,
) -> u32 {
    three_word_message_post_body!(
        first_payload_word,
        second_payload_word,
        third_payload_word,
        payload_flag;
        message_kind_arena_pool,
        fixed_block_pool_alloc,
        message_kind_construct,
        three_word_message_dispatch()
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::fixed_block_pool::FixedBlockPool;
    use parking_lot::MutexGuard;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: [u32; 4] = [0; 4];
    static mut ALLOC_POOL: *mut FixedBlockPool = core::ptr::null_mut();
    static mut ALLOC_SIZE: usize = 0;
    static mut CONSTRUCT_STORAGE: *mut ThreeWordMessage = core::ptr::null_mut();
    static mut CONSTRUCT_KIND: u32 = 0;
    static mut DISPATCH_MESSAGE: *mut ThreeWordMessage = core::ptr::null_mut();
    static mut DISPATCH_TARGET: *mut u8 = core::ptr::null_mut();
    static mut DISPATCH_RESULT: u32 = 0;
    static mut STORAGE: [u32; 8] = [0; 8];

    unsafe extern "C" fn recording_pool() -> *mut FixedBlockPool {
        CALLS[0] += 1;
        0x1000usize as *mut FixedBlockPool
    }

    unsafe extern "C" fn recording_alloc(pool: *mut FixedBlockPool, size: usize) -> *mut u8 {
        CALLS[1] += 1;
        ALLOC_POOL = pool;
        ALLOC_SIZE = size;
        core::ptr::addr_of_mut!(STORAGE).cast()
    }

    unsafe extern "C" fn recording_construct(
        storage: *mut MessageKind,
        kind: u32,
    ) -> *mut MessageKind {
        CALLS[2] += 1;
        CONSTRUCT_STORAGE = storage.cast();
        CONSTRUCT_KIND = kind;
        core::ptr::addr_of_mut!((*storage).base.vtable).write_volatile(0x1111_2222);
        core::ptr::addr_of_mut!((*storage).kind).write_volatile(kind);
        storage
    }

    unsafe extern "C" fn recording_dispatch(
        message: *mut ThreeWordMessage,
        target: *mut u8,
    ) -> u32 {
        CALLS[3] += 1;
        DISPATCH_MESSAGE = message;
        DISPATCH_TARGET = target;
        DISPATCH_RESULT
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock();
        unsafe {
            CALLS = [0; 4];
            ALLOC_POOL = core::ptr::null_mut();
            ALLOC_SIZE = 0;
            CONSTRUCT_STORAGE = core::ptr::null_mut();
            CONSTRUCT_KIND = 0;
            DISPATCH_MESSAGE = core::ptr::null_mut();
            DISPATCH_TARGET = core::ptr::null_mut();
            DISPATCH_RESULT = 0;
            STORAGE = [0xa5a5_a5a5; 8];
        }
        guard
    }

    fn invoke(first: u32, second: u32, third: u32, flag: u32) -> u32 {
        three_word_message_post_body!(
            first,
            second,
            third,
            flag;
            recording_pool,
            recording_alloc,
            recording_construct,
            recording_dispatch
        )
    }

    #[test]
    fn allocates_constructs_and_dispatches_the_complete_message() {
        let guard = reset();
        unsafe {
            DISPATCH_RESULT = 0x8765_4321;
            assert_eq!(invoke(0x1020_3040, 0x5060_7080, 0x90a0_b0c0, 0xd4), DISPATCH_RESULT);
            assert_eq!(CALLS, [1, 1, 1, 1]);
            assert_eq!(ALLOC_POOL, 0x1000usize as *mut FixedBlockPool);
            assert_eq!(ALLOC_SIZE, THREE_WORD_MESSAGE_SIZE);
            assert_eq!(CONSTRUCT_STORAGE, core::ptr::addr_of_mut!(STORAGE).cast());
            assert_eq!(CONSTRUCT_KIND, THREE_WORD_MESSAGE_KIND);
            assert_eq!(DISPATCH_MESSAGE, core::ptr::addr_of_mut!(STORAGE).cast());
            assert!(DISPATCH_TARGET.is_null(), "the tail dispatcher gets r1 = 0");
            assert_eq!(
                STORAGE,
                [
                    THREE_WORD_MESSAGE_VTABLE,
                    THREE_WORD_MESSAGE_KIND,
                    0x1020_3040,
                    0x5060_7080,
                    0x90a0_b0c0,
                    0xa5a5_a5d4,
                    0xa5a5_a5a5,
                    0xa5a5_a5a5,
                ],
                "the final strb changes only the low byte at +0x14"
            );
        }
        drop(guard);
    }

    #[test]
    fn forwards_zero_and_high_bit_payloads_without_gating() {
        let guard = reset();
        unsafe {
            DISPATCH_RESULT = 0;
            assert_eq!(invoke(0, u32::MAX, 0x8000_0000, 0xffff_fff0), 0);
            assert_eq!(CALLS, [1, 1, 1, 1], "all stages run regardless of payload values");
            assert_eq!(STORAGE[2..6], [0, u32::MAX, 0x8000_0000, 0xa5a5_a5f0]);
        }
        drop(guard);
    }
}
