//! `kind_0x21_message_post` — original: `FUN_0827fdd0` @ **0x0827fdd0**
//! (**76 bytes**, 0x0827fdd0..0x0827fe1b). The next independently callable
//! entry begins at 0x0827fe1c with `push {r4, r5, r6, r7, r8, r9, sl, lr}`.
//! Raw A32 decoding finds **4 unconditional plain `bl` call sites** and zero
//! predicated `bl` call sites.
//!
//! # Algorithm
//!
//! Allocates 32 bytes from the message-kind arena, then enters the derived
//! kind-0x21 constructor at 0x0827fe1c. That constructor writes its vtable,
//! copies the five supplied payload values, invokes either vtable slot +0x30
//! or +0x34 on the supplied target according to the first payload word, and
//! stores that result at +0x0c. This entry tail-dispatches the completed
//! message through `FUN_08110e4c` with its explicit target (the sixth
//! argument).
//!
//! # Deliberate deviations
//!
//! `FUN_08110e4c` remains unported. This module deliberately reuses the
//! existing target-only `message_dispatch` seam from `three_word_message_post`.
//! The target callback is likewise a test seam on the host; target code reads
//! the verified four-byte vtable slot directly.

use crate::app::message_kind::{message_kind_construct, MessageKind};
use crate::app::message_kind_arena::message_kind_arena_pool;
use crate::app::three_word_message_post::message_dispatch;
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

pub const KIND_0X21_MESSAGE_SIZE: usize = 0x20;
pub const KIND_0X21_MESSAGE_VTABLE: u32 = 0x089a_641c;
pub const KIND_0X21: u32 = 0x21;
pub const SPECIAL_FIRST_PAYLOAD: u32 = 0x4d6e_7553;

#[repr(C)]
pub struct Kind0x21Message {
    pub base: MessageKind,
    pub first_payload: u32,
    pub target_result: u32,
    pub second_payload: u32,
    pub target: u32,
    pub third_payload: u8,
    pub fifth_payload: u8,
    pub padding: [u8; 6],
}

const _: [u8; 0x08] = [0; core::mem::offset_of!(Kind0x21Message, first_payload)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Kind0x21Message, target_result)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(Kind0x21Message, second_payload)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(Kind0x21Message, target)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(Kind0x21Message, third_payload)];
const _: [u8; KIND_0X21_MESSAGE_SIZE] = [0; core::mem::size_of::<Kind0x21Message>()];

#[cfg(target_os = "none")]
unsafe fn target_callback(target: *mut u8, first_payload: u32) -> u32 {
    let slot = if first_payload == SPECIAL_FIRST_PAYLOAD { 12 } else { 13 };
    let vtable = unsafe { core::ptr::read(target.cast::<u32>()) } as *const u32;
    let callback: unsafe extern "C" fn(*mut u8) -> u32 = unsafe { core::mem::transmute(core::ptr::read(vtable.add(slot))) };
    unsafe { callback(target) }
}

#[cfg(not(target_os = "none"))]
unsafe fn target_callback(_target: *mut u8, _first_payload: u32) -> u32 {
    panic!("kind_0x21_message_post requires target callback")
}

macro_rules! kind_0x21_message_post_body {
    ($first:expr, $second:expr, $third:expr, $target:expr, $fifth:expr, $dispatch_target:expr; $pool:path, $alloc:path, $construct:path, $callback:expr, $dispatch:expr) => {{
        let storage = unsafe { $alloc($pool(), KIND_0X21_MESSAGE_SIZE) }.cast::<Kind0x21Message>();
        let message = unsafe { $construct(storage.cast(), KIND_0X21) }.cast::<Kind0x21Message>();
        unsafe {
            core::ptr::addr_of_mut!((*message).base.base.vtable).write_volatile(KIND_0X21_MESSAGE_VTABLE);
            core::ptr::addr_of_mut!((*message).first_payload).write_volatile($first);
            core::ptr::addr_of_mut!((*message).target_result).write_volatile(($callback)($target, $first));
            core::ptr::addr_of_mut!((*message).second_payload).write_volatile($second);
            core::ptr::addr_of_mut!((*message).target).write_volatile($target as u32);
            core::ptr::addr_of_mut!((*message).third_payload).write_volatile($third as u8);
            core::ptr::addr_of_mut!((*message).fifth_payload).write_volatile($fifth as u8);
            ($dispatch)(message.cast(), $dispatch_target)
        }
    }};
}

/// Constructs the 32-byte kind-0x21 message and posts it to `dispatch_target`.
///
/// # Safety
/// The arena, target object, and dispatcher must be initialized; `target`
/// must have the callback selected by `first_payload`, as in retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kind_0x21_message_post(
    first_payload: u32,
    second_payload: u32,
    third_payload: u32,
    target: *mut u8,
    fifth_payload: u32,
    dispatch_target: *mut u8,
) -> u32 {
    kind_0x21_message_post_body!(
        first_payload, second_payload, third_payload, target, fifth_payload, dispatch_target;
        message_kind_arena_pool, fixed_block_pool_alloc, message_kind_construct, target_callback, message_dispatch()
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::fixed_block_pool::FixedBlockPool;

    static mut STORAGE: [u32; 8] = [0; 8];
    static mut CALLBACK_SLOT: u32 = 0;
    static mut DISPATCH_TARGET: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn pool() -> *mut FixedBlockPool { 0x1000usize as *mut FixedBlockPool }
    unsafe extern "C" fn alloc(_: *mut FixedBlockPool, _: usize) -> *mut u8 { core::ptr::addr_of_mut!(STORAGE).cast() }
    unsafe extern "C" fn construct(storage: *mut MessageKind, kind: u32) -> *mut MessageKind { (*storage).kind = kind; storage }
    unsafe fn callback(_: *mut u8, first: u32) -> u32 { CALLBACK_SLOT = if first == SPECIAL_FIRST_PAYLOAD { 12 } else { 13 }; 0xfeed_beef }
    unsafe extern "C" fn dispatch(message: *mut MessageKind, target: *mut u8) -> u32 { DISPATCH_TARGET = target; (*message).kind }

    #[test]
    fn constructs_layout_selects_callback_and_forwards_target() {
        unsafe {
            STORAGE = [0xa5a5_a5a5; 8];
            let target = 0x4321usize as *mut u8;
            let dispatch_target = 0x8765usize as *mut u8;
            assert_eq!(kind_0x21_message_post_body!(1, 2, 0x123u32, target, 0x456u32, dispatch_target; pool, alloc, construct, callback, dispatch), KIND_0X21);
            let message = core::ptr::addr_of!(STORAGE).cast::<Kind0x21Message>();
            assert_eq!((*message).base.base.vtable, KIND_0X21_MESSAGE_VTABLE);
            assert_eq!((*message).base.kind, KIND_0X21);
            assert_eq!((*message).first_payload, 1);
            assert_eq!((*message).target_result, 0xfeed_beef);
            assert_eq!((*message).second_payload, 2);
            assert_eq!((*message).target, target as u32);
            assert_eq!((*message).third_payload, 0x23);
            assert_eq!((*message).fifth_payload, 0x56);
            assert_eq!(CALLBACK_SLOT, 13);
            assert_eq!(DISPATCH_TARGET, dispatch_target);
        }
    }

    #[test]
    fn special_first_payload_uses_slot_30() {
        unsafe {
            kind_0x21_message_post_body!(SPECIAL_FIRST_PAYLOAD, 0, 0, core::ptr::null_mut::<u8>(), 0, core::ptr::null_mut::<u8>(); pool, alloc, construct, callback, dispatch);
            assert_eq!(CALLBACK_SLOT, 12);
        }
    }
}
