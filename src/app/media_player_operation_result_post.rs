//! `media_player_operation_result_post` — original: `FUN_081fb4a4` @
//! **0x081fb4a4**. The true extent is **124 bytes**, 0x081fb4a4..0x081fb51f:
//! 120 bytes of code followed by the derived-vtable literal at 0x081fb520.
//! The next function begins at 0x081fb524. Raw A32 decoding finds **3 plain
//! `bl` call sites and no predicated `bl` call sites**.
//!
//! # Algorithm
//!
//! Allocates a 24-byte kind-0x18 message, installs its derived vtable, copies
//! four caller words to +0x08..+0x14, and posts it with `no_wait = 1`. If the
//! post reports failure, it invokes the message's vtable +0x04 destructor.
//!
//! # Deliberate deviations
//!
//! The owner argument in r0 is unused by the retail instructions and is named
//! `_owner` here. The dynamic destructor call remains a real vtable dispatch
//! on device; host tests inject that boundary because the wire vtable contains
//! 32-bit ARM function addresses.

use crate::app::message_kind::{message_kind_construct, MessageKind};
use crate::app::message_kind_arena::message_kind_arena_pool;
use crate::app::queued_message::{queued_message_post, MessageTarget};
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

/// Literal-pool word at 0x081fb520.
pub const MEDIA_PLAYER_OPERATION_RESULT_VTABLE: u32 = 0x0898_9968;
pub const MEDIA_PLAYER_OPERATION_RESULT_KIND: u32 = 0x18;
pub const MEDIA_PLAYER_OPERATION_RESULT_SIZE: usize = 0x18;

#[repr(C)]
pub struct MediaPlayerOperationResult {
    pub base: MessageKind,
    pub event_code: u32,
    pub status: u32,
    pub result_handle: u32,
    pub value: u32,
}

const _: [u8; 0x08] = [0; core::mem::offset_of!(MediaPlayerOperationResult, event_code)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(MediaPlayerOperationResult, value)];
const _: [u8; MEDIA_PLAYER_OPERATION_RESULT_SIZE] = [0; core::mem::size_of::<MediaPlayerOperationResult>()];

type Release = unsafe extern "C" fn(*mut MessageKind);

#[cfg(target_os = "none")]
unsafe fn release_derived_message(message: *mut MediaPlayerOperationResult) {
    let vtable = unsafe { core::ptr::addr_of!((*message).base.base.vtable).read_volatile() };
    let release: Release = unsafe { core::mem::transmute((vtable + 4) as usize) };
    unsafe { release(message.cast()) };
}

#[cfg(not(target_os = "none"))]
unsafe fn release_derived_message(_: *mut MediaPlayerOperationResult) {
    panic!("derived message release requires an ARM vtable")
}

unsafe fn post_operation_result<Pool, Alloc, Construct, Post, Drop>(
    target: *mut MessageTarget, event_code: u32, value: u32, status: u32, result_handle: u32,
    pool: Pool, alloc: Alloc, construct: Construct, post: Post, drop_message: Drop,
) where
    Pool: FnOnce() -> *mut crate::heap::fixed_block_pool::FixedBlockPool,
    Alloc: FnOnce(*mut crate::heap::fixed_block_pool::FixedBlockPool, usize) -> *mut u8,
    Construct: FnOnce(*mut MessageKind, u32) -> *mut MessageKind,
    Post: FnOnce(*mut MessageKind, *mut MessageTarget, u32, usize, u32) -> u32,
    Drop: FnOnce(*mut MediaPlayerOperationResult),
{
    let storage = alloc(pool(), MEDIA_PLAYER_OPERATION_RESULT_SIZE).cast::<MediaPlayerOperationResult>();
    let message = construct(storage.cast(), MEDIA_PLAYER_OPERATION_RESULT_KIND).cast::<MediaPlayerOperationResult>();
    unsafe {
        core::ptr::addr_of_mut!((*message).base.base.vtable).write_volatile(MEDIA_PLAYER_OPERATION_RESULT_VTABLE);
        core::ptr::addr_of_mut!((*message).event_code).write_volatile(event_code);
        core::ptr::addr_of_mut!((*message).status).write_volatile(status);
        core::ptr::addr_of_mut!((*message).result_handle).write_volatile(result_handle);
        core::ptr::addr_of_mut!((*message).value).write_volatile(value);
    }
    if post(message.cast(), target, 1, 0, 0) == 0 {
        drop_message(message);
    }
}

/// Posts a media-player operation result. The six arguments preserve the retail
/// AAPCS signature; `_owner` is deliberately unused by the original.
///
/// # Safety
/// The message arena, target, and derived vtable must be valid retailOS state.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_operation_result_post(
    _owner: *mut u8, target: *mut MessageTarget, event_code: u32, value: u32, status: u32, result_handle: u32,
) {
    unsafe {
        post_operation_result(target, event_code, value, status, result_handle,
            || message_kind_arena_pool(),
            |pool, size| fixed_block_pool_alloc(pool, size),
            |storage, kind| message_kind_construct(storage, kind),
            |message, target, no_wait, reply_queue, flags| queued_message_post(message.cast(), target, no_wait, reply_queue, flags),
            |message| release_derived_message(message),
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn initializes_wire_layout_and_posts_without_waiting() {
        let mut storage = [0u32; 6];
        let mut observed_post = (core::ptr::null_mut(), 0, 0usize, 0);
        unsafe {
            post_operation_result(core::ptr::null_mut(), 0x10, 0x20, 0x30, 0x40,
                || core::ptr::null_mut(),
                |_, size| { assert_eq!(size, 24); storage.as_mut_ptr().cast() },
                |message, kind| { assert_eq!(kind, 0x18); message },
                |message, _, no_wait, reply_queue, flags| { observed_post = (message, no_wait, reply_queue, flags); 1 },
                |_| panic!("successful post must retain message"),
            );
        }
        assert_eq!(storage, [MEDIA_PLAYER_OPERATION_RESULT_VTABLE, 0, 0x10, 0x30, 0x40, 0x20]);
        assert_eq!(observed_post.0, storage.as_mut_ptr().cast());
        assert_eq!((observed_post.1, observed_post.2, observed_post.3), (1, 0, 0));
    }

    #[test]
    fn releases_exact_message_only_when_post_fails() {
        let mut storage = [0u32; 6];
        let mut released = core::ptr::null_mut();
        unsafe {
            post_operation_result(core::ptr::null_mut(), 0, 0, 0, 0,
                || core::ptr::null_mut(),
                |_, _| storage.as_mut_ptr().cast(),
                |message, _| message,
                |_, _, _, _, _| 0,
                |message| released = message,
            );
        }
        assert_eq!(released, storage.as_mut_ptr().cast());
    }
}
