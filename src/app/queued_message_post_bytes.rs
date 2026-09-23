//! `queued_message_post_bytes` — original: `FUN_081fb41c` @ **0x081fb41c**.
//! The true extent is **136 bytes**, 0x081fb41c..0x081fb4a3: 34 instruction
//! words, with the next function opening at 0x081fb4a4 (`push {r3, r4, r5,
//! r6, r7, r8, r9, lr}`). Raw A32 decoding finds **3 plain `bl` call sites**
//! (`message_arena_pool`, `fixed_block_pool_alloc`, and
//! `queued_message_construct`), **no predicated `bl` forms**, plus the
//! indirect `blx` release call after a failed post.
//!
//! # Algorithm
//!
//! Allocates a 12-byte queued-message envelope from the shared message arena,
//! constructs its owned byte payload, and posts it to `target` without waiting.
//! A nonzero post result becomes one. On allocation failure or post failure it
//! returns zero; the latter also invokes the envelope's vtable +0x04 release
//! slot, exactly as the retail instructions do.
//!
//! # Deliberate deviations
//!
//! The release slot is an ARM wire address, so host builds keep the dynamic
//! dispatch behind the testable helper and panic if the exported entry reaches
//! it. The target path performs the real vtable call. The existing
//! `queued_message_post` port also releases on its failure path; this wrapper
//! deliberately preserves its own retail release call rather than suppressing
//! it.

use crate::app::message_arena::message_arena_pool;
use crate::app::queued_message::{queued_message_construct, queued_message_post, MessageTarget, QueuedMessage};
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

type Release = unsafe extern "C" fn(*mut QueuedMessage);

#[cfg(target_os = "none")]
unsafe fn release_queued_message(message: *mut QueuedMessage) {
    let vtable = unsafe { core::ptr::addr_of!((*message).vtable).read_volatile() };
    let release: Release = unsafe { core::mem::transmute((vtable + 4) as usize) };
    unsafe { release(message) };
}

#[cfg(not(target_os = "none"))]
unsafe fn release_queued_message(_: *mut QueuedMessage) {
    panic!("queued_message_post_bytes release requires an ARM vtable")
}

unsafe fn post_bytes<Pool, Alloc, Construct, Post, ReleaseMessage>(
    target: *mut MessageTarget, message_code: u32, bytes: *const u8, byte_count: u32,
    pool: Pool, alloc: Alloc, construct: Construct, post: Post, release: ReleaseMessage,
) -> u32
where
    Pool: FnOnce() -> *mut crate::heap::fixed_block_pool::FixedBlockPool,
    Alloc: FnOnce(*mut crate::heap::fixed_block_pool::FixedBlockPool, usize) -> *mut u8,
    Construct: FnOnce(*mut QueuedMessage, u32, *const u8, u32) -> *mut QueuedMessage,
    Post: FnOnce(*mut QueuedMessage, *mut MessageTarget, u32, usize, u32) -> u32,
    ReleaseMessage: FnOnce(*mut QueuedMessage),
{
    let storage = alloc(pool(), core::mem::size_of::<u32>() * 3).cast::<QueuedMessage>();
    if storage.is_null() {
        return 0;
    }
    let message = construct(storage, message_code, bytes, byte_count);
    if post(message, target, 1, 0, 0) != 0 {
        1
    } else {
        release(message);
        0
    }
}

/// `queued_message_post_bytes` — original: `FUN_081fb41c` @ **0x081fb41c**
/// (136 bytes; 3 plain `bl` call sites and no predicated forms — see module
/// header).
///
/// Constructs and fire-and-forget posts an owned byte-payload queued message.
/// Returns one only when the post succeeds; otherwise returns zero after the
/// retail failure cleanup.
///
/// # Safety
///
/// `target` must satisfy [`queued_message_post`]'s unguarded target-chain
/// precondition. `bytes` and `byte_count` must satisfy
/// [`queued_message_construct`]'s payload-constructor precondition.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queued_message_post_bytes(
    target: *mut MessageTarget, message_code: u32, bytes: *const u8, byte_count: u32,
) -> u32 {
    unsafe {
        post_bytes(target, message_code, bytes, byte_count,
            || message_arena_pool(),
            |pool, size| fixed_block_pool_alloc(pool, size),
            |storage, code, source, len| queued_message_construct(storage, code, source, len),
            |message, destination, no_wait, reply_queue, flags| queued_message_post(message, destination, no_wait, reply_queue, flags),
            |message| release_queued_message(message),
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn posts_constructed_payload_and_collapses_success_to_one() {
        let mut storage = [0u32; 3];
        let bytes = [0x12u8, 0x34, 0x56];
        let mut observed_construct = (core::ptr::null_mut(), 0, core::ptr::null(), 0);
        let mut observed_post = (core::ptr::null_mut(), core::ptr::null_mut(), 0, 1usize, 1);
        let result = unsafe {
            post_bytes(core::ptr::null_mut(), 0x6380_002a, bytes.as_ptr(), bytes.len() as u32,
                || core::ptr::null_mut(),
                |_, size| { assert_eq!(size, 12); storage.as_mut_ptr().cast() },
                |message, code, source, len| { observed_construct = (message, code, source, len); message },
                |message, target, no_wait, reply_queue, flags| { observed_post = (message, target, no_wait, reply_queue, flags); 7 },
                |_| panic!("successful post must retain message"),
            )
        };
        assert_eq!(result, 1);
        assert_eq!(observed_construct, (storage.as_mut_ptr().cast(), 0x6380_002a, bytes.as_ptr(), 3));
        assert_eq!(observed_post, (storage.as_mut_ptr().cast(), core::ptr::null_mut(), 1, 0, 0));
    }

    #[test]
    fn allocation_failure_skips_construct_post_and_release() {
        let result = unsafe {
            post_bytes(core::ptr::null_mut(), 0, core::ptr::null(), 0,
                || core::ptr::null_mut(),
                |_, _| core::ptr::null_mut(),
                |_, _, _, _| panic!("NULL allocation must not construct"),
                |_, _, _, _, _| panic!("NULL allocation must not post"),
                |_| panic!("NULL allocation must not release"),
            )
        };
        assert_eq!(result, 0);
    }

    #[test]
    fn failed_post_releases_constructed_message() {
        let mut storage = [0u32; 3];
        let mut released = core::ptr::null_mut();
        let result = unsafe {
            post_bytes(core::ptr::null_mut(), 0, core::ptr::null(), 0,
                || core::ptr::null_mut(),
                |_, _| storage.as_mut_ptr().cast(),
                |message, _, _, _| message,
                |_, _, _, _, _| 0,
                |message| released = message,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(released, storage.as_mut_ptr().cast());
    }
}
