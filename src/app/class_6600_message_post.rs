//! `class_6600_message_post` — original: `FUN_080ef9c0` @ **0x080ef9c0**.
//! The true extent is **84 bytes**, `0x080ef9c0..0x080efa13`; raw A32
//! decoding shows the next function starts at `0x080efa14` with `mov r0, #1`.
//! There are **3 direct call sites**: one plain `bl` and two predicated
//! `bleq`; the body contains five plain `bl` instructions and no predicated
//! calls.
//!
//! # Algorithm
//!
//! For message codes in `0x6600_0000..=0x6600_0007`, obtains the class-0x6600
//! singleton, allocates a 12-byte queued-message envelope, constructs an empty
//! payload with that code, and posts it fire-and-forget. Other codes are a
//! no-op.
//!
//! # Deliberate deviations
//!
//! None. The retail function does not check allocation failure before passing
//! the result to the constructor, so this port deliberately does not either.

use crate::app::message_arena::message_arena_pool;
use crate::app::queued_message::{queued_message_construct, queued_message_post, MessageTarget, QueuedMessage};
use crate::app::registry::instance_of_class_6600;
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

const CLASS_6600_MESSAGE_CODE_BASE: u32 = 0x6600_0000;
const CLASS_6600_MESSAGE_CODE_COUNT: u32 = 8;
const QUEUED_MESSAGE_STORAGE_SIZE: usize = 12;

macro_rules! class_6600_message_post_body {
    ($message_code:expr; $instance:path, $pool:path, $alloc:path, $construct:path, $post:path) => {{
        if $message_code.wrapping_sub(CLASS_6600_MESSAGE_CODE_BASE) < CLASS_6600_MESSAGE_CODE_COUNT {
            let target = unsafe { $instance() }.cast::<MessageTarget>();
            let storage = unsafe { $alloc($pool(), QUEUED_MESSAGE_STORAGE_SIZE) };
            let message = unsafe {
                $construct(
                    storage.cast::<QueuedMessage>(),
                    $message_code,
                    core::ptr::null(),
                    0,
                )
            };
            unsafe { $post(message, target, 1, 0, 0) };
        }
    }};
}

/// Posts an empty queued message to the class-0x6600 singleton.
///
/// # Safety
///
/// The class singleton, message arena, and queued-message target chain must be
/// initialized retailOS state. These are the stock function's unguarded
/// requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_6600_message_post(message_code: u32) {
    class_6600_message_post_body!(
        message_code;
        instance_of_class_6600,
        message_arena_pool,
        fixed_block_pool_alloc,
        queued_message_construct,
        queued_message_post
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::fixed_block_pool::FixedBlockPool;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 5] = [0; 5];
    static mut ALLOC_ARGS: (*mut FixedBlockPool, usize) = (core::ptr::null_mut(), 0);
    static mut CONSTRUCT_ARGS: (*mut QueuedMessage, u32, *const u8, u32) =
        (core::ptr::null_mut(), 0, core::ptr::null(), 0);
    static mut POST_ARGS: (*mut QueuedMessage, *mut MessageTarget, u32, usize, u32) =
        (core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);

    unsafe extern "C" fn recording_instance() -> *mut u8 {
        CALLS[0] += 1;
        0x1000usize as *mut u8
    }

    unsafe extern "C" fn recording_pool() -> *mut FixedBlockPool {
        CALLS[1] += 1;
        0x2000usize as *mut FixedBlockPool
    }

    unsafe extern "C" fn recording_alloc(pool: *mut FixedBlockPool, size: usize) -> *mut u8 {
        CALLS[2] += 1;
        ALLOC_ARGS = (pool, size);
        0x3000usize as *mut u8
    }

    unsafe extern "C" fn recording_construct(
        storage: *mut QueuedMessage, message_code: u32, bytes: *const u8, byte_count: u32,
    ) -> *mut QueuedMessage {
        CALLS[3] += 1;
        CONSTRUCT_ARGS = (storage, message_code, bytes, byte_count);
        0x4000usize as *mut QueuedMessage
    }

    unsafe extern "C" fn recording_post(
        message: *mut QueuedMessage, target: *mut MessageTarget, no_wait: u32, reply_queue: usize, flags: u32,
    ) -> u32 {
        CALLS[4] += 1;
        POST_ARGS = (message, target, no_wait, reply_queue, flags);
        0
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CALLS = [0; 5];
            ALLOC_ARGS = (core::ptr::null_mut(), 0);
            CONSTRUCT_ARGS = (core::ptr::null_mut(), 0, core::ptr::null(), 0);
            POST_ARGS = (core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
        }
        guard
    }

    fn invoke(message_code: u32) {
        class_6600_message_post_body!(
            message_code;
            recording_instance,
            recording_pool,
            recording_alloc,
            recording_construct,
            recording_post
        );
    }

    #[test]
    fn posts_each_code_in_the_class_6600_range() {
        let guard = reset();
        for message_code in CLASS_6600_MESSAGE_CODE_BASE..(CLASS_6600_MESSAGE_CODE_BASE + CLASS_6600_MESSAGE_CODE_COUNT) {
            invoke(message_code);
        }
        unsafe {
            assert_eq!(CALLS, [8, 8, 8, 8, 8]);
            assert_eq!(ALLOC_ARGS, (0x2000usize as *mut FixedBlockPool, QUEUED_MESSAGE_STORAGE_SIZE));
            assert_eq!(CONSTRUCT_ARGS, (0x3000usize as *mut QueuedMessage, 0x6600_0007, core::ptr::null(), 0));
            assert_eq!(POST_ARGS, (0x4000usize as *mut QueuedMessage, 0x1000usize as *mut MessageTarget, 1, 0, 0));
        }
        drop(guard);
    }

    #[test]
    fn ignores_codes_outside_the_eight_code_range() {
        let guard = reset();
        invoke(CLASS_6600_MESSAGE_CODE_BASE - 1);
        invoke(CLASS_6600_MESSAGE_CODE_BASE + CLASS_6600_MESSAGE_CODE_COUNT);
        invoke(u32::MAX);
        unsafe {
            assert_eq!(CALLS, [0; 5]);
        }
        drop(guard);
    }
}
