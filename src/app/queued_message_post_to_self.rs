//! Synchronous queued-message posting with the destination's own reply queue.

use crate::app::message_arena::message_arena_pool;
use crate::app::queued_message::{queued_message_construct, queued_message_post, MessageTarget, QueuedMessage};
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

unsafe fn post_to_self<Create, Post>(target: *mut MessageTarget, create: Create, post: Post)
where
    Create: FnOnce() -> *mut QueuedMessage,
    Post: FnOnce(*mut QueuedMessage, *mut MessageTarget, u32, usize, u32) -> u32,
{
    // Snapshot before any allocator/constructor can change the task context.
    let reply_queue = unsafe { (*(*(*target).owner).task_ctx).queue_pool } as usize;
    let message = create();
    let _ = post(message, target, 0, reply_queue, 0);
}

/// Original `FUN_081a78ac` @ **0x081a78ac**, **88 bytes**, ending at
/// the next real function's push @ 0x081a7904. Raw A32 decoding verifies
/// **2 inbound plain BLs, 0 predicated BLs, 1 inbound tail B**; the body
/// itself contains **4 plain BLs and 0 predicated BLs**.
///
/// Read target->owner (+0x10)->task_ctx (+0x0c)->queue_pool (+0x1c),
/// allocate a 12-byte arena envelope, construct its owned byte payload,
/// then post synchronously (no_wait=0, flags=0), using the saved queue as
/// reply_queue. Discard the post result; do not guard allocation failure.
/// A zero saved queue is passed unchanged to the poster's existing fallback.
///
/// Deliberate deviations: typed repr(C) links preserve ARM field offsets
/// while allowing native host pointers; Rust closures inline into direct
/// calls to existing ports. No additional validation or failure cleanup.
/// Ghidra's apparent fifth constructor argument is stale stack data, not
/// part of the verified four-register constructor ABI.
///
/// # Safety
/// The complete target chain must be valid. Arena storage and the payload
/// must satisfy `queued_message_construct` and `queued_message_post`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queued_message_post_to_self(
    target: *mut MessageTarget, message_code: u32, bytes: *const u8, byte_count: u32,
) {
    unsafe {
        post_to_self(target,
            || {
                let storage = fixed_block_pool_alloc(message_arena_pool(), 12).cast();
                queued_message_construct(storage, message_code, bytes, byte_count)
            },
            |message, destination, no_wait, reply_queue, flags| {
                queued_message_post(message, destination, no_wait, reply_queue, flags)
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::queued_message::MessageTargetOwner;
    use crate::kernel::task::TaskCtx;

    #[test]
    fn reply_queue_is_captured_before_construction_changes_destination() {
        unsafe {
            let mut context: TaskCtx = core::mem::zeroed();
            context.queue_pool = 0x1234usize as *mut u8;
            let mut owner = MessageTargetOwner { unused_00: [0; 3], task_ctx: &mut context };
            let mut target = MessageTarget { unused_00: [0; 4], owner: &mut owner };
            let context_ptr = &mut context as *mut TaskCtx;
            post_to_self(&mut target,
                || { (*context_ptr).queue_pool = 0x5678usize as *mut u8; core::ptr::null_mut() },
                |_, destination, _, reply, _| {
                    assert_eq!((*(*(*destination).owner).task_ctx).queue_pool as usize, 0x5678);
                    assert_eq!(reply, 0x1234);
                    0
                },
            );
        }
    }

    #[test]
    fn zero_snapshot_is_not_replaced_by_new_destination_queue() {
        unsafe {
            let mut context: TaskCtx = core::mem::zeroed();
            let mut owner = MessageTargetOwner { unused_00: [0; 3], task_ctx: &mut context };
            let mut target = MessageTarget { unused_00: [0; 4], owner: &mut owner };
            let context_ptr = &mut context as *mut TaskCtx;
            post_to_self(&mut target,
                || { (*context_ptr).queue_pool = 0x5678usize as *mut u8; core::ptr::null_mut() },
                |_, _, _, reply, _| { assert_eq!(reply, 0); 1 },
            );
        }
    }
}
