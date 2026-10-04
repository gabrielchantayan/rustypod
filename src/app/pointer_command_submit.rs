//! `pointer_command_submit` — `FUN_081df20c` @ 0x081df20c.
//! True extent: 60 bytes, 0x081df20c..0x081df248; the next entry starts
//! with push {r4,r5,r6,lr}. Two inbound plain BLs, no predicated BLs.
//! Body: three plain BLs, no predicated BLs, one tail branch.
//!
//! Allocate a 12-byte command, set its kind to zero and its value to the
//! caller's word, leaving the third word untouched. Enqueue the command,
//! run the existing once initializer, then post the mailbox at context+0x20.
//! Deliberate deviation: Rust calls mailbox_slot_post rather than tail
//! branching. Context offsets retain the target ABI, not host pointer sizes.

use crate::app::once_initializer::{initialize_once, OnceInitializationState};
use crate::app::pointer_queue::{pointer_queue_enqueue, PointerQueue};
use crate::heap::veneers::operator_new;
use crate::kernel::kobj::{mailbox_slot_post, Mailbox};

#[inline(always)]
unsafe fn allocate_pointer_command(value: u32) -> *mut u32 {
    let command = operator_new(12).cast::<u32>();
    command.write(0);
    command.add(1).write(value);
    command
}

/// # Safety
/// `context` must be a live retailOS target-layout queue/context, including
/// its initialization byte at +0x25 and mailbox pointer at +0x20. The heap
/// must return writable aligned storage; allocation failure is unguarded,
/// exactly as in the firmware. This context ABI is only usable on 32-bit ARM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pointer_command_submit(context: *mut u8, value: u32) {
    let command = allocate_pointer_command(value);
    pointer_queue_enqueue(context.cast::<PointerQueue>(), command.cast());
    initialize_once(context.cast::<OnceInitializationState>());
    mailbox_slot_post(context.add(0x20).cast::<*mut Mailbox>());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};

    #[test]
    fn command_preserves_unused_word_and_full_width_values() {
        let _heap = mock_heap();
        for value in [0, 1, 0x8000_0000, u32::MAX] {
            let mut storage = [0xa5a5_a5a5, 0x5a5a_5a5a, 0xdead_beef];
            unsafe {
                set_alloc_ret(storage.as_mut_ptr().cast());
                let command = allocate_pointer_command(value);
                assert_eq!(command, storage.as_mut_ptr());
                assert_eq!(storage, [0, value, 0xdead_beef]);
                assert_eq!(alloc_log().1, 12);
                assert_eq!(alloc_log().2, 2);
            }
        }
    }
}
