//! Pending-queue lookup for a Showcase slot.
//!
//! `showcase_slot_pending_queue` — original: `FUN_081b6d4c` @
//! **0x081b6d4c** (**60 bytes**; **6 direct `bl` call sites, all
//! unconditional**).
//!
//! Raw ARM decoding establishes the exact extent `0x081b6d4c..0x081b6d88`:
//!
//! ```text
//! 081b6d4c  push {r4, lr}
//! 081b6d50  ldrb r2, [r0, #32]
//! 081b6d54  cmp r2, #0
//! 081b6d58  bleq 0x08030f44
//! 081b6d5c  cmp r1, #3
//! 081b6d60  bhi 0x081b6d80
//! 081b6d64  add r1, r1, r1, lsl #1
//! 081b6d68  add r4, r0, r1, lsl #3
//! 081b6d6c  add r0, r4, #136
//! 081b6d70  bl 0x081b7f9c
//! 081b6d74  cmp r0, #0
//! 081b6d78  addne r0, r4, #136
//! 081b6d7c  popne {r4, pc}
//! 081b6d80  mov r0, #0
//! 081b6d84  pop {r4, pc}
//! ```
//!
//! The following `push {r4, r5, r6, lr}` at `0x081b6d88` starts a separately
//! linked function; there is no literal pool. Decoding every ARM B/BL word in
//! `osos.dec` finds six direct inbound sites at `0x081b6b34`, `0x081b6b5c`,
//! `0x081b7188`, `0x081b7324`, `0x081b782c`, and `0x081b7f24`. All are
//! unconditional `bl`; there are no predicated forms.
//!
//! # Algorithm
//!
//! Panic through `heap_panic` when the Showcase state byte at `+0x20` is zero.
//! For slots `0..4`, find the 24-byte slot record, whose queue begins at
//! `showcase + slot * 0x18 + 0x88`, and return that queue only when its cursor
//! words at `+4` and `+8` differ. Return NULL for an empty queue or an
//! out-of-range slot.
//!
//! # Deliberate deviations
//!
//! The concrete Showcase layout is unrecovered. The port retains its verified
//! 32-bit word layout, so its offsets remain correct on 64-bit hosts, and calls
//! the existing Rust `heap_panic` port instead of branching to its retailOS
//! address.

use crate::app::showcase_queue_has_pending_entry::showcase_queue_has_pending_entry;
use crate::heap::veneers::heap_panic;

const SHOWCASE_READY_OFFSET: usize = 0x20;
const SLOT_QUEUE_OFFSET_WORDS: usize = 0x88 / core::mem::size_of::<u32>();
const SLOT_STRIDE_WORDS: usize = 0x18 / core::mem::size_of::<u32>();
const SHOWCASE_SLOT_COUNT: u32 = 4;

/// Returns the selected Showcase slot's queue only when it has pending work.
///
/// # Safety
///
/// `showcase` must point to a readable Showcase object containing its ready
/// byte at `+0x20` and all four embedded slot queues. As in retailOS, this
/// routine does not NULL-check it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn showcase_slot_pending_queue(
    showcase: *const u32,
    slot: u32,
) -> *const u32 {
    if showcase.cast::<u8>().add(SHOWCASE_READY_OFFSET).read() == 0 {
        heap_panic();
    }

    if slot >= SHOWCASE_SLOT_COUNT {
        return core::ptr::null();
    }

    let queue = showcase.add(SLOT_QUEUE_OFFSET_WORDS + slot as usize * SLOT_STRIDE_WORDS);
    if showcase_queue_has_pending_entry(queue) != 0 {
        queue
    } else {
        core::ptr::null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOWCASE_WORDS: usize = SLOT_QUEUE_OFFSET_WORDS + (SHOWCASE_SLOT_COUNT as usize - 1) * SLOT_STRIDE_WORDS + 3;

    fn ready_showcase() -> [u32; SHOWCASE_WORDS] {
        let mut showcase = [0; SHOWCASE_WORDS];
        unsafe {
            showcase
                .as_mut_ptr()
                .cast::<u8>()
                .add(SHOWCASE_READY_OFFSET)
                .write(1);
        }
        showcase
    }

    fn slot_queue(showcase: &mut [u32; SHOWCASE_WORDS], slot: usize) -> *mut u32 {
        unsafe { showcase.as_mut_ptr().add(SLOT_QUEUE_OFFSET_WORDS + slot * SLOT_STRIDE_WORDS) }
    }

    #[test]
    fn returns_each_nonempty_slot_queue() {
        let mut showcase = ready_showcase();

        for slot in 0..SHOWCASE_SLOT_COUNT as usize {
            let queue = slot_queue(&mut showcase, slot);
            unsafe {
                queue.add(1).write(0x100 + slot as u32);
                queue.add(2).write(0x200 + slot as u32);
                assert_eq!(
                    showcase_slot_pending_queue(showcase.as_ptr(), slot as u32),
                    queue.cast_const(),
                );
            }
        }
    }

    #[test]
    fn empty_slot_queue_returns_null() {
        let mut showcase = ready_showcase();
        let queue = slot_queue(&mut showcase, 2);
        unsafe {
            queue.add(1).write(0xfeed_face);
            queue.add(2).write(0xfeed_face);
            assert!(showcase_slot_pending_queue(showcase.as_ptr(), 2).is_null());
        }
    }

    #[test]
    fn out_of_range_slot_returns_null_without_selecting_queue() {
        let mut showcase = ready_showcase();
        let queue = slot_queue(&mut showcase, 3);
        unsafe {
            queue.add(1).write(1);
            queue.add(2).write(2);
            assert!(showcase_slot_pending_queue(showcase.as_ptr(), 4).is_null());
            assert!(showcase_slot_pending_queue(showcase.as_ptr(), u32::MAX).is_null());
        }
    }
}
