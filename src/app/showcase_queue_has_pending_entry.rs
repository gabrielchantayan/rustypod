//! Pending-entry predicate for a Showcase slot queue.
//!
//! `showcase_queue_has_pending_entry` — original: `FUN_081b7f9c` @
//! **0x081b7f9c** (**28 bytes**; **11 direct `bl` call sites, all
//! unconditional**).
//!
//! Raw ARM decoding establishes the exact extent `0x081b7f9c..0x081b7fb8`:
//!
//! ```text
//! 081b7f9c  ldr r1, [r0, #4]
//! 081b7fa0  ldr r0, [r0, #8]
//! 081b7fa4  cmp r1, r0
//! 081b7fa8  movne r0, #0
//! 081b7fac  moveq r0, #1
//! 081b7fb0  eor r0, r0, #1
//! 081b7fb4  bx lr
//! ```
//!
//! `0x081b7fb8` begins a separately entered initializer, so the predicate has
//! no trailing literal pool. Decoding every ARM B/BL word in `osos.dec` finds
//! its 11 direct inbound call sites at `0x081b6d70`, `0x081b6fcc`,
//! `0x081b755c`, `0x081b7720`, `0x081b7858`, `0x081b78d8`, `0x081b7ba0`,
//! `0x081b7c20`, `0x081b7d44`, `0x081b7e8c`, and `0x081b7f4c`; every one is
//! an unconditional `bl`, with no predicated forms. The call sites query the
//! queues embedded in the four Showcase slots.
//!
//! # Algorithm
//!
//! Return one when the two cursor words at `queue + 4` and `queue + 8` differ;
//! otherwise return zero. This is the queue's pending-entry condition.
//!
//! # Deliberate deviations
//!
//! The queue layout has no recovered concrete type. The port models it as
//! aligned `u32` words, preserving the two verified ARM offsets on both the
//! target and 64-bit host.

/// Returns one when a Showcase queue's cursor words differ.
///
/// # Safety
///
/// `queue` must point to an aligned, readable object containing `u32` words at
/// offsets `+4` and `+8`. As in retailOS, this routine does not NULL-check it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn showcase_queue_has_pending_entry(queue: *const u32) -> u32 {
    (queue.add(1).read() != queue.add(2).read()) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_cursors_have_no_pending_entry() {
        for cursor in [0, 1, 0x7fff_ffff, u32::MAX] {
            let queue = [0xfeed_face, cursor, cursor, 0xdec0_de01];

            assert_eq!(
                unsafe { showcase_queue_has_pending_entry(queue.as_ptr()) },
                0,
                "equal cursor {cursor:#010x}"
            );
        }
    }

    #[test]
    fn unequal_cursors_have_a_pending_entry() {
        for (first_cursor, second_cursor) in [(0, 1), (1, 0), (u32::MAX, 0), (0, u32::MAX)] {
            let queue = [0xfeed_face, first_cursor, second_cursor, 0xdec0_de01];

            assert_eq!(
                unsafe { showcase_queue_has_pending_entry(queue.as_ptr()) },
                1,
                "cursors {first_cursor:#010x}, {second_cursor:#010x}"
            );
        }
    }

    #[test]
    fn reads_only_the_two_cursor_words() {
        let queue = [0xfeed_face, 4, 5, 0xdec0_de01];
        let before = queue;

        assert_eq!(unsafe { showcase_queue_has_pending_entry(queue.as_ptr()) }, 1);
        assert_eq!(queue, before, "a predicate must not mutate queue state");
    }
}
