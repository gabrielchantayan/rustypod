//! Completes pending queues in the four Showcase slots.
//!
//! `showcase_pending_queues_complete` — original: `FUN_081b6fb4` @
//! **0x081b6fb4** (**64 bytes**, `0x081b6fb4..0x081b6ff4`; the separately
//! linked next function begins at `0x081b6ff4`).
//!
//! Raw ARM decoding finds three direct inbound calls, all unconditional `bl`
//! (no predicated forms), at `0x081b6aac`, `0x081b6e78`, and `0x081b6f58`.
//!
//! # Algorithm
//!
//! For each of four 24-byte Showcase slots, test the queue at slot `+0x88`.
//! Complete it only when its cursor words differ, then set `showcase + 0xea`
//! to one.
//!
//! # Deliberate deviations
//!
//! The recovered Showcase layout is opaque. Raw byte offsets and target-width
//! queue pointers preserve the ARM layout on 64-bit hosts.

const SLOT_COUNT: usize = 4;
const SLOT_SIZE: usize = 0x18;
const SLOT_QUEUE_OFFSET: usize = 0x88;
const COMPLETION_READY_OFFSET: usize = 0xea;

/// Completes the pending queue in each Showcase slot and marks completion ready.
///
/// # Safety
///
/// `showcase` must point to writable storage through `+0xea`; each queue word
/// at `showcase + slot * 0x18 + 0x88` must be a valid target-width pointer to
/// a queue readable at `+4` and `+8`. Pending queues must meet
/// [`crate::app::queue_complete::queue_complete`]'s preconditions.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn showcase_pending_queues_complete(showcase: *mut u8) {
    for slot in 0..SLOT_COUNT {
        let queue = showcase.add(slot * SLOT_SIZE + SLOT_QUEUE_OFFSET).cast::<u32>().read();
        let queue = queue as usize as *mut u32;
        if crate::app::showcase_queue_has_pending_entry::showcase_queue_has_pending_entry(queue) != 0 {
            crate::app::queue_complete::queue_complete(queue.cast());
        }
    }
    showcase.add(COMPLETION_READY_OFFSET).write(1);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::mode_selected_position_set::MODE_SELECTED_POSITION_SET_TEST_LOCK;
    use crate::app::queue_complete::{QueueCompleteOps, DEFAULT_QUEUE_COMPLETE_OPS, QUEUE_COMPLETE_OPS};
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicU32, Ordering};

    const FIXTURE_LEN: usize = 0x1000;
    const QUEUE_BASE: usize = 0x100;
    const QUEUE_STRIDE: usize = 0x100;
    static GATE_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn completion_gate(_state: *mut u8) -> u32 {
        GATE_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }
    unsafe extern "C" fn unused_operation(_state: *mut u8) -> u32 { unreachable!() }
    unsafe extern "C" fn unused_release_check(_state: *mut u8) -> u32 { unreachable!() }
    unsafe extern "C" fn unused_release(_request: *mut u8) { unreachable!() }
    unsafe extern "C" fn unused_set_position(_state: *mut u8, _mode: u32, _position: u32) -> u32 { unreachable!() }

    struct RestoreQueueCompleteOps;
    impl Drop for RestoreQueueCompleteOps {
        fn drop(&mut self) { unsafe { QUEUE_COMPLETE_OPS = DEFAULT_QUEUE_COMPLETE_OPS; } }
    }

    #[test]
    fn completes_only_pending_slot_queues_then_sets_ready_byte() {
        let Some(showcase) = try_map_u32_slab(hints::SHOWCASE_PENDING_QUEUES_COMPLETE, FIXTURE_LEN) else { return; };
        let _lock = MODE_SELECTED_POSITION_SET_TEST_LOCK.lock();
        let _restore = RestoreQueueCompleteOps;
        unsafe {
            showcase.write_bytes(0, FIXTURE_LEN);
            QUEUE_COMPLETE_OPS = QueueCompleteOps {
                completion_gate,
                queue_operation: unused_operation,
                release_check: unused_release_check,
                release: unused_release,
                set_position: unused_set_position,
            };
            for slot in 0..SLOT_COUNT {
                let queue = showcase.add(QUEUE_BASE + slot * QUEUE_STRIDE).cast::<u32>();
                queue.write(0);
                queue.add(1).write(slot as u32);
                queue.add(2).write(if slot == 2 { 0x77 } else { slot as u32 });
                queue.cast::<u8>().add(0x14).cast::<u32>().write(1);
                queue.cast::<u8>().add(0x24).write(1);
                showcase.add(slot * SLOT_SIZE + SLOT_QUEUE_OFFSET).cast::<u32>().write(queue as usize as u32);
            }
            GATE_CALLS.store(0, Ordering::Relaxed);
            showcase_pending_queues_complete(showcase);
        }
        assert_eq!(GATE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(unsafe { showcase.add(COMPLETION_READY_OFFSET).read() }, 1);
    }
}
