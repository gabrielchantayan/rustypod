//! Schedule pending Showcase queues, then continue the selected-slot pass.
//!
//! Original: `FUN_081b7f18` @ **0x081b7f18**, **132 bytes** including the
//! four-byte literal at `0x081b7f98`; next function: `0x081b7f9c`.
//! Full-image ARM decoding finds two inbound BL sites: plain BL at
//! `0x081b6f84` and BLEQ at `0x081b6e98`. The body has three plain BLs,
//! one BLEQ to heap_panic, and a tail B to `0x081b6ae8`.
//!
//! Require a pending queue for the selected slot. Visit all four queues at
//! `+0x88 + slot*0x18`; for unequal cursors, dispatch the queue's context with
//! request 10,000,000 and its word at +0x10 shifted left 19 (wrapping u32),
//! then stamp that slot's pass count at `+0x1c4 + slot*4` to ten. Continue
//! through `0x081b6ae8` with the original selected slot, zero, and 200.
//!
//! Deliberate deviations: reuse the existing Rust lookup, predicate, and panic
//! ports. Unported dispatch and continuation use verified firmware addresses;
//! host invocation of those addresses is unsupported, not silently ignored.
//! A private callback-parameterized core permits isolated host edge tests.
//! Target-width word offsets preserve the layout on 64-bit hosts. The dispatch
//! target's semantic interpretation is not assumed: raw `0x0822b2a8` ends at
//! `0x0822b2c4`, and its tail target `0x081f0ec4` forwards both r1 and r2 to
//! virtual slot +0x30. Ghidra incorrectly includes the next function's body.

use crate::app::showcase_queue_has_pending_entry::showcase_queue_has_pending_entry;
use crate::app::showcase_slot_pending_queue::showcase_slot_pending_queue;
use crate::heap::veneers::heap_panic;

#[inline(always)]
unsafe fn schedule_queues(
    showcase: *mut u32,
    mut dispatch: impl FnMut(u32, u32, u32),
) {
    for slot in 0..4 {
        let queue = showcase.add(0x22 + slot * 6);
        if showcase_queue_has_pending_entry(queue) != 0 {
            let argument = queue.add(4).read().wrapping_shl(19);
            let context = queue.read();
            dispatch(context, 10_000_000, argument);
            showcase.add(0x71 + slot).write(10);
        }
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_context(context: u32, request: u32, argument: u32) {
    let dispatch: unsafe extern "C" fn(u32, u32, u32) =
        core::mem::transmute(0x0822_b2a8usize);
    dispatch(context, request, argument);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn continue_slot_pass(showcase: *mut u32, slot: u32) {
    let resume: unsafe extern "C" fn(*mut u32, u32, u32, u32) =
        core::mem::transmute(0x081b_6ae8usize);
    resume(showcase, slot, 0, 200);
}

/// Dispatches pending queues and resumes the selected slot's pass.
///
/// # Safety
/// `showcase` must be an aligned writable retail Showcase object with four
/// embedded queues and pass counts through +0x1d0. Its selected slot must have
/// pending work; queue contexts and the remaining object must satisfy the
/// retail dispatch and continuation contracts. Host calls cannot run the
/// unported firmware continuation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn showcase_pending_queues_schedule(showcase: *mut u32, slot: u32) {
    if showcase_slot_pending_queue(showcase, slot).is_null() {
        heap_panic();
    }
    #[cfg(target_os = "none")]
    {
        schedule_queues(showcase, |context, request, argument| {
            dispatch_context(context, request, argument);
        });
        continue_slot_pass(showcase, slot);
    }
    #[cfg(not(target_os = "none"))]
    panic!("showcase_pending_queues_schedule requires retailOS dispatch and continuation");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queues_preserve_every_word() {
        let mut showcase = [0xabad_cafe; 0x75];
        for slot in 0..4 {
            showcase[0x23 + slot * 6] = slot as u32;
            showcase[0x24 + slot * 6] = slot as u32;
        }
        let before = showcase;
        unsafe { schedule_queues(showcase.as_mut_ptr(), |_, _, _| panic!("empty queue dispatched")); }
        assert_eq!(showcase, before);
    }

    #[test]
    fn mixed_queues_wrap_arguments_and_stamp_only_after_dispatch() {
        let mut showcase = [0; 0x75];
        for slot in 0..4 {
            let base = 0x22 + slot * 6;
            showcase[base] = 0x1000 + slot as u32;
            showcase[base + 1] = if slot == 1 { 7 } else { u32::MAX };
            showcase[base + 2] = if slot == 1 { 7 } else { 0 };
            showcase[base + 4] = [0, 123, 0x2000, u32::MAX][slot];
            showcase[0x71 + slot] = 30 + slot as u32;
        }
        let before = showcase;
        let pointer = showcase.as_mut_ptr();
        let mut calls = 0;
        unsafe {
            schedule_queues(pointer, |context, request, argument| {
                let slot = (context - 0x1000) as usize;
                assert_eq!(slot, [0, 2, 3][calls]);
                assert_eq!(request, 10_000_000);
                assert_eq!(argument, [0, 0, 0xfff8_0000][calls]);
                assert_eq!(pointer.add(0x71 + slot).read(), 30 + slot as u32);
                if calls != 0 { assert_eq!(pointer.add(0x71).read(), 10); }
                calls += 1;
            });
        }
        assert_eq!(calls, 3);
        let mut expected = before;
        for slot in [0, 2, 3] { expected[0x71 + slot] = 10; }
        assert_eq!(showcase, expected);
    }

    #[test]
    fn dispatch_mutation_is_observed_by_later_queue_checks() {
        let mut showcase = [0; 0x75];
        showcase[0x23] = 1;
        let pointer = showcase.as_mut_ptr();
        let mut calls = 0;
        unsafe {
            schedule_queues(pointer, |_, _, _| {
                calls += 1;
                if calls == 1 {
                    pointer.add(0x23 + 3 * 6).write(1);
                    pointer.add(0x22 + 3 * 6 + 4).write(1);
                }
            });
        }
        assert_eq!(calls, 2);
        assert_eq!(showcase[0x74], 10);
    }
}
