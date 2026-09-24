//! `queue_remove_source_tail_index` — original: `FUN_080b8228` @ `0x080b8228`.
//!
//! Load address: `0x080b8228`; true size: 48 bytes (`0x30`), ending in a
//! tail branch to `0x080b0fbc` before the next real function at `0x080b8258`.
//! Raw ARM decoding verifies zero plain `bl` instructions and zero predicated
//! `bl` instructions in the body; a complete direct-call scan finds three
//! inbound plain `bl` call sites and no predicated inbound calls.
//!
//! When the byte addressed by the pointer at `0x08a0e180` is nonzero, select
//! one of the two 0x48-byte queue records at `0x08b1c858` and remove its final
//! entry. A disabled queue returns one. The retail routine tail-branches to
//! `0x080b0fbc`, which repeats the gate and selection before entering the
//! shared removal body at `0x080b0fdc`; this port deliberately inlines that
//! unported tail chain rather than inventing a callee seam.

use core::ptr;

const SOURCE_ENABLED_POINTER: *const u32 = 0x08a0_e180 as *const u32;
const SOURCE_RECORDS: *const u32 = 0x08b1_c858 as *const u32;
const RECORD_WORDS: usize = 0x48 / size_of::<u32>();
const QUEUE_LENGTH_WORD: usize = 0x40 / size_of::<u32>();
const QUEUE_LIMIT_WORD: usize = 0x44 / size_of::<u32>();

/// Removes the selected static queue's final entry.
///
/// # Safety
///
/// The firmware globals above must be mapped. Each selected queue must have a
/// length word at `0x40`, a signed upper limit at `0x44`, and entries through
/// its current final element.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
#[cfg_attr(target_os = "none", link_section = ".text.queue_remove_source_tail_index")]
pub unsafe extern "C" fn queue_remove_source_tail_index(selector: u32) -> u32 {
    let enabled = ptr::read_volatile(ptr::read_volatile(SOURCE_ENABLED_POINTER) as *const u8);
    if enabled == 0 {
        return 1;
    }

    remove_selected_tail(SOURCE_RECORDS as *mut u32, selector)
}

#[inline(always)]
unsafe fn remove_selected_tail(records: *mut u32, selector: u32) -> u32 {
    let queue = records.add(if selector == 1 { RECORD_WORDS } else { 0 });
    let index = ptr::read_volatile(queue.add(QUEUE_LENGTH_WORD)).wrapping_sub(1);
    remove_queue_index(queue, index)
}

#[inline(always)]
unsafe fn remove_queue_index(queue: *mut u32, index: u32) -> u32 {
    let length = ptr::read_volatile(queue.add(QUEUE_LENGTH_WORD));
    if length == 0 {
        return 5;
    }

    let index_signed = index as i32;
    if index_signed < 0
        || (ptr::read_volatile(queue.add(QUEUE_LIMIT_WORD)) as i32) < index_signed
        || (length as i32) <= index_signed
    {
        return 6;
    }

    let final_index = length - 1;
    let mut current = index;
    while current != final_index {
        let entry = ptr::read_volatile(queue.add(current as usize + 1));
        ptr::write_volatile(queue.add(current as usize), entry);
        current += 1;
    }
    ptr::write_volatile(queue.add(final_index as usize), 0);
    ptr::write_volatile(queue.add(QUEUE_LENGTH_WORD), final_index);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::QUEUE_REMOVE_SOURCE_TAIL_INDEX, 0x1000).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn records() -> Option<*mut u32> {
        Some(((*FIXTURE)? as *mut u32).add(0x40))
    }

    #[test]
    fn removes_the_tail_from_each_selected_queue() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(records) = (unsafe { records() }) else {
            assert!(note_missing_u32_fixture("util/queue_remove_source_tail_index"));
            return;
        };
        unsafe {
            for (selector, initial) in [(0, [10, 20, 30]), (1, [40, 50, 60])] {
                let queue = records.add(if selector == 1 { RECORD_WORDS } else { 0 });
                queue.add(QUEUE_LENGTH_WORD).write_volatile(3);
                queue.add(QUEUE_LIMIT_WORD).write_volatile(2);
                for (index, value) in initial.into_iter().enumerate() {
                    queue.add(index).write_volatile(value);
                }
                assert_eq!(remove_selected_tail(records, selector), 0);
                assert_eq!([queue.read_volatile(), queue.add(1).read_volatile(), queue.add(2).read_volatile()], [initial[0], initial[1], 0]);
                assert_eq!(queue.add(QUEUE_LENGTH_WORD).read_volatile(), 2);
            }
        }
    }

    #[test]
    fn rejects_empty_and_invalid_tail_indices_without_writing() {
        let _lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(records) = (unsafe { records() }) else {
            assert!(note_missing_u32_fixture("util/queue_remove_source_tail_index"));
            return;
        };
        unsafe {
            records.add(QUEUE_LENGTH_WORD).write_volatile(0);
            assert_eq!(remove_selected_tail(records, 0), 5);

            let queue = records.add(RECORD_WORDS);
            queue.add(QUEUE_LENGTH_WORD).write_volatile(2);
            queue.add(QUEUE_LIMIT_WORD).write_volatile(1);
            queue.write_volatile(0xaaaa_aaaa);
            queue.add(1).write_volatile(0xbbbb_bbbb);
            assert_eq!(remove_queue_index(queue, u32::MAX), 6);
            assert_eq!([queue.read_volatile(), queue.add(1).read_volatile()], [0xaaaa_aaaa, 0xbbbb_bbbb]);
        }
    }
}
