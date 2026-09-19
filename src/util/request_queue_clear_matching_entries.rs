//! `request_queue_clear_matching_entries` — original: `FUN_0806b544` @
//! 0x0806b544 (112 bytes; four inbound plain `bl` callers and one plain direct
//! `bl` in the body, with zero predicated `bl` forms).
//!
//! Raw `osos.dec` establishes the exact extent `0x0806b544..0x0806b5b4`:
//! `0x0806b5b4` is the literal pool word `0x08a0aa78`, and `0x0806b5b8`
//! begins a distinct `push {r4,r5,r6,lr}` function. The queue starts at the
//! global pointer held at that literal. It scans entries from queue word +1;
//! for each matching request ID, it optionally requires the entry's context
//! word (+0x18) to equal `context`, clears both words, and invokes
//! `FUN_08058c3c` when the entry has a successor.
//!
//! # Deliberate deviations
//!
//! `FUN_08058c3c` is not ported or named in the ledger. The device build calls
//! its verified retail address directly; host tests install a seam that records
//! the call. Target-width words are used rather than host pointers because
//! every observed entry field is four bytes apart.

#[cfg(not(target_os = "none"))]
use core::ptr;

const REQUEST_QUEUE_GLOBAL: *const *mut u32 = 0x08a0_aa78 as *const *mut u32;
const RETAIL_MOVE_ENTRY_TO_QUEUE_END: usize = 0x0805_8c3c;

type MoveEntryToQueueEnd = unsafe extern "C" fn(*mut u32, *mut u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn request_queue() -> *mut u32 {
    unsafe { REQUEST_QUEUE_GLOBAL.read_volatile() }
}

#[cfg(not(target_os = "none"))]
static mut REQUEST_QUEUE: *mut u32 = ptr::null_mut();

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn request_queue() -> *mut u32 {
    unsafe { ptr::read_volatile(ptr::addr_of!(REQUEST_QUEUE)) }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn move_entry_to_queue_end(queue: *mut u32, entry: *mut u32) {
    let move_entry: MoveEntryToQueueEnd = unsafe { core::mem::transmute(RETAIL_MOVE_ENTRY_TO_QUEUE_END) };
    unsafe { move_entry(queue, entry) }
}

#[cfg(not(target_os = "none"))]
static mut MOVE_ENTRY_TO_QUEUE_END: MoveEntryToQueueEnd = missing_move_entry_to_queue_end;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_move_entry_to_queue_end(_queue: *mut u32, _entry: *mut u32) {
    panic!("request_queue_clear_matching_entries requires FUN_08058c3c @ 0x08058c3c")
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn move_entry_to_queue_end(queue: *mut u32, entry: *mut u32) {
    let move_entry = unsafe { ptr::read_volatile(ptr::addr_of!(MOVE_ENTRY_TO_QUEUE_END)) };
    unsafe { move_entry(queue, entry) }
}

/// Clears the request ID and context of matching queued entries.
///
/// `context == 0` accepts every entry with the requested ID; otherwise it
/// accepts only entries whose context word equals `context`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn request_queue_clear_matching_entries(request_id: u32, context: u32) {
    let queue = unsafe { request_queue() };
    let mut entry = unsafe { queue.add(1).read() } as *mut u32;

    while !entry.is_null() {
        if unsafe { entry.add(2).read() } == request_id
            && (context == 0 || unsafe { entry.add(6).read() } == context)
        {
            unsafe {
                entry.add(2).write(0);
                entry.add(6).write(0);
            }
            let next = unsafe { entry.read() } as *mut u32;
            if !next.is_null() {
                unsafe { move_entry_to_queue_end(queue, entry) };
                entry = next;
                continue;
            }
        }
        entry = unsafe { entry.read() } as *mut u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const QUEUE: usize = 0;
    const FIRST: usize = 16;
    const SECOND: usize = 32;
    const THIRD: usize = 48;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::REQUEST_QUEUE_CLEAR_MATCHING_ENTRIES, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut MOVED: [u32; 4] = [0; 4];
    static mut MOVED_LEN: usize = 0;

    unsafe extern "C" fn record_move(_queue: *mut u32, entry: *mut u32) {
        unsafe {
            MOVED[MOVED_LEN] = entry as usize as u32;
            MOVED_LEN += 1;
        }
    }

    unsafe fn fixture() -> Option<*mut u32> {
        let base = *FIXTURE.as_ref()? as *mut u8;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        Some(base.cast())
    }

    unsafe fn entry(base: *mut u32, word: usize) -> *mut u32 {
        unsafe { base.add(word) }
    }

    unsafe fn install(base: *mut u32) -> (*mut u32, MoveEntryToQueueEnd) {
        let old_queue = unsafe { REQUEST_QUEUE };
        let old_move = unsafe { MOVE_ENTRY_TO_QUEUE_END };
        unsafe {
            REQUEST_QUEUE = base.add(QUEUE);
            MOVE_ENTRY_TO_QUEUE_END = record_move;
            MOVED_LEN = 0;
        }
        (old_queue, old_move)
    }

    unsafe fn restore(old_queue: *mut u32, old_move: MoveEntryToQueueEnd) {
        unsafe {
            REQUEST_QUEUE = old_queue;
            MOVE_ENTRY_TO_QUEUE_END = old_move;
        }
    }

    #[test]
    fn clears_every_matching_id_when_context_is_wildcard() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/request_queue_clear_matching_entries"));
            return;
        };
        unsafe {
            let first = entry(base, FIRST);
            let second = entry(base, SECOND);
            let third = entry(base, THIRD);
            base.add(QUEUE + 1).write(first as usize as u32);
            first.write(second as usize as u32);
            second.write(third as usize as u32);
            first.add(2).write(7); first.add(6).write(1);
            second.add(2).write(7); second.add(6).write(2);
            third.add(2).write(9); third.add(6).write(7);
            let saved = install(base);
            request_queue_clear_matching_entries(7, 0);
            restore(saved.0, saved.1);
            assert_eq!(first.add(2).read(), 0); assert_eq!(first.add(6).read(), 0);
            assert_eq!(second.add(2).read(), 0); assert_eq!(second.add(6).read(), 0);
            assert_eq!(third.add(2).read(), 9);
            assert_eq!(MOVED_LEN, 2);
            assert_eq!(MOVED[0], first as usize as u32); assert_eq!(MOVED[1], second as usize as u32);
        }
    }

    #[test]
    fn context_filter_preserves_mismatches_and_does_not_move_tail() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/request_queue_clear_matching_entries"));
            return;
        };
        unsafe {
            let first = entry(base, FIRST);
            let second = entry(base, SECOND);
            base.add(QUEUE + 1).write(first as usize as u32);
            first.write(second as usize as u32);
            first.add(2).write(7); first.add(6).write(1);
            second.add(2).write(7); second.add(6).write(2);
            let saved = install(base);
            request_queue_clear_matching_entries(7, 2);
            restore(saved.0, saved.1);
            assert_eq!(first.add(2).read(), 7); assert_eq!(first.add(6).read(), 1);
            assert_eq!(second.add(2).read(), 0); assert_eq!(second.add(6).read(), 0);
            assert_eq!(MOVED_LEN, 0);
        }
    }
}
