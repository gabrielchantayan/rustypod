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
//! `move_entry_to_queue_end` when the entry has a successor.
//!
//! # Deliberate deviations
//!
//! Target-width words are used rather than host pointers because every
//! observed entry field is four bytes apart. Tail promotion uses the Rust port.

#[cfg(not(target_os = "none"))]
use core::ptr;

const REQUEST_QUEUE_GLOBAL: *const *mut u32 = 0x08a0_aa78 as *const *mut u32;
use super::move_entry_to_queue_end::move_entry_to_queue_end;

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

    unsafe fn fixture() -> Option<*mut u32> {
        let base = *FIXTURE.as_ref()? as *mut u8;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        Some(base.cast())
    }

    unsafe fn entry(base: *mut u32, word: usize) -> *mut u32 {
        unsafe { base.add(word) }
    }

    unsafe fn install(base: *mut u32) -> *mut u32 {
        let old_queue = REQUEST_QUEUE;
        REQUEST_QUEUE = base.add(QUEUE);
        old_queue
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
            base.add(QUEUE + 2).write(third as usize as u32);
            second.add(1).write(first as usize as u32);
            third.add(1).write(second as usize as u32);
            first.add(2).write(7); first.add(6).write(1);
            second.add(2).write(7); second.add(6).write(2);
            third.add(2).write(9); third.add(6).write(7);
            let saved = install(base);
            request_queue_clear_matching_entries(7, 0);
            REQUEST_QUEUE = saved;
            assert_eq!(first.add(2).read(), 0); assert_eq!(first.add(6).read(), 0);
            assert_eq!(second.add(2).read(), 0); assert_eq!(second.add(6).read(), 0);
            assert_eq!(third.add(2).read(), 9);
            assert_eq!(base.add(QUEUE + 1).read(), third as usize as u32);
            assert_eq!(base.add(QUEUE + 2).read(), second as usize as u32);
            assert_eq!(third.read(), first as usize as u32);
            assert_eq!(first.add(1).read(), third as usize as u32);
            assert_eq!(first.read(), second as usize as u32);
            assert_eq!(second.add(1).read(), first as usize as u32);
            assert_eq!(second.read(), 0);
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
            base.add(QUEUE + 2).write(second as usize as u32);
            second.add(1).write(first as usize as u32);
            first.add(2).write(7); first.add(6).write(1);
            second.add(2).write(7); second.add(6).write(2);
            let saved = install(base);
            request_queue_clear_matching_entries(7, 2);
            REQUEST_QUEUE = saved;
            assert_eq!(first.add(2).read(), 7); assert_eq!(first.add(6).read(), 1);
            assert_eq!(second.add(2).read(), 0); assert_eq!(second.add(6).read(), 0);
            assert_eq!(base.add(QUEUE + 1).read(), first as usize as u32);
            assert_eq!(base.add(QUEUE + 2).read(), second as usize as u32);
            assert_eq!(first.read(), second as usize as u32);
            assert_eq!(second.add(1).read(), first as usize as u32);
        }
    }
}
