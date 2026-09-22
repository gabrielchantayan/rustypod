//! `queue_match_and_promote` — original: `FUN_08243778` @ 0x08243778
//! (204 bytes; two inbound plain `bl` callers, zero predicated inbound `bl`
//! forms, one plain outbound `bl`, zero predicated outbound `bl` forms, and two
//! indirect `blx`/`bx` dispatches).
//!
//! Raw `osos.dec` establishes the exact extent `0x08243778..0x08243844`:
//! `push {r4,r5,r6,r7,r8,r9,sl,lr}` starts this function and the next `push`
//! at 0x08243844 starts a separate function. It selects an operation table for
//! `kind`, scans the intrusive queue at header words +4/+5, and asks table slot
//! +4 whether each entry payload (+8) matches `value`. A matched non-head entry
//! is unlinked and promoted to the head. A miss tail-dispatches table slot +8.
//!
//! # Deliberate deviations
//!
//! `FUN_082432c8` and its operation tables have no names.yaml entries. The
//! device build therefore calls its verified retail address; host tests install
//! a selector seam. Target pointers remain u32 words, not host pointers.

use core::ptr;

const RETAIL_SELECT_QUEUE_OPERATION: usize = 0x0824_32c8;

type SelectQueueOperation = unsafe extern "C" fn(u32) -> *mut u32;
type EntryMatches = unsafe extern "C" fn(*mut u32, *mut u32, u32, usize) -> u32;
type QueueMiss = unsafe extern "C" fn(*mut u32, *mut u32, u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_select_queue_operation(kind: u32) -> *mut u32 {
    let select: SelectQueueOperation = unsafe { core::mem::transmute(RETAIL_SELECT_QUEUE_OPERATION) };
    unsafe { select(kind) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_select_queue_operation(_kind: u32) -> *mut u32 {
    panic!("queue_match_and_promote requires FUN_082432c8 @ 0x082432c8")
}

#[cfg(target_os = "none")]
pub const DEFAULT_QUEUE_MATCH_AND_PROMOTE_SELECTOR: SelectQueueOperation = firmware_select_queue_operation;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_QUEUE_MATCH_AND_PROMOTE_SELECTOR: SelectQueueOperation = missing_select_queue_operation;

pub static mut QUEUE_MATCH_AND_PROMOTE_SELECTOR: SelectQueueOperation =
    DEFAULT_QUEUE_MATCH_AND_PROMOTE_SELECTOR;

#[inline(always)]
unsafe fn select_queue_operation(kind: u32) -> *mut u32 {
    let selector = unsafe { ptr::read_volatile(ptr::addr_of!(QUEUE_MATCH_AND_PROMOTE_SELECTOR)) };
    unsafe { selector(kind) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn entry_matches(operation: *mut u32, entry: *mut u32, value: u32) -> u32 {
    let matches: EntryMatches = unsafe { core::mem::transmute(operation.add(1).read() as usize) };
    unsafe { matches(operation, entry.add(2), value, matches as usize) }
}

#[cfg(not(target_arch = "arm"))]
static mut HOST_ENTRY_MATCHES: EntryMatches = missing_entry_matches;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_entry_matches(_operation: *mut u32, _entry: *mut u32, _value: u32, _self_pointer: usize) -> u32 {
    panic!("queue_match_and_promote requires an entry matcher")
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn entry_matches(operation: *mut u32, entry: *mut u32, value: u32) -> u32 {
    let matches = unsafe { ptr::read_volatile(ptr::addr_of!(HOST_ENTRY_MATCHES)) };
    unsafe { matches(operation, entry.add(2), value, 0) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn dispatch_miss(operation: *mut u32, queue: *mut u32, miss_value: u32, value: u32) -> u32 {
    let miss: QueueMiss = unsafe { core::mem::transmute(operation.add(2).read() as usize) };
    unsafe { miss(operation, queue, miss_value, value) }
}

#[cfg(not(target_arch = "arm"))]
static mut HOST_QUEUE_MISS: QueueMiss = missing_queue_miss;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_queue_miss(_operation: *mut u32, _queue: *mut u32, _miss_value: u32, _value: u32) -> u32 {
    panic!("queue_match_and_promote requires a miss handler")
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn dispatch_miss(operation: *mut u32, queue: *mut u32, miss_value: u32, value: u32) -> u32 {
    let miss = unsafe { ptr::read_volatile(ptr::addr_of!(HOST_QUEUE_MISS)) };
    unsafe { miss(operation, queue, miss_value, value) }
}

/// Finds the first entry of `kind` whose operation accepts `value`, promotes a
/// non-head match, or dispatches the operation table's miss handler.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn queue_match_and_promote(
    queue: *mut u32,
    kind: u32,
    value: u32,
    miss_value: u32,
) -> u32 {
    let operation = unsafe { select_queue_operation(kind) };
    let mut entry = unsafe { queue.add(4).read() } as usize as *mut u32;

    while !entry.is_null() {
        if unsafe { (entry.cast::<u8>().add(0xc8)).read() } == kind as u8
            && unsafe { entry_matches(operation, entry, value) } != 0
        {
            let previous = unsafe { entry.read() } as usize as *mut u32;
            if !previous.is_null() {
                let next = unsafe { entry.add(1).read() } as usize as *mut u32;
                unsafe { previous.add(1).write(next as usize as u32) };
                if next.is_null() {
                    unsafe { queue.add(5).write(previous as usize as u32) };
                } else {
                    unsafe { next.write(previous as usize as u32) };
                }
                let head = unsafe { queue.add(4).read() } as usize as *mut u32;
                unsafe {
                    entry.add(1).write(head as usize as u32);
                    entry.write(0);
                    head.write(entry as usize as u32);
                    queue.add(4).write(entry as usize as u32);
                }
            }
            return 0;
        }
        entry = unsafe { entry.add(1).read() } as usize as *mut u32;
    }

    unsafe { dispatch_miss(operation, queue, miss_value, value) }
}


#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const HEADER: usize = 0;
    const FIRST: usize = 64;
    const SECOND: usize = 128;
    const THIRD: usize = 192;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::QUEUE_MATCH_AND_PROMOTE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut OPERATION: [u32; 3] = [0; 3];
    static mut SEEN_MISS: [u32; 3] = [0; 3];

    unsafe extern "C" fn select_operation(_kind: u32) -> *mut u32 { unsafe { OPERATION.as_mut_ptr() } }
    unsafe extern "C" fn match_value(_operation: *mut u32, payload: *mut u32, value: u32, _self_pointer: usize) -> u32 {
        unsafe { (payload.read() == value) as u32 }
    }
    unsafe extern "C" fn record_miss(_operation: *mut u32, queue: *mut u32, miss_value: u32, value: u32) -> u32 {
        unsafe { SEEN_MISS = [queue as usize as u32, miss_value, value] };
        0xfeed_beef
    }
    unsafe fn fixture() -> Option<*mut u32> {
        let base = *FIXTURE.as_ref()? as *mut u8;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        Some(base.cast())
    }
    unsafe fn node(base: *mut u32, word: usize) -> *mut u32 { unsafe { base.add(word) } }
    unsafe fn install() -> (SelectQueueOperation, EntryMatches, QueueMiss) {
        let old_selector = unsafe { QUEUE_MATCH_AND_PROMOTE_SELECTOR };
        let old_matches = unsafe { HOST_ENTRY_MATCHES };
        let old_miss = unsafe { HOST_QUEUE_MISS };
        unsafe {
            QUEUE_MATCH_AND_PROMOTE_SELECTOR = select_operation;
            HOST_ENTRY_MATCHES = match_value;
            HOST_QUEUE_MISS = record_miss;
            SEEN_MISS = [0; 3];
        }
        (old_selector, old_matches, old_miss)
    }
    unsafe fn restore(saved: (SelectQueueOperation, EntryMatches, QueueMiss)) {
        unsafe {
            QUEUE_MATCH_AND_PROMOTE_SELECTOR = saved.0;
            HOST_ENTRY_MATCHES = saved.1;
            HOST_QUEUE_MISS = saved.2;
        }
    }

    #[test]
    fn promotes_matching_interior_entry_and_preserves_queue_links() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("util/queue_match_and_promote")); return; };
        unsafe {
            let first = node(base, FIRST); let second = node(base, SECOND); let third = node(base, THIRD);
            base.add(HEADER + 4).write(first as usize as u32); base.add(HEADER + 5).write(third as usize as u32);
            first.add(1).write(second as usize as u32); second.write(first as usize as u32); second.add(1).write(third as usize as u32); third.write(second as usize as u32);
            first.add(2).write(1); second.add(2).write(9); third.add(2).write(9);
            first.cast::<u8>().add(0xc8).write(6); second.cast::<u8>().add(0xc8).write(6); third.cast::<u8>().add(0xc8).write(6);
            let saved = install();
            assert_eq!(queue_match_and_promote(base.add(HEADER), 6, 9, 17), 0);
            restore(saved);
            assert_eq!(base.add(4).read(), second as usize as u32); assert_eq!(second.read(), 0); assert_eq!(second.add(1).read(), first as usize as u32);
            assert_eq!(first.read(), second as usize as u32); assert_eq!(first.add(1).read(), third as usize as u32); assert_eq!(third.read(), first as usize as u32);
        }
    }

    #[test]
    fn miss_dispatches_operation_handler_with_reordered_values() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("util/queue_match_and_promote")); return; };
        unsafe {
            let saved = install();
            assert_eq!(queue_match_and_promote(base.add(HEADER), 6, 9, 17), 0xfeed_beef);
            restore(saved);
            assert_eq!(SEEN_MISS, [base as usize as u32, 17, 9]);
        }
    }
}
