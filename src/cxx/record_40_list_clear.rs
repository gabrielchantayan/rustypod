//! Record-40 list clear — `FUN_083dc89c` @ load address `0x083dc89c`.
//!
//! Raw extent [0x083dc89c, 0x083dc968): 204 bytes, ending in pop {r4,r5,pc};
//! the next function is record_40_list_construct. Zero outgoing plain or
//! predicated BLs; one unconditional indirect BLX at 0x083dc91c. Whole-image
//! A32 decoding finds one incoming plain BL at 0x081f15ec, no predicated BLs.
//! Walk from sentinel->next to the captured sentinel. Unlink each node,
//! decrement count, call vtable slot zero on its inline payload, then push
//! it onto the pool free list. Capture the successor before the callback,
//! and reload the free-list head after it. Chunks and sentinel are retained.
//!
//! Deliberate deviations: dead retail stack temporaries are omitted. Links
//! and the payload vtable address remain u32; host vtable entries contain
//! native function pointers rather than four-byte target function pointers.

use super::record_40_list_construct::Record40List;
use super::record_40_list_node_pool_acquire::Record40ListNode;
use core::ptr::addr_of_mut;

type PayloadDestroy = unsafe extern "C" fn(*mut u32);

/// # Safety
/// `list` and its sentinel/ring must be aligned, valid writable target-layout
/// objects. Each live node's payload starts with a valid u32 vtable address,
/// whose first entry accepts the inline payload pointer. Callbacks must leave
/// the captured sentinel and successor chain valid for the remaining traversal.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_40_list_clear(list: *mut Record40List) {
    let end = (*list).sentinel;
    let mut current = (*(end as usize as *mut Record40ListNode)).next;
    while current != end {
        if current == (*list).sentinel {
            current = (*list).sentinel;
            continue;
        }
        let node = current as usize as *mut Record40ListNode;
        let next = (*node).next;
        let previous = (*node).previous;
        (previous as usize as *mut u32).write(next);
        (*(next as usize as *mut Record40ListNode)).previous = previous;
        (*list).count = (*list).count.wrapping_sub(1);
        let payload = addr_of_mut!((*node).payload).cast::<u32>();
        let destroy = (payload.read() as usize as *const PayloadDestroy).read();
        destroy(payload);
        (*node).next = (*list).pool.free;
        (*list).pool.free = current;
        current = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::record_40_list_node_pool_acquire::Record40ListNodePool;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut LIST: *mut Record40List = core::ptr::null_mut();
    static mut CALLS: usize = 0;
    static mut INITIAL_COUNT: u32 = 0;

    unsafe extern "C" fn destroy(payload: *mut u32) {
        let node = payload.sub(2).cast::<Record40ListNode>();
        let id = payload.add(1).read();
        assert_eq!(id as usize, CALLS + 1);
        CALLS += 1;
        assert_eq!((*LIST).count, INITIAL_COUNT.wrapping_sub(CALLS as u32));
        let sentinel = (*LIST).sentinel as usize as *mut Record40ListNode;
        assert_eq!((*sentinel).next, (*node).next);
        assert_eq!((*((*node).next as usize as *mut Record40ListNode)).previous,
            sentinel as usize as u32);
        // Destroy is before recycling, and may change both payload and links.
        assert_ne!((*LIST).pool.free, node as usize as u32);
        if id == 1 {
            (*LIST).pool.free = payload.add(2).read();
        }
        payload.add(1).write(0xded0_0000 | id);
        (*node).next = 0; // traversal must use the saved successor
    }

    #[test]
    fn empty_single_many_and_wrapping_count_preserve_callback_and_recycle_order() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::RECORD_40_LIST_CLEAR, 0x1000) else {
            note_missing_u32_fixture("cxx/record_40_list_clear");
            return;
        };
        unsafe {
            for (length, count) in [(0usize, 0u32), (1, 1), (3, 3), (1, 0)] {
                slab.write_bytes(0xa5, 0x1000);
                let list = slab.cast::<Record40List>();
                let sentinel = slab.add(0x100).cast::<Record40ListNode>();
                let spare = slab.add(0x300) as usize as u32;
                let original_free = slab.add(0x340) as usize as u32;
                let table = slab.add(0x400).cast::<PayloadDestroy>();
                table.write(destroy);
                let word = |index: usize| slab.add(0x100 + index * 48) as usize as u32;
                list.write(Record40List {
                    pool: Record40ListNodePool { chunks: 0x1234, free: original_free,
                        next: 0x5678, end: 0x9abc },
                    sentinel: word(0), count,
                });
                sentinel.write(Record40ListNode { next: if length == 0 { word(0) } else { word(1) },
                    previous: word(length), payload: [0xa5a5_a5a5; 10] });
                for index in 1..=length {
                    let node = word(index) as usize as *mut Record40ListNode;
                    let mut payload = [0xa5a5_a5a5; 10];
                    payload[0] = table as usize as u32;
                    payload[1] = index as u32;
                    payload[2] = spare;
                    node.write(Record40ListNode { next: if index == length { word(0) } else { word(index + 1) },
                        previous: word(index - 1), payload });
                }
                LIST = list;
                CALLS = 0;
                INITIAL_COUNT = count;
                record_40_list_clear(list);
                let calls = CALLS;
                assert_eq!(calls, length);
                assert_eq!((*list).count, count.wrapping_sub(length as u32));
                assert_eq!((*sentinel).next, word(0));
                assert_eq!((*sentinel).previous, word(0));
                assert_eq!((*sentinel).payload, [0xa5a5_a5a5; 10]);
                assert_eq!((*list).pool.free, if length == 0 { original_free } else { word(length) });
                assert_eq!([(*list).pool.chunks, (*list).pool.next, (*list).pool.end], [0x1234, 0x5678, 0x9abc]);
                for index in 1..=length {
                    let node = word(index) as usize as *mut Record40ListNode;
                    assert_eq!((*node).next, if index == 1 { spare } else { word(index - 1) });
                    assert_eq!((*node).payload[1], 0xded0_0000 | index as u32);
                    assert_eq!(&(&(*node).payload)[3..], &[0xa5a5_a5a5; 7]);
                }
                record_40_list_clear(list);
                let calls = CALLS;
                assert_eq!(calls, length);
            }
        }
    }
}
