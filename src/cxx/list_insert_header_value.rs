//! Wrapper around the ported list-node insertion member.

use crate::cxx::list_node_pool_insert_refcounted::list_node_pool_insert_refcounted;

/// list_insert_header_value — original: `FUN_083dc0f8` @ 0x083dc0f8
/// (40 bytes; raw extent `0x083dc0f8..0x083dc120`, bounded by the next
/// separately linked `push {r4,r5,r6,r7,lr}` entry). Exactly three inbound
/// direct calls are unconditional plain `bl`; there are no predicated calls.
///
/// The wrapper loads the target node word through `list + 0x10`, materializes
/// it in a stack local, and calls the ported list-node insertion with that
/// local, `list`, and `value`. Its fourth ABI argument only initializes the
/// stack output slot that the callee overwrites; the wrapper discards it.
///
/// # Safety
///
/// `list` must point to at least five readable target words, and its word at
/// +0x10 must be a valid aligned pointer to a readable node word. The
/// firmware callee's additional allocation and list invariants apply.
type ListNodeInsertFn = unsafe extern "C" fn(*mut u32, *mut u32, *const u32, *const u32);

#[inline(always)]
unsafe fn list_insert_header_value_with(
    insert: ListNodeInsertFn,
    list: *mut u32,
    value: u32,
    discarded_output_seed: u32,
) {
    let node = *((*list.add(4)) as *const u32);
    let mut discarded_output = discarded_output_seed;
    insert(&mut discarded_output, list, &node, &value);
}
#[inline(never)]
pub unsafe extern "C" fn list_insert_header_value(
    list: *mut u32,
    value: u32,
    _unused: u32,
    discarded_output_seed: u32,
) {
    list_insert_header_value_with(list_node_pool_insert_refcounted, list, value, discarded_output_seed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: (usize, usize, u32, u32) = (0, 0, 0, 0);

    unsafe extern "C" fn record_insert(output: *mut u32, list: *mut u32, node: *const u32, payload: *const u32) {
        CALL = (list as usize, node as usize, *node, *payload);
        *output = 0xfeed_beef;
    }

    #[test]
    fn loads_the_header_node_word_and_discards_the_output_seed() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_INSERT_HEADER_VALUE, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/list_insert_header_value"));
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let list = slab.cast::<u32>();
            let node_slot = list.add(8);
            *node_slot = 0x1357_9bdf;
            *list.add(4) = node_slot as usize as u32;
            CALL = (0, 0, 0, 0);
            list_insert_header_value_with(record_insert, list, 0x2468_ace0, 0xaaaa_5555);
            assert_eq!(CALL.0, list as usize);
            assert_ne!(CALL.1, node_slot as usize);
            assert_eq!(CALL.2, 0x1357_9bdf);
            assert_eq!(CALL.3, 0x2468_ace0);
        }
    }
}
