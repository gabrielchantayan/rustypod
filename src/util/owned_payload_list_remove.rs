//! Remove the first keyed node and its owned payload.
//!
//! `FUN_081e6c94` @ 0x081e6c94: true extent [0x081e6c94,0x081e6d58),
//! 196 bytes, ending before the next independent push. Whole-image raw A32
//! decoding verifies two inbound plain BLs (0x08106cb8, 0x08106cc4), zero
//! predicated inbound BLs; three outbound plain BLs and one BLNE.
//!
//! Walk the +0x14 links comparing +4 with the key. On the first match,
//! either free +0 with tag 0x37, or clear the optional +0x10 array's
//! construction byte, free its nonzero raw allocation with tag 3, and
//! delete its descriptor. Unlink and delete the node; return 1. A miss
//! returns 0 without changing the list. Ghidra's noreturn delete annotation
//! hides this successful return and truncates the extent.
//!
//! Deliberate deviation: omit the side-effect-free count-sized trivial
//! element destruction loop. All pointer fields remain target-width words;
//! heap calls reuse the existing ported veneers, not new firmware seams.

use crate::heap::veneers::{free_wrapper, operator_delete};

/// # Safety
/// `head` must be writable; its chain must contain readable, writable,
/// aligned six-word nodes. Owned payloads must satisfy the heap veneers'
/// allocation contract; array descriptors must contain four writable words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_payload_list_remove(head: *mut u32, key: u32) -> u32 {
    let mut node = head.read() as usize as *mut u32;
    let mut previous: *mut u32 = core::ptr::null_mut();
    while !node.is_null() {
        if node.add(1).read() == key {
            if node.cast::<u8>().add(12).read() == 0 {
                free_wrapper(node.read() as usize as *mut u8, 0x37);
            } else {
                let array = node.add(4).read() as usize as *mut u32;
                if !array.is_null() {
                    array.cast::<u8>().add(12).write(0);
                    let allocation = array.read() as usize as *mut u8;
                    if !allocation.is_null() {
                        free_wrapper(allocation, 3);
                    }
                    operator_delete(array.cast());
                }
            }
            let next = node.add(5).read();
            if previous.is_null() {
                head.write(next);
            } else {
                previous.add(5).write(next);
            }
            operator_delete(node.cast());
            return 1;
        }
        previous = node;
        node = node.add(5).read() as usize as *mut u32;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OWNED_PAYLOAD_LIST_REMOVE, 0x1000)
            .map(|pointer| pointer as usize)
    });

    #[test]
    fn removes_first_match_at_each_position_and_preserves_misses() {
        let _lock = mock_heap();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("util/owned_payload_list_remove"));
            return;
        };
        unsafe {
            let head = base as *mut u32;
            let nodes = [head.add(8), head.add(16), head.add(24)];
            head.write(0);
            assert_eq!(owned_payload_list_remove(head, 7), 0);
            assert_eq!(free_log().0, 0);
            for position in 0..3 {
                for (i, &node) in nodes.iter().enumerate() {
                    node.write(0);
                    node.add(1).write(if i >= position { 7 } else { 9 });
                    node.add(2).write(0x12345678);
                    node.add(3).write(0);
                    node.add(4).write(0);
                    node.add(5).write(if i == 2 { 0 } else { nodes[i + 1] as usize as u32 });
                }
                head.write(nodes[0] as usize as u32);
                let before = free_log().0;
                assert_eq!(owned_payload_list_remove(head, 99), 0);
                assert_eq!(free_log().0, before);
                assert_eq!(head.read(), nodes[0] as usize as u32);
                assert_eq!(owned_payload_list_remove(head, 7), 1);
                let next = if position == 2 { 0 } else { nodes[position + 1] as usize as u32 };
                let link = if position == 0 { head } else { nodes[position - 1].add(5) };
                assert_eq!(link.read(), next);
                assert_eq!(free_log(), (before + 2, nodes[position].cast(), 2));
                assert_eq!(nodes[position].add(2).read(), 0x12345678);
                if position < 2 {
                    assert_eq!(nodes[position + 1].add(1).read(), 7);
                }
            }
        }
    }

    #[test]
    fn array_cleanup_handles_null_descriptor_allocation_and_construction_states() {
        let _lock = mock_heap();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("util/owned_payload_list_remove"));
            return;
        };
        unsafe {
            let head = base as *mut u32;
            let node = head.add(8);
            let array = head.add(32);
            for descriptor in [false, true] {
                for allocation in [0u32, base as u32 + 256] {
                    for constructed in [0u32, 0xaabbccff] {
                        head.write(node as usize as u32);
                        node.write(0xdeadbeef);
                        node.add(1).write(42);
                        node.add(3).write(1);
                        node.add(4).write(if descriptor { array as usize as u32 } else { 0 });
                        node.add(5).write(0);
                        array.write(allocation);
                        array.add(1).write(0x11223344);
                        array.add(2).write(u32::MAX);
                        array.add(3).write(constructed);
                        let before = free_log().0;
                        assert_eq!(owned_payload_list_remove(head, 42), 1);
                        assert_eq!(head.read(), 0);
                        let calls = 1 + usize::from(descriptor) + usize::from(descriptor && allocation != 0);
                        assert_eq!(free_log(), (before + calls, node.cast(), 2));
                        assert_eq!(array.read(), allocation);
                        assert_eq!(array.add(1).read(), 0x11223344);
                        assert_eq!(array.add(2).read(), u32::MAX);
                        assert_eq!(array.add(3).read(), if descriptor { constructed & !0xff } else { constructed });
                    }
                }
            }
        }
    }
}
