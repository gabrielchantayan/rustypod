//! `object_list_pop_front` — `FUN_081f18c0` at **0x081f18c0**.
//! True extent: **44 bytes**, `0x081f18c0..0x081f18ec`; the next function
//! starts with `stmdb sp!, {r4, lr}`. Raw A32 decoding verifies two inbound
//! plain BLs (0x081f1974 and 0x081f1a08), zero predicated inbound BLs,
//! and zero outbound plain or predicated BLs.
//!
//! Reads the object's head at +8. An empty list returns null without writing
//! anything, including a stale tail. Otherwise returns the old head, replaces
//! it with the node's next word at +4, and clears tail +12 only if that next
//! word is zero. The removed node's link remains intact. Callers use the
//! returned polymorphic node for result extraction or virtual destruction.
//!
//! Deliberate deviations: none; pointer fields remain target-width u32 words.

#[repr(C)]
pub struct ObjectList {
    pub vtable: u32,
    pub owner: u32,
    pub head: u32,
    pub tail: u32,
}

#[repr(C)]
pub struct ObjectListNode {
    pub vtable: u32,
    pub next: u32,
}

/// Removes the first node without destroying it or clearing its link.
///
/// # Safety
/// `list` must point to a writable target-layout object. A nonzero head must
/// address a readable, aligned `ObjectListNode`. Access must be exclusive.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_list_pop_front(list: *mut ObjectList) -> *mut ObjectListNode {
    unsafe {
        let head = (*list).head;
        if head == 0 {
            return core::ptr::null_mut();
        }
        let node = head as usize as *mut ObjectListNode;
        let next = (*node).next;
        (*list).head = next;
        if next == 0 {
            (*list).tail = 0;
        }
        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn empty_singleton_and_chain_match_word_reference() {
        let Some(slab) = try_map_u32_slab(hints::OBJECT_LIST_POP_FRONT, 0x1000) else {
            return;
        };
        unsafe {
            let first = slab.add(0x100).cast::<ObjectListNode>();
            let second = slab.add(0x200).cast::<ObjectListNode>();
            let first_addr = first as usize as u32;
            let second_addr = second as usize as u32;
            for (head, tail, next) in [
                (0, 0, 0),
                (0, 0xdead_beef, 0),
                (first_addr, first_addr, 0),
                (first_addr, second_addr, second_addr),
            ] {
                first.write(ObjectListNode { vtable: 0x1234_5678, next });
                second.write(ObjectListNode { vtable: 0x8765_4321, next: 0 });
                let mut list = ObjectList { vtable: 0x1111_1111, owner: 0x2222_2222, head, tail };
                let mut expected = [list.vtable, list.owner, head, tail];
                // Independent reference to the firmware's four-word layout.
                if expected[2] != 0 {
                    expected[2] = (expected[2] as usize as *const u32).add(1).read();
                    if expected[2] == 0 { expected[3] = 0; }
                }
                assert_eq!(object_list_pop_front(&mut list) as usize as u32, head);
                assert_eq!([list.vtable, list.owner, list.head, list.tail], expected);
                assert_eq!((*first).vtable, 0x1234_5678);
                assert_eq!((*first).next, next);
                assert_eq!((*second).vtable, 0x8765_4321);
                assert_eq!((*second).next, 0);
                if next != 0 {
                    assert_eq!(object_list_pop_front(&mut list), second);
                    assert_eq!((list.head, list.tail), (0, 0));
                    assert!(object_list_pop_front(&mut list).is_null());
                }
            }
        }
    }
}
