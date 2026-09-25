//! FreeType `ftlist.c` — the doubly-linked list primitives shared by the
//! module, service, and driver registries. This file currently ports the
//! search primitive only.

use core::ptr;

/// `FT_ListNodeRec` — the node the original walks. On ARM it is 12
/// bytes: `prev` @ +0, `next` @ +4, `data` @ +8. `ft_list_find` touches
/// only `next` and `data`.
#[repr(C)]
pub struct FtListNode {
    pub prev: *mut FtListNode,
    pub next: *mut FtListNode,
    pub data: *mut core::ffi::c_void,
}

/// `FT_ListRec`'s head word. The original takes `FT_List` (a pointer to
/// the record) and dereferences it once for `list->head`; the rest of the
/// record (`tail` @ +4) is not read here.
#[repr(C)]
pub struct FtList {
    pub head: *mut FtListNode,
    pub tail: *mut FtListNode,
}

/// `ft_list_find` — original: `FUN_0804cb24` @ **0x0804cb24** (40 bytes
/// exactly, `0x0804cb24..0x0804cb4c`; the distinct next function,
/// `FT_List_Remove`, starts at `0x0804cb4c`). Ghidra's 40-byte extent is
/// correct here.
///
/// Decoding every ARM BL word in `osos.dec` verifies **5 direct inbound
/// call sites**, all unconditional plain `bl` (cond 0xe): 0x0804c384,
/// 0x0804c46c, 0x0804ecf0, 0x08080ec8, and 0x080868cc. There are no
/// predicated BL forms and no inbound tail `b` branches.
///
/// Upstream `FT_List_Find( FT_List list, void* data )` from
/// `src/base/ftlist.c`: load `list->head`, walk `node->next`, return the
/// first node whose `node->data` equals `data`, else NULL. The raw body
/// is exactly that loop: `ldr r0,[r0]` (head), `ldr r2,[r0,#8]` /
/// `cmp r2,r1` / `bxeq lr` (data match), `ldr r0,[r0,#4]` (next), NULL
/// test, `mov r0,#0; bx lr` on exhaustion.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `list` must be non-NULL and point at a valid `FT_ListRec` head word;
/// every reachable node must be a valid, non-NULL-terminated chain of
/// `FtListNode`. The original does not guard against a NULL `list`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ft_list_find")]
#[inline(never)]
pub unsafe extern "C" fn ft_list_find(
    list: *const FtList,
    data: *mut core::ffi::c_void,
) -> *mut FtListNode {
    let mut node = ptr::read_volatile(ptr::addr_of!((*list).head));
    while !node.is_null() {
        if ptr::read_volatile(ptr::addr_of!((*node).data)) == data {
            return node;
        }
        node = ptr::read_volatile(ptr::addr_of!((*node).next));
    }
    ptr::null_mut()
}

/// `ft_list_remove` — original: `FUN_0804cb4c` @ **0x0804cb4c** (36 bytes
/// exactly, `0x0804cb4c..0x0804cb70`; `0x0804cb70` begins the next distinct
/// function). Raw `osos.dec` words decode to two conditional link updates
/// followed by `bx lr`; Ghidra's extent is exact.
///
/// Every ARM BL-immediate in the firmware gives **3 direct inbound call
/// sites**, all unconditional plain `bl` (cond 0xe): 0x0804c398, 0x0804c484,
/// and 0x080868f8. There are no predicated inbound BL forms. This leaf has
/// no outgoing calls.
///
/// FreeType `FT_List_Remove` from `src/base/ftlist.c`: splice `node` out of
/// `list` by replacing either `node->prev->next` or `list->head` with
/// `node->next`, then replacing either `node->next->prev` or `list->tail`
/// with `node->prev`. The node's own links remain unchanged.
///
/// Deliberate deviations: host pointer fields are wider than the target's
/// four-byte fields; `repr(C)` preserves the field order used by the
/// algorithm, while tests validate observable list-link behavior.
///
/// # Safety
///
/// `list` and `node` must be valid, non-NULL pointers. Any non-NULL adjacent
/// nodes must be writable `FtListNode` values. The original makes no checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ft_list_remove")]
#[inline(never)]
pub unsafe extern "C" fn ft_list_remove(list: *mut FtList, node: *mut FtListNode) {
    let prev = ptr::read_volatile(ptr::addr_of!((*node).prev));
    let next = ptr::read_volatile(ptr::addr_of!((*node).next));

    if prev.is_null() {
        ptr::write_volatile(ptr::addr_of_mut!((*list).head), next);
    } else {
        ptr::write_volatile(ptr::addr_of_mut!((*prev).next), next);
    }

    if next.is_null() {
        ptr::write_volatile(ptr::addr_of_mut!((*list).tail), prev);
    } else {
        ptr::write_volatile(ptr::addr_of_mut!((*next).prev), prev);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    fn node(data: *mut core::ffi::c_void) -> FtListNode {
        FtListNode { prev: ptr::null_mut(), next: ptr::null_mut(), data }
    }

    fn chain(nodes: &mut [FtListNode]) {
        for i in 0..nodes.len() - 1 {
            nodes[i].next = &mut nodes[i + 1] as *mut FtListNode;
            nodes[i + 1].prev = &mut nodes[i] as *mut FtListNode;
        }
    }

    fn list_of(head: *mut FtListNode) -> FtList {
        FtList { head, tail: ptr::null_mut() }
    }

    #[test]
    fn finds_first_matching_node() {
        let mut a = 0x11u32;
        let mut b = 0x22u32;
        let mut nodes = [
            node(&mut a as *mut u32 as *mut _),
            node(&mut b as *mut u32 as *mut _),
            node(&mut b as *mut u32 as *mut _),
        ];
        chain(&mut nodes);
        let list = list_of(&mut nodes[0]);

        let found = unsafe { ft_list_find(&list, &mut b as *mut u32 as *mut _) };
        assert_eq!(found, &mut nodes[1] as *mut FtListNode);
    }

    #[test]
    fn returns_null_on_miss_and_on_empty_list() {
        let mut a = 0x11u32;
        let key = 0x99u32;
        let mut nodes = [node(&mut a as *mut u32 as *mut _)];
        let list = list_of(&mut nodes[0]);
        let key_ptr = &key as *const u32 as *mut core::ffi::c_void;
        assert!(unsafe { ft_list_find(&list, key_ptr) }.is_null());

        let empty = list_of(ptr::null_mut());
        assert!(unsafe { ft_list_find(&empty, key_ptr) }.is_null());
    }

    #[test]
    fn matches_head_node_immediately() {
        let mut a = 0x11u32;
        let key = &mut a as *mut u32 as *mut core::ffi::c_void;
        let mut nodes = [node(key), node(ptr::null_mut())];
        chain(&mut nodes);
        let list = list_of(&mut nodes[0]);
        assert_eq!(unsafe { ft_list_find(&list, key) }, &mut nodes[0] as *mut FtListNode);
    }

    #[test]
    fn matches_last_node_after_walking_the_chain() {
        let key = 0xdead_beefusize as *mut core::ffi::c_void;
        let mut nodes = [node(ptr::null_mut()), node(ptr::null_mut()), node(key)];
        chain(&mut nodes);
        let list = list_of(&mut nodes[0]);
        assert_eq!(unsafe { ft_list_find(&list, key) }, &mut nodes[2] as *mut FtListNode);
    }

    #[test]
    fn null_data_matches_a_node_with_null_data() {
        let mut nodes = [node(1usize as *mut _), node(ptr::null_mut())];
        chain(&mut nodes);
        let list = list_of(&mut nodes[0]);
        assert_eq!(
            unsafe { ft_list_find(&list, ptr::null_mut()) },
            &mut nodes[1] as *mut FtListNode
        );
    }

    fn linked_list(nodes: &mut [FtListNode]) -> FtList {
        chain(nodes);
        FtList {
            head: &mut nodes[0],
            tail: &mut nodes[nodes.len() - 1],
        }
    }

    #[test]
    fn removes_head_and_updates_the_new_head_prev_link() {
        let mut nodes = [node(ptr::null_mut()), node(ptr::null_mut()), node(ptr::null_mut())];
        let mut list = linked_list(&mut nodes);
        let first = nodes.as_mut_ptr();
        let middle = first.wrapping_add(1);
        let last = first.wrapping_add(2);
        let removed_prev = nodes[0].prev;
        let removed_next = nodes[0].next;

        unsafe { ft_list_remove(&mut list, &mut nodes[0]) };

        assert_eq!(list.head, middle);
        assert_eq!(list.tail, last);
        assert!(nodes[1].prev.is_null());
        assert_eq!(nodes[0].prev, removed_prev);
        assert_eq!(nodes[0].next, removed_next);
    }

    #[test]
    fn removes_middle_and_splices_neighbors() {
        let mut nodes = [node(ptr::null_mut()), node(ptr::null_mut()), node(ptr::null_mut())];
        let mut list = linked_list(&mut nodes);
        let first = nodes.as_mut_ptr();
        let last = first.wrapping_add(2);
        let removed_prev = nodes[1].prev;
        let removed_next = nodes[1].next;

        unsafe { ft_list_remove(&mut list, &mut nodes[1]) };

        assert_eq!(list.head, first);
        assert_eq!(list.tail, last);
        assert_eq!(nodes[0].next, last);
        assert_eq!(nodes[2].prev, first);
        assert_eq!(nodes[1].prev, removed_prev);
        assert_eq!(nodes[1].next, removed_next);
    }

    #[test]
    fn removes_tail_and_singleton() {
        let mut nodes = [node(ptr::null_mut()), node(ptr::null_mut())];
        let mut list = linked_list(&mut nodes);
        let first = nodes.as_mut_ptr();

        unsafe { ft_list_remove(&mut list, &mut nodes[1]) };

        assert_eq!(list.head, first);
        assert_eq!(list.tail, first);
        assert!(nodes[0].next.is_null());

        let mut only = [node(ptr::null_mut())];
        let mut singleton = linked_list(&mut only);
        unsafe { ft_list_remove(&mut singleton, &mut only[0]) };
        assert!(singleton.head.is_null());
        assert!(singleton.tail.is_null());
    }
}
