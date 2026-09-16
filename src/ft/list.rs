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
}
