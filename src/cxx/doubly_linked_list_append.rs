//! Append a node to a doubly linked list.
//!
//! `doubly_linked_list_append` — original: `FUN_0804caa8` @ `0x0804caa8`
//! (32 bytes; eight ARM words). Raw `osos.dec` establishes the exact extent
//! `0x0804caa8..0x0804cac8`; `0x0804cac8` begins the next independently
//! entered function with `push {r4-r11,lr}`. The body contains no calls.
//! Whole-image A32 decoding finds three inbound plain `bl` calls
//! (`0x0804c08c`, `0x0804d688`, and `0x0804d8dc`) and no predicated `bl`
//! calls.
//!
//! Algorithm: save the current tail as the new node's previous link, clear its
//! next link, install it as the head when the list was empty or as the old
//! tail's next link otherwise, then install it as the tail. Deliberate
//! deviation: none; `#[repr(C)]` preserves the target's adjacent pointer-word
//! fields on ARM while retaining valid native pointers in host tests.

/// Target-layout list header: head then tail.
#[repr(C)]
pub struct DoublyLinkedList {
    pub head: *mut DoublyLinkedListNode,
    pub tail: *mut DoublyLinkedListNode,
}

/// Prefix shared by nodes that can be linked into [`DoublyLinkedList`].
#[repr(C)]
pub struct DoublyLinkedListNode {
    pub previous: *mut DoublyLinkedListNode,
    pub next: *mut DoublyLinkedListNode,
}

/// Appends `node` to `list`. Neither pointer is NULL-checked by retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn doubly_linked_list_append(
    list: *mut DoublyLinkedList,
    node: *mut DoublyLinkedListNode,
) {
    let previous_tail = unsafe { (*list).tail };
    unsafe {
        (*node).previous = previous_tail;
        (*node).next = core::ptr::null_mut();
        if previous_tail.is_null() {
            (*list).head = node;
        } else {
            (*previous_tail).next = node;
        }
        (*list).tail = node;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appending_to_empty_list_initializes_both_header_links() {
        let mut list = DoublyLinkedList {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
        };
        let mut stale_link = DoublyLinkedListNode {
            previous: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
        };
        let mut node = DoublyLinkedListNode {
            previous: &mut stale_link,
            next: &mut stale_link,
        };

        unsafe { doubly_linked_list_append(&mut list, &mut node) };

        assert!(core::ptr::eq(list.head, &mut node));
        assert!(core::ptr::eq(list.tail, &mut node));
        assert!(node.previous.is_null());
        assert!(node.next.is_null());
    }

    #[test]
    fn appending_relinks_tail_and_discards_stale_node_next_link() {
        let mut first = DoublyLinkedListNode {
            previous: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
        };
        let mut stale_next = DoublyLinkedListNode {
            previous: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
        };
        let mut node = DoublyLinkedListNode {
            previous: core::ptr::null_mut(),
            next: &mut stale_next,
        };
        let mut list = DoublyLinkedList {
            head: &mut first,
            tail: &mut first,
        };

        unsafe { doubly_linked_list_append(&mut list, &mut node) };

        assert!(core::ptr::eq(list.head, &mut first));
        assert!(core::ptr::eq(list.tail, &mut node));
        assert!(core::ptr::eq(first.next, &mut node));
        assert!(core::ptr::eq(node.previous, &mut first));
        assert!(node.next.is_null());
    }
}
