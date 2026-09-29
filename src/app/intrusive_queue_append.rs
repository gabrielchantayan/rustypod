//! `intrusive_queue_append` — original: `FUN_082d7fdc` @ **0x082d7fdc**
//! (**64 bytes**, `0x082d7fdc..0x082d801c`; the next separately linked
//! function begins with `push {lr}` at `0x082d801c`). Raw A32 decoding finds
//! two inbound direct calls, one plain `bl` and one predicated `bleq`; there
//! are no outbound BL instructions.
//!
//! Appends a node whose intrusive two-word link can occur at any offset in the
//! node, preserving target-width four-byte pointers. It clears the new link's
//! next word, records the old tail in its second word, repairs the old tail's
//! next link when present, then installs the new tail. If the queue's deferred
//! node slot is empty and byte +0x1e of the node is clear, it also selects this
//! node for deferred processing.
//!
//! Deliberate deviations: none.

/// Target-width queue anchor at offsets +0x00, +0x04, and +0x08.
#[repr(C)]
pub struct IntrusiveQueue {
    pub head: u32,
    pub tail: u32,
    pub deferred_node: u32,
}

/// Target-width two-word node link. The caller supplies its actual location
/// because retail nodes place this link at differing offsets.
#[repr(C)]
pub struct IntrusiveQueueLink {
    pub next: u32,
    pub previous: u32,
}

/// Appends `node` to `queue` through its link at `node_link`.
///
/// # Safety
///
/// `queue`, `node`, and `node_link` must be writable target-layout objects;
/// `node_link` must lie within `node`. When `queue.tail` is nonzero, it must
/// name a writable node with a link at the same offset as `node_link`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn intrusive_queue_append(
    queue: *mut IntrusiveQueue,
    node_link: *mut IntrusiveQueueLink,
    node: *mut u8,
) {
    unsafe {
        (*node_link).next = 0;
        let old_tail = (*queue).tail;
        (*node_link).previous = old_tail;
        if old_tail == 0 {
            (*queue).head = node as usize as u32;
        } else {
            let link_offset = node_link.cast::<u8>().offset_from(node) as usize;
            let old_tail_link = (old_tail as usize as *mut u8)
                .add(link_offset)
                .cast::<IntrusiveQueueLink>();
            (*old_tail_link).next = node as usize as u32;
        }
        (*queue).tail = node as usize as u32;
        if (*queue).deferred_node == 0 && node.add(0x1e).read() == 0 {
            (*queue).deferred_node = node as usize as u32;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const FIRST_OFFSET: usize = 0x100;
    const SECOND_OFFSET: usize = 0x200;
    const LINK_OFFSET: usize = 0x10;

    unsafe fn reset(slab: *mut u8) {
        unsafe { core::ptr::write_bytes(slab, 0, SLAB_LEN) };
    }

    #[test]
    fn append_empty_queue_sets_anchor_links_and_deferred_node() {
        let Some(slab) = try_map_u32_slab(hints::INTRUSIVE_QUEUE_APPEND_EMPTY, SLAB_LEN) else {
            return;
        };
        unsafe {
            reset(slab);
            let queue = slab.cast::<IntrusiveQueue>();
            let node = slab.add(FIRST_OFFSET);
            let link = node.add(LINK_OFFSET).cast::<IntrusiveQueueLink>();
            intrusive_queue_append(queue, link, node);

            assert_eq!((*queue).head, node as usize as u32);
            assert_eq!((*queue).tail, node as usize as u32);
            assert_eq!((*queue).deferred_node, node as usize as u32);
            assert_eq!((*link).next, 0);
            assert_eq!((*link).previous, 0);
        }
    }

    #[test]
    fn append_repairs_tail_and_respects_deferred_selection_conditions() {
        let Some(slab) = try_map_u32_slab(hints::INTRUSIVE_QUEUE_APPEND_CHAIN, SLAB_LEN) else {
            return;
        };
        unsafe {
            reset(slab);
            let queue = slab.cast::<IntrusiveQueue>();
            let first = slab.add(FIRST_OFFSET);
            let second = slab.add(SECOND_OFFSET);
            let first_link = first.add(LINK_OFFSET).cast::<IntrusiveQueueLink>();
            let second_link = second.add(LINK_OFFSET).cast::<IntrusiveQueueLink>();

            intrusive_queue_append(queue, first_link, first);
            (*queue).deferred_node = 0x1234_5678;
            intrusive_queue_append(queue, second_link, second);

            assert_eq!((*queue).head, first as usize as u32);
            assert_eq!((*queue).tail, second as usize as u32);
            assert_eq!((*queue).deferred_node, 0x1234_5678);
            assert_eq!((*first_link).next, second as usize as u32);
            assert_eq!((*second_link).next, 0);
            assert_eq!((*second_link).previous, first as usize as u32);

            reset(slab);
            let queue = slab.cast::<IntrusiveQueue>();
            let node = slab.add(FIRST_OFFSET);
            let link = node.add(LINK_OFFSET).cast::<IntrusiveQueueLink>();
            node.add(0x1e).write(1);
            intrusive_queue_append(queue, link, node);
            assert_eq!((*queue).deferred_node, 0);
        }
    }
}
