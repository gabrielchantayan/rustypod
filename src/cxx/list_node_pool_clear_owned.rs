//! Owned-payload intrusive-list clear — original: `FUN_083dc1d8` at load
//! address `0x083dc1d8`.
//!
//! Raw `osos.dec` establishes the exact 116-byte extent: 29 A32 words from
//! `push {r4,r5,r6,lr}` at `0x083dc1d8` through `pop {r4,r5,r6,pc}` at
//! `0x083dc248`; `0x083dc24c` begins the separately linked
//! [`list_node_pool_erase_owned`] routine. Decoding every aligned A32
//! BL-immediate word in the body finds one unconditional plain `bl` at
//! `0x083dc214`, to that routine, and zero predicated `bl` instructions.
//! Whole-image A32 decoding finds two unconditional inbound `bl` sites at
//! `0x08132e50` and `0x08134080`, with no predicated inbound calls.
//!
//! The routine walks the ring from `sentinel.next`, erasing each non-sentinel
//! node. Erasure returns the successor before recycling the node, so the
//! traversal remains valid while draining the list.
//!
//! Deliberate deviation: the retail stack temporaries used to pass the current
//! node and successor to the eraser become Rust locals; they have no observable
//! effect after return.

use crate::cxx::list_node_pool_erase_owned::{list_node_pool_erase_owned, OwnedListHeader};

/// Removes every live node from an owned-payload list, releasing each payload
/// and returning nodes to the list's pool free chain.
///
/// Original: `FUN_083dc1d8` at load address `0x083dc1d8` (116 bytes; two
/// unconditional inbound `bl` sites, one unconditional internal `bl`, no
/// predicated `bl`).
///
/// # Safety
///
/// `header` must be a valid [`OwnedListHeader`] whose sentinel and live nodes
/// form a valid intrusive ring. Each node payload must satisfy
/// [`list_node_pool_erase_owned`]'s release contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_clear_owned")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_clear_owned(header: *mut OwnedListHeader) {
    let sentinel = (*header).sentinel;
    let mut current = (sentinel as usize as *const u32).read();
    while current != sentinel {
        let mut successor = 0;
        list_node_pool_erase_owned(&mut successor, header, &mut current);
        current = successor;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::list_node_pool_acquire::{ListNode, ListNodePool};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    const SENTINEL: usize = 0x1000;
    const NODE_A: usize = 0x2000;
    const NODE_B: usize = 0x2400;
    const NODE_C: usize = 0x2800;

    unsafe fn word(base: *mut u8, offset: usize) -> u32 {
        base.add(offset) as usize as u32
    }

    unsafe fn node(base: *mut u8, offset: usize) -> *mut ListNode {
        base.add(offset).cast()
    }

    unsafe fn initialize_ring(base: *mut u8, header: *mut OwnedListHeader) {
        let sentinel = word(base, SENTINEL);
        let a = word(base, NODE_A);
        let b = word(base, NODE_B);
        let c = word(base, NODE_C);
        ptr::write(node(base, SENTINEL), ListNode { next: a, prev: c, payload: [0; 3] });
        ptr::write(node(base, NODE_A), ListNode { next: b, prev: sentinel, payload: [0; 3] });
        ptr::write(node(base, NODE_B), ListNode { next: c, prev: a, payload: [0; 3] });
        ptr::write(node(base, NODE_C), ListNode { next: sentinel, prev: b, payload: [0; 3] });
        ptr::write(header, OwnedListHeader { pool: ListNodePool::default(), sentinel, count: 3 });
    }

    #[test]
    fn clear_owned_drains_ring_and_preserves_empty_list() {
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_CLEAR_OWNED, 0x8000) else {
            note_missing_u32_fixture("cxx/list_node_pool_clear_owned");
            return;
        };

        unsafe {
            let header = slab.cast::<OwnedListHeader>();
            initialize_ring(slab, header);
            list_node_pool_clear_owned(header);

            assert_eq!((*header).count, 0);
            assert_eq!((*node(slab, SENTINEL)).next, word(slab, SENTINEL));
            assert_eq!((*node(slab, SENTINEL)).prev, word(slab, SENTINEL));
            assert_eq!((*header).pool.free, word(slab, NODE_C));
            assert_eq!((*node(slab, NODE_C)).next, word(slab, NODE_B));
            assert_eq!((*node(slab, NODE_B)).next, word(slab, NODE_A));
            assert_eq!((*node(slab, NODE_A)).next, 0);

            // The sentinel case never calls the eraser and has no side effects.
            let free = (*header).pool.free;
            list_node_pool_clear_owned(header);
            assert_eq!((*header).count, 0);
            assert_eq!((*header).pool.free, free);
        }
    }
}
