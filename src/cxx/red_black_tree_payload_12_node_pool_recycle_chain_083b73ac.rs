//! Red-black-tree payload-12 node-pool recycle chain — retailOS
//! `FUN_083b73ac` at load address `0x083b73ac`.
//!
//! Load address: `0x083b73ac`; true size: 68 bytes (`0x44`), from
//! `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}` at `0x083b73ec`.
//! `0x083b73f0` begins the next real function. Raw A32 decoding verifies two
//! outgoing unconditional plain `bl` calls (the recursive call at `0x083b73c4`
//! and `string_object_destroy` @ `0x08277484` at `0x083b73d8`) and zero
//! predicated `bl` calls.
//!
//! Recursively drains a node chain through each node's `+0x0c` right link, then
//! prepends every node to `pool+0x04` through that same link. Before a node is
//! returned to the free list, it destroys the embedded StringObject at `+0x10`.
//! Recursion visits the tail first, preserving incoming-chain order in the free
//! list.
//!
//! Deliberate deviations: named target-word indices replace retail's
//! callee-saved-register shuffling while retaining recursive order, destruction
//! order, and every target-width load and store.

use crate::cxx::string_object::{string_object_destroy, StringObject};

const POOL_FREE: usize = 1;
const NODE_RIGHT: usize = 3;
const NODE_STRING: usize = 4;

/// Recycles a right-linked chain of 28-byte red-black-tree nodes onto `pool`.
///
/// # Safety
///
/// `pool` must have a writable free-list word at `+0x04`. `chain` must be NULL
/// or a finite writable chain with target-pointer right links at `+0x0c` and
/// valid StringObjects at `+0x10`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_payload_12_node_pool_recycle_chain_083b73ac")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_12_node_pool_recycle_chain_083b73ac(
    pool: *mut u32,
    chain: *mut u32,
) {
    if chain.is_null() {
        return;
    }

    unsafe { red_black_tree_payload_12_node_pool_recycle_chain_083b73ac(pool, chain.add(NODE_RIGHT).read() as usize as *mut u32) };
    unsafe { chain.add(NODE_RIGHT).write(pool.add(POOL_FREE).read()) };
    unsafe { string_object_destroy(chain.add(NODE_STRING).cast::<StringObject>()) };
    unsafe { pool.add(POOL_FREE).write(chain as usize as u32) };
}

#[cfg(test)]
mod tests {
    use crate::testing::{hints, try_map_u32_slab};

    use super::red_black_tree_payload_12_node_pool_recycle_chain_083b73ac;

    const POOL: usize = 0;
    const FIRST: usize = 8;
    const SECOND: usize = 16;
    const THIRD: usize = 24;
    const EXISTING_FREE: usize = 32;
    const NODE_RIGHT: usize = 3;
    const NODE_STRING: usize = 4;
    const NODE_PAYLOAD_TAIL: usize = 6;

    #[test]
    fn recycles_right_chain_in_input_order_and_destroys_embedded_strings() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_12_NODE_POOL_RECYCLE_CHAIN_083B73AC, 0x1000) else {
            return;
        };
        unsafe {
            let words = slab.cast::<u32>();
            let pool = words.add(POOL);
            let first = words.add(FIRST);
            let second = words.add(SECOND);
            let third = words.add(THIRD);
            let existing_free = words.add(EXISTING_FREE);

            pool.add(1).write(existing_free as usize as u32);
            first.add(NODE_RIGHT).write(second as usize as u32);
            second.add(NODE_RIGHT).write(third as usize as u32);
            third.add(NODE_RIGHT).write(0);
            for node in [first, second, third] {
                node.add(NODE_STRING).write(0xdead_beef);
                node.add(NODE_STRING + 1).write(0);
                node.add(NODE_PAYLOAD_TAIL).write(0);
                node.add(NODE_PAYLOAD_TAIL + 1).write(0);
            }

            red_black_tree_payload_12_node_pool_recycle_chain_083b73ac(pool, first);

            assert_eq!(pool.add(1).read(), first as usize as u32);
            assert_eq!(first.add(NODE_RIGHT).read(), second as usize as u32);
            assert_eq!(second.add(NODE_RIGHT).read(), third as usize as u32);
            assert_eq!(third.add(NODE_RIGHT).read(), existing_free as usize as u32);
            for node in [first, second, third] {
                assert_ne!(node.add(NODE_STRING).read(), 0xdead_beef);
                assert_eq!(node.add(NODE_PAYLOAD_TAIL).read(), 0);
            }
        }
    }

    #[test]
    fn null_chain_leaves_free_list_unchanged() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_12_NODE_POOL_RECYCLE_CHAIN_083B73AC_NULL, 0x1000) else {
            return;
        };
        unsafe {
            let pool = slab.cast::<u32>();
            let existing_free = pool.add(EXISTING_FREE);
            pool.add(1).write(existing_free as usize as u32);

            red_black_tree_payload_12_node_pool_recycle_chain_083b73ac(pool, core::ptr::null_mut());

            assert_eq!(pool.add(1).read(), existing_free as usize as u32);
        }
    }
}
