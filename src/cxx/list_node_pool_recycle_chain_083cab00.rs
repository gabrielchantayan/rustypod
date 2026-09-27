//! `list_node_pool_recycle_chain_083cab00` — retailOS `FUN_083cab00` @
//! `0x083cab00`.
//!
//! Load address: `0x083cab00`; true size: 60 bytes (`0x3c`), from
//! `push {r4,r5,lr}` through `pop {r4,r5,pc}` at `0x083cab38`; the following
//! `push {r2-r9,sl,lr}` at `0x083cab3c` begins the next real function. Raw
//! ARM decoding verifies one outgoing plain `bl` (the recursive call at
//! `0x083cab18`) and zero predicated `bl` instructions. Whole-image decoding
//! finds two inbound unconditional plain `bl` sites (`0x083ca900` and the
//! recursive site), with no predicated inbound calls.
//!
//! Recursively drains the chain through each node's `+0x08` link, then prepends
//! each node to `pool+0x04` through its `+0x0c` free link. Recursion visits the
//! tail first, preserving the incoming chain order in the free list.
//!
//! Deliberate deviation: this separately linked copy uses named word indices
//! instead of the retail callee-saved register shuffling; it retains the
//! recursive order and all target-width loads and stores.

const POOL_FREE: usize = 1;
const NODE_CHAIN_NEXT: usize = 2;
const NODE_FREE_NEXT: usize = 3;

/// Recycles a chain of 16-byte nodes onto a target-width node pool free list.
///
/// # Safety
///
/// `pool` must point to a writable owner with its free-list word at `+0x04`.
/// `chain` must be NULL or a finite writable chain whose next links are u32
/// target pointers at `+0x08` and whose free links at `+0x0c` are writable.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_recycle_chain_083cab00")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_recycle_chain_083cab00(pool: *mut u32, chain: *mut u32) {
    if chain.is_null() {
        return;
    }

    unsafe { list_node_pool_recycle_chain_083cab00(pool, chain.add(NODE_CHAIN_NEXT).read() as usize as *mut u32) };
    unsafe { chain.add(NODE_FREE_NEXT).write(pool.add(POOL_FREE).read()) };
    unsafe { pool.add(POOL_FREE).write(chain as usize as u32) };
}

#[cfg(test)]
mod tests {
    use crate::testing::{hints, try_map_u32_slab};

    use super::{list_node_pool_recycle_chain_083cab00, NODE_CHAIN_NEXT, NODE_FREE_NEXT, POOL_FREE};

    #[test]
    fn recycles_chain_in_input_order_ahead_of_existing_free_nodes() {
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_RECYCLE_CHAIN_083CAB00, 0x1000) else {
            return;
        };
        unsafe {
            let pool = slab.cast::<u32>();
            let first = pool.add(4);
            let second = pool.add(8);
            let third = pool.add(12);
            let existing_free = pool.add(16);

            pool.add(POOL_FREE).write(existing_free as usize as u32);
            first.add(NODE_CHAIN_NEXT).write(second as usize as u32);
            second.add(NODE_CHAIN_NEXT).write(third as usize as u32);
            third.add(NODE_CHAIN_NEXT).write(0);
            first.add(NODE_FREE_NEXT).write(0xaaaa_aaaa);
            second.add(NODE_FREE_NEXT).write(0xbbbb_bbbb);
            third.add(NODE_FREE_NEXT).write(0xcccc_cccc);

            list_node_pool_recycle_chain_083cab00(pool, first);

            assert_eq!(pool.add(POOL_FREE).read(), first as usize as u32);
            assert_eq!(first.add(NODE_FREE_NEXT).read(), second as usize as u32);
            assert_eq!(second.add(NODE_FREE_NEXT).read(), third as usize as u32);
            assert_eq!(third.add(NODE_FREE_NEXT).read(), existing_free as usize as u32);
            assert_eq!(first.add(NODE_CHAIN_NEXT).read(), second as usize as u32);
            assert_eq!(second.add(NODE_CHAIN_NEXT).read(), third as usize as u32);
        }
    }

    #[test]
    fn null_chain_leaves_existing_free_list_unchanged() {
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_RECYCLE_CHAIN_083CAB00_NULL, 0x1000) else {
            return;
        };
        unsafe {
            let pool = slab.cast::<u32>();
            let existing_free = pool.add(16);
            pool.add(POOL_FREE).write(existing_free as usize as u32);

            list_node_pool_recycle_chain_083cab00(pool, core::ptr::null_mut());

            assert_eq!(pool.add(POOL_FREE).read(), existing_free as usize as u32);
        }
    }
}
