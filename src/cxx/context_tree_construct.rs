//! Context-bearing red-black-tree constructor — `FUN_081e2078` @ `0x081e2078`.
//!
//! Raw A32 extent is [0x081e2078, 0x081e20dc): 100 bytes, ending in
//! pop {r3-r7,pc}; the next word begins a real function. One outgoing plain
//! BL at 0x081e20b4 calls the ported pool acquire @ 0x083bdea0. Whole-image
//! decoding finds two incoming plain BLs at 0x08297338 and 0x08297400;
//! there are no incoming or outgoing predicated BLs.
//!
//! Clear the pool, sentinel, count, and two state bytes; acquire a 20-byte
//! sentinel, clear its parent, self-link its children, and store the context
//! word at +0x1c. Return the original tree. Deliberate deviations: omit the
//! redundant stack zero spill/reload; preserve target-width pointer words.

use super::red_black_tree_node_pool_acquire_083bdea0::{
    red_black_tree_node_pool_acquire_083bdea0, RedBlackTreeNodePool083bdea0,
};
use core::ptr::addr_of_mut;

#[repr(C)]
pub struct ContextTree {
    pub pool: RedBlackTreeNodePool083bdea0,
    pub sentinel: u32,
    pub count: u32,
    pub state: u8,
    pub comparator_state: u8,
    pub padding: [u8; 2],
    pub context: u32,
}

const _: [u8; 32] = [0; core::mem::size_of::<ContextTree>()];

/// Initialize an empty context-bearing tree.
///
/// # Safety
/// `tree` must be writable; the configured heap must supply writable storage
/// whose addresses fit in u32. Allocation failure is dereferenced as in stock.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_tree_construct(tree: *mut ContextTree, context: u32) -> *mut ContextTree {
    addr_of_mut!((*tree).pool.chunks).write(0);
    addr_of_mut!((*tree).sentinel).write(0);
    addr_of_mut!((*tree).count).write(0);
    addr_of_mut!((*tree).state).write(0);
    addr_of_mut!((*tree).comparator_state).write(0);
    addr_of_mut!((*tree).pool.end).write(0);
    addr_of_mut!((*tree).pool.next).write(0);
    addr_of_mut!((*tree).pool.free).write(0);
    let sentinel = red_black_tree_node_pool_acquire_083bdea0(addr_of_mut!((*tree).pool));
    let word = sentinel as usize as u32;
    addr_of_mut!((*tree).sentinel).write(word);
    addr_of_mut!((*sentinel).parent).write(0);
    addr_of_mut!((*sentinel).left).write(word);
    addr_of_mut!((*sentinel).right).write(word);
    addr_of_mut!((*tree).context).write(context);
    tree
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut NEXT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn slab_alloc(_heap: *mut HeapDescriptorDescriptor, size: usize, _tag: usize) -> *mut u8 {
        let result = NEXT;
        NEXT = NEXT.add((size + 3) & !3);
        result
    }

    #[test]
    fn empty_tree_preserves_padding_payload_and_neighbors_for_full_width_contexts() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CONTEXT_TREE_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/context_tree_construct");
            return;
        };
        unsafe {
            let _heap = crate::heap::veneers::tests::mock_heap();
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = slab_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            for context in [0, 1, 0x8000_0000, 0xffff_ffff] {
                slab.write_bytes(0xa5, 0x1000);
                NEXT = slab.add(0x100);
                let tree = slab.add(4).cast::<ContextTree>();
                assert_eq!(context_tree_construct(tree, context), tree);
                let chunk = slab.add(0x100).cast::<u32>();
                let sentinel = slab.add(0x10c).cast::<u32>();
                let word = sentinel as usize as u32;
                assert_eq!((*tree).pool.chunks, chunk as usize as u32);
                assert_eq!((*tree).pool.free, 0);
                assert_eq!((*tree).pool.next, word + 20);
                assert_eq!((*tree).pool.end, word + 32 * 20);
                assert_eq!((*tree).sentinel, word);
                assert_eq!((*tree).count, 0);
                assert_eq!(((*tree).state, (*tree).comparator_state), (0, 0));
                assert_eq!((*tree).padding, [0xa5; 2]);
                assert_eq!((*tree).context, context);
                assert_eq!(core::slice::from_raw_parts(chunk, 3), &[0, 32, word]);
                assert_eq!(core::slice::from_raw_parts(sentinel, 5),
                    &[0xa5a5_a500, 0, word, word, 0xa5a5_a5a5]);
                assert_eq!(slab.cast::<u32>().read(), 0xa5a5_a5a5);
                assert_eq!(slab.add(36).cast::<u32>().read(), 0xa5a5_a5a5);
            }
        }
    }
}
