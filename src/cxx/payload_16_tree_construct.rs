//! Empty 16-byte-payload tree constructor — `FUN_083db10c` @ `0x083db10c`.
//!
//! True extent [0x083db10c, 0x083db164): 88 bytes; the next PUSH begins
//! another function. Raw A32 decoding finds one outgoing plain BL to
//! 0x083b9f4c and one incoming plain BL at 0x081e0be4; no predicated BLs.
//!
//! Clear the embedded pool, header, count and state byte; copy the comparator
//! byte, acquire a 32-byte header, clear its parent and self-link both children.
//! Return the original tree. Deliberate deviations: reuse the canonical Rust
//! pool acquire rather than its retail address; preserve target-width pointer
//! words on hosts. Padding and header payload remain untouched. Ordered volatile
//! initialization preserves the retail selector read when it aliases the tree.

use super::red_black_tree_payload_16_node_pool_acquire_083b9f4c::{
    red_black_tree_payload_16_node_pool_acquire_083b9f4c, RedBlackTreePayload16NodePool,
};
use core::ptr::addr_of_mut;

#[repr(C)]
pub struct Payload16Tree {
    pub pool: RedBlackTreePayload16NodePool,
    pub header: u32,
    pub count: u32,
    pub state: u8,
    pub comparator_state: u8,
    pub padding: [u8; 2],
}
const _: [u8; 28] = [0; core::mem::size_of::<Payload16Tree>()];

/// Construct an empty tree in caller-owned storage.
///
/// # Safety
/// `tree` is aligned writable storage; `comparator` is readable and may alias
/// it. The heap must supply writable allocations whose addresses fit in u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn payload_16_tree_construct(
    tree: *mut Payload16Tree, comparator: *const u8,
) -> *mut Payload16Tree {
    addr_of_mut!((*tree).pool.chunks).write_volatile(0);
    addr_of_mut!((*tree).header).write_volatile(0);
    addr_of_mut!((*tree).count).write_volatile(0);
    addr_of_mut!((*tree).state).write_volatile(0);
    let comparator = comparator.read_volatile();
    addr_of_mut!((*tree).comparator_state).write_volatile(comparator);
    addr_of_mut!((*tree).pool.end).write_volatile(0);
    addr_of_mut!((*tree).pool.next).write_volatile(0);
    addr_of_mut!((*tree).pool.free).write_volatile(0);
    let header = red_black_tree_payload_16_node_pool_acquire_083b9f4c(addr_of_mut!((*tree).pool));
    let word = header as usize as u32;
    addr_of_mut!((*tree).header).write(word);
    addr_of_mut!((*header).parent).write(0);
    addr_of_mut!((*header).left).write(word);
    addr_of_mut!((*header).right).write(word);
    tree
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use core::ptr;

    static mut NEXT: *mut u8 = ptr::null_mut();
    unsafe extern "C" fn slab_alloc(_: *mut HeapDescriptorDescriptor, size: usize, _: usize) -> *mut u8 {
        let result = NEXT;
        NEXT = NEXT.add((size + 3) & !3);
        result
    }

    #[test]
    fn constructs_empty_header_preserving_payload_padding_and_alias_read_order() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::PAYLOAD_16_TREE_CONSTRUCT, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/payload_16_tree_construct"));
            return;
        };
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = slab_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            // Every byte value, then aliases cleared before and after the read.
            for case in 0..259 {
                slab.write_bytes(0xa5, 0x1000);
                NEXT = slab.add(0x100);
                let tree = slab.add(4).cast::<Payload16Tree>();
                let value = case as u8;
                let (input, expected): (*const u8, u8) = match case {
                    256 => (tree.cast::<u8>(), 0),
                    257 => (addr_of_mut!((*tree).pool.free).cast::<u8>(), 0xa5),
                    258 => (addr_of_mut!((*tree).comparator_state), 0xa5),
                    _ => (&value as *const u8, value),
                };
                assert_eq!(payload_16_tree_construct(tree, input), tree);
                let chunk = slab.add(0x100).cast::<u32>();
                let header = slab.add(0x10c).cast::<u32>();
                let word = header as usize as u32;
                assert_eq!([(*tree).pool.chunks, (*tree).pool.free, (*tree).pool.next, (*tree).pool.end],
                    [chunk as usize as u32, 0, word + 32, word + 32 * 32]);
                assert_eq!([(*tree).header, (*tree).count], [word, 0]);
                assert_eq!(((*tree).state, (*tree).comparator_state), (0, expected));
                assert_eq!((*tree).padding, [0xa5; 2]);
                assert_eq!(core::slice::from_raw_parts(chunk, 3), &[0, 32, word]);
                assert_eq!(core::slice::from_raw_parts(header, 8),
                    &[0xa5a5_a500, 0, word, word, 0xa5a5_a5a5, 0xa5a5_a5a5, 0xa5a5_a5a5, 0xa5a5_a5a5]);
                assert_eq!(slab.cast::<u32>().read(), 0xa5a5_a5a5);
                assert_eq!(slab.add(32).cast::<u32>().read(), 0xa5a5_a5a5);
            }
        }
    }
}
