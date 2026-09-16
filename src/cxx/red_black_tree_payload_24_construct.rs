//! Red-black-tree 24-byte-payload constructor — original:
//! `FUN_083db2d4` at load address `0x083db2d4`.
//!
//! Raw `osos.dec` establishes the exact 88-byte extent: 22 ARM words from
//! `push {r4-r6,lr}` at `0x083db2d4` through `pop {r4-r6,pc}` at
//! `0x083db328`; the next separately linked function starts at `0x083db32c`.
//! It has four inbound direct call sites (all plain unconditional `bl`) and
//! makes one plain unconditional `bl`, to
//! [`red_black_tree_payload_24_node_pool_acquire`]. There are no predicated
//! direct calls.
//!
//! The constructor clears the embedded 16-byte node pool, header pointer,
//! count, and comparator-adjacent flag; copies one comparator byte; obtains
//! the header sentinel from the pool; and establishes an empty tree by making
//! its leftmost and rightmost links self-referential.
//!
//! Deliberate deviations: the ignored third ABI argument remains present in
//! the signature. Target pointers stay `u32` words so the 28-byte layout is
//! preserved on hosts with wider native pointers.

use crate::cxx::red_black_tree_payload_24_node_pool_acquire::{
    red_black_tree_payload_24_node_pool_acquire, RedBlackTreePayload24Node,
    RedBlackTreePayload24NodePool,
};

/// A 24-byte-payload red-black tree and its embedded node pool.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload24 {
    pub pool: RedBlackTreePayload24NodePool,
    pub header: u32,
    pub node_count: u32,
    pub initialized: u8,
    pub comparator: u8,
    _padding: [u8; 2],
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreePayload24, header)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(RedBlackTreePayload24, node_count)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(RedBlackTreePayload24, initialized)];
const _: [u8; 0x19] = [0; core::mem::offset_of!(RedBlackTreePayload24, comparator)];
const _: [u8; 0x1c] = [0; core::mem::size_of::<RedBlackTreePayload24>()];

/// Constructs an empty 24-byte-payload red-black tree.
///
/// Original: `FUN_083db2d4` at load address `0x083db2d4` (88 bytes; four
/// unconditional inbound `bl` sites; one unconditional outbound `bl`).
///
/// # Safety
///
/// `tree` must be writable and `comparator` must point to one readable byte.
/// The acquired node is immediately dereferenced, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_payload_24_construct")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_24_construct(
    tree: *mut RedBlackTreePayload24,
    comparator: *const u8,
    _allocator: *mut u8,
) -> *mut RedBlackTreePayload24 {
    unsafe { construct_with_acquire(tree, comparator, red_black_tree_payload_24_node_pool_acquire) }
}

#[inline(always)]
unsafe fn construct_with_acquire(
    tree: *mut RedBlackTreePayload24,
    comparator: *const u8,
    acquire: unsafe extern "C" fn(*mut RedBlackTreePayload24NodePool) -> *mut RedBlackTreePayload24Node,
) -> *mut RedBlackTreePayload24 {
    unsafe {
        (*tree).pool = RedBlackTreePayload24NodePool::default();
        (*tree).header = 0;
        (*tree).node_count = 0;
        (*tree).initialized = 0;
        (*tree).comparator = comparator.read();

        let header = acquire(&mut (*tree).pool);
        (*tree).header = header as usize as u32;
        (*header).parent = 0;
        (*header).left = header as usize as u32;
        (*header).right = header as usize as u32;
        tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static mut SENTINEL: *mut RedBlackTreePayload24Node = core::ptr::null_mut();

    unsafe extern "C" fn acquire_recycled_sentinel(
        _pool: *mut RedBlackTreePayload24NodePool,
    ) -> *mut RedBlackTreePayload24Node {
        unsafe { SENTINEL }
    }

    #[test]
    fn clears_tree_and_initializes_a_recycled_sentinel() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_24_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/red_black_tree_payload_24_construct");
            return;
        };

        unsafe {
            let sentinel = slab.add(0x100) as *mut RedBlackTreePayload24Node;
            SENTINEL = sentinel;
            sentinel.write(core::mem::zeroed());
            (*sentinel).color = 1;
            (*sentinel).parent = 0x1111_1111;
            (*sentinel).left = 0x2222_2222;
            (*sentinel).right = 0x3333_3333;

            let mut tree = RedBlackTreePayload24 {
                pool: RedBlackTreePayload24NodePool {
                    chunks: 1,
                    free: sentinel as usize as u32,
                    next: 2,
                    end: 3,
                },
                header: 4,
                node_count: 5,
                initialized: 7,
                comparator: 6,
                _padding: [8; 2],
            };
            let comparator = 0xa5;
            let result = construct_with_acquire(&mut tree, &comparator, acquire_recycled_sentinel);
            assert!(core::ptr::eq(result, &mut tree));
            assert_eq!(tree.pool.chunks, 0);
            assert_eq!(tree.pool.free, 0);
            assert_eq!(tree.pool.next, 0);
            assert_eq!(tree.pool.end, 0);
            assert_eq!(tree.header, sentinel as usize as u32);
            assert_eq!(tree.node_count, 0);
            assert_eq!(tree.comparator, comparator);
            assert_eq!(tree.initialized, 0);
            assert_eq!((*sentinel).color, 1);
            assert_eq!((*sentinel).parent, 0);
            assert_eq!((*sentinel).left, tree.header);
            assert_eq!((*sentinel).right, tree.header);
        }
    }
}
