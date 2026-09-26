//! Red-black-tree 8-byte-payload constructor — retailOS `FUN_083db244` @
//! `0x083db244` (88 bytes).
//!
//! Raw `osos.dec` establishes the exact 22-word A32 extent from `push
//! {r4-r6,lr}` at 0x083db244 through `pop {r4-r6,pc}` at 0x083db298;
//! 0x083db29c starts the next function. Whole-image decoding finds two inbound
//! unconditional plain `bl` sites (0x0809dbc0 and 0x0809df4c), no predicated
//! forms, and one outbound unconditional plain `bl` to the still-retail node
//! pool acquire at 0x083bc980. The constructor clears the embedded pool,
//! header, count, and initialization byte; copies the comparator byte; acquires
//! a header sentinel; then clears its parent and self-links its left/right
//! words.
//!
//! Deliberate deviations: the ignored third ABI argument remains present.
//! Pointers remain `u32` target words so the 28-byte object layout survives
//! hosts with wider native pointers.

/// A 24-byte tree node with an 8-byte caller-owned payload.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload8Node {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub payload: [u8; 8],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreePayload8Node, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreePayload8Node, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreePayload8Node, right)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreePayload8Node, payload)];
const _: [u8; 0x18] = [0; core::mem::size_of::<RedBlackTreePayload8Node>()];

/// The target-width pool state passed to retail `FUN_083bc980`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload8NodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreePayload8NodePool>()];

/// A 28-byte red-black tree with an 8-byte client payload per node.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload8 {
    pub pool: RedBlackTreePayload8NodePool,
    pub header: u32,
    pub node_count: u32,
    pub initialized: u8,
    pub comparator: u8,
    _padding: [u8; 2],
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreePayload8, header)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(RedBlackTreePayload8, node_count)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(RedBlackTreePayload8, initialized)];
const _: [u8; 0x19] = [0; core::mem::offset_of!(RedBlackTreePayload8, comparator)];
const _: [u8; 0x1c] = [0; core::mem::size_of::<RedBlackTreePayload8>()];

type RetailNodePoolAcquire = unsafe extern "C" fn(*mut RedBlackTreePayload8NodePool) -> *mut RedBlackTreePayload8Node;
const RETAIL_NODE_POOL_ACQUIRE_ADDRESS: usize = 0x083b_c980;

/// Constructs an empty 8-byte-payload red-black tree.
///
/// # Safety
///
/// `tree` must be writable, `comparator` must point to one readable byte, and
/// retail node-pool acquisition must return a writable node.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_payload_8_construct")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_8_construct(
    tree: *mut RedBlackTreePayload8,
    comparator: *const u8,
    _allocator: *mut u8,
) -> *mut RedBlackTreePayload8 {
    let acquire: RetailNodePoolAcquire = unsafe { core::mem::transmute(RETAIL_NODE_POOL_ACQUIRE_ADDRESS) };
    unsafe { construct_with_acquire(tree, comparator, acquire) }
}

#[inline(always)]
unsafe fn construct_with_acquire(
    tree: *mut RedBlackTreePayload8,
    comparator: *const u8,
    acquire: RetailNodePoolAcquire,
) -> *mut RedBlackTreePayload8 {
    unsafe {
        (*tree).pool = RedBlackTreePayload8NodePool::default();
        (*tree).header = 0;
        (*tree).node_count = 0;
        (*tree).initialized = 0;
        (*tree).comparator = comparator.read();
        let header = acquire(&mut (*tree).pool);
        let header_word = header as usize as u32;
        (*tree).header = header_word;
        (*header).parent = 0;
        (*header).left = header_word;
        (*header).right = header_word;
        tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    static mut SENTINEL: *mut RedBlackTreePayload8Node = core::ptr::null_mut();

    unsafe extern "C" fn acquire_recycled_sentinel(
        _pool: *mut RedBlackTreePayload8NodePool,
    ) -> *mut RedBlackTreePayload8Node {
        unsafe { SENTINEL }
    }

    #[test]
    fn clears_tree_and_initializes_recycled_sentinel() {
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_8_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/red_black_tree_payload_8_construct");
            return;
        };
        unsafe {
            let tree = slab.cast::<RedBlackTreePayload8>();
            let sentinel = slab.add(0x100).cast::<RedBlackTreePayload8Node>();
            tree.write(RedBlackTreePayload8 {
                pool: RedBlackTreePayload8NodePool { chunks: 1, free: 2, next: 3, end: 4 },
                header: 5,
                node_count: 6,
                initialized: 7,
                comparator: 8,
                _padding: [9; 2],
            });
            sentinel.write(RedBlackTreePayload8Node {
                color: 1,
                _padding: [0; 3],
                parent: 0x1111_1111,
                left: 0x2222_2222,
                right: 0x3333_3333,
                payload: [0xa5; 8],
            });
            SENTINEL = sentinel;
            let comparator = 0x5a;
            assert_eq!(construct_with_acquire(tree, &comparator, acquire_recycled_sentinel), tree);
            assert_eq!(((*tree).pool.chunks, (*tree).pool.free, (*tree).pool.next, (*tree).pool.end), (0, 0, 0, 0));
            assert_eq!(((*tree).header, (*tree).node_count, (*tree).initialized, (*tree).comparator), (sentinel as usize as u32, 0, 0, comparator));
            assert_eq!(((*sentinel).color, (*sentinel).parent, (*sentinel).left, (*sentinel).right), (1, 0, (*tree).header, (*tree).header));
            assert_eq!((*sentinel).payload, [0xa5; 8]);
        }
    }
}
