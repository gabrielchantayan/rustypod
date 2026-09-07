//! Node pool of the word-keyed `_Rb_tree` family — the libstdc++
//! container instantiation whose element is a single 32-bit word, laid
//! out contiguously at 0x083c0000..0x083c0c00 in osos.
//!
//! - [`word_key_set_allocate_node`] — original: `FUN_083c00dc` @
//!   0x083c00dc (184 bytes; 20 unconditional `bl` call sites).
//!
//! # The family
//!
//! The container is the same shape as the byte-keyed and string-keyed
//! maps already ported (`cxx/byte_key_map.rs`, `cxx/string_map.rs`):
//! the node pool in the first 0x10 bytes, the header node pointer at
//! +0x10, the live-node count at +0x14, a multi-insert flag byte at
//! +0x18 and the comparator object at +0x19. What differs is the
//! element: its nodes are 0x14 bytes, i.e. the standard 0x10-byte
//! `_Rb_tree_node_base` header (color byte, parent, left, right) plus
//! exactly one 32-bit word at +0x10. That word is the whole element —
//! `_M_insert` @ 0x083c09d8 copies it with a single
//! `adds r1,r0,#16; ldrne r2,[r8]; strne r2,[r1]` — and the key
//! accessor @ 0x083b6a2c is `add r0,r0,#16; bx lr` while the
//! comparator @ 0x083d74c4 is an unsigned word `less`
//! (`ldr r0,[r1]; ldr r1,[r2]; cmp r0,r1; movcs r0,#0; movcc r0,#1`).
//! A set of unsigned words, then — `std::set<unsigned>` or
//! `std::set<T *>`; nothing in the family distinguishes the two, so the
//! port types the element `u32`.
//!
//! The rest of that instantiation, none of it ported here: the
//! self-pointing header construction (callers such as the singleton
//! constructor @ 0x08258a70 allocate the header out of this same pool
//! and make it circular), `insert_unique` @ 0x083c0824,
//! `_M_insert` @ 0x083c09d8, the rebalance helpers @ 0x083c0194 /
//! 0x083c01e8, and the whole-tree recycler @ 0x083c099c, which pushes
//! every node back onto this pool's free list through the node's +0xc
//! right link (`ldr r1,[tree,#4]; str r1,[node,#12]; str node,[tree,#4]`)
//! — the exact inverse of the pop below.

/// A red-black tree node of the word-keyed family: the 0x10-byte
/// `_Rb_tree_node_base` header with the single 32-bit element at +0x10.
/// Fields are typed struct members, never literal byte offsets: the
/// 32-bit target layout is exact (asserted below) while a 64-bit host
/// keeps the fields disjoint (the `StringKeyTreeNode` precedent in
/// `cxx/string_map.rs`).
#[repr(C)]
pub struct WordKeySetNode {
    /// +0: red-black color byte (0 = red; a freshly carved node is red).
    pub color: u8,
    /// +1..+4: padding.
    pub _pad: [u8; 3],
    /// +4: parent link.
    pub parent: *mut WordKeySetNode,
    /// +8: left child (smaller keys), null when absent.
    pub left: *mut WordKeySetNode,
    /// +0xc: right child, null when absent — and, while the node sits
    /// on the pool's free list, the next-free link.
    pub right: *mut WordKeySetNode,
    /// +0x10: the element. Left uninitialised by the allocator; the
    /// caller copies it in.
    pub key: u32,
}

/// The node pool state, occupying the container's first 0x10 bytes
/// (libstdc++'s old `_Rb_tree` kept its allocator's pool in the
/// container's own base subobject).
#[repr(C)]
pub struct WordKeySetNodePool {
    /// +0: newest growth-chunk header (0xc bytes: prev / capacity /
    /// arena); null until the first arena is carved.
    pub chunk_head: *mut WordKeySetPoolChunk,
    /// +4: free-list head, threaded through the freed node's +0xc word
    /// (its right link).
    pub free_list: *mut WordKeySetNode,
    /// +8: bump cursor into the current arena.
    pub bump: *mut u8,
    /// +0xc: end of the current arena; `bump == bump_end` means grow.
    pub bump_end: *mut u8,
}

/// A growth-chunk header (0xc bytes): the intrusive list of arenas the
/// pool has carved, newest first.
#[repr(C)]
pub struct WordKeySetPoolChunk {
    /// +0: the previous (older) chunk header.
    pub prev: *mut WordKeySetPoolChunk,
    /// +4: node capacity of this chunk's arena.
    pub capacity: u32,
    /// +8: the arena — `capacity` nodes of 0x14 bytes each.
    pub arena: *mut u8,
}

/// The container as the family's tree operations read it. Only the
/// pool head is touched here; the remaining fields are the scouted
/// layout, from `_M_insert` @ 0x083c09d8 (`ldr r0,[r4,#16]` header,
/// `ldr r0,[r4,#20]` count) and `insert_unique` @ 0x083c0824
/// (`ldrb r1,[r5,#24]` multi flag, `add r0,r5,#25` comparator). Sized
/// off the pool struct so the fields stay disjoint on a 64-bit host
/// (the `StringKeyTree` precedent).
#[repr(C)]
pub struct WordKeySet {
    /// +0..+0x10: the node pool state [`WordKeySetNodePool`].
    pub _opaque: [u8; core::mem::size_of::<WordKeySetNodePool>()],
    /// +0x10: the header node (parent = root, left = leftmost,
    /// right = rightmost); itself carved from this pool.
    pub header: *mut WordKeySetNode,
    /// +0x14: live node count.
    pub node_count: u32,
    /// +0x18: multi-insert flag byte (nonzero = multiset semantics).
    pub multi_insert: u8,
    /// +0x19: key-comparator object (stateless unsigned `less`; only
    /// its address is passed to the comparator @ 0x083d74c4).
    pub comparator: u8,
}

// Target-exact layout; on a 64-bit host the pointer fields widen and
// the offsets shift — harmless, all access goes through the structs.
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x4] = [0; core::mem::offset_of!(WordKeySetNode, parent)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(WordKeySetNode, left)];
    const _: [u8; 0xc] = [0; core::mem::offset_of!(WordKeySetNode, right)];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(WordKeySetNode, key)];
    const _: [u8; 0x14] = [0; core::mem::size_of::<WordKeySetNode>()];
    const _: [u8; 0x4] = [0; core::mem::offset_of!(WordKeySetNodePool, free_list)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(WordKeySetNodePool, bump)];
    const _: [u8; 0xc] = [0; core::mem::offset_of!(WordKeySetNodePool, bump_end)];
    const _: [u8; 0x10] = [0; core::mem::size_of::<WordKeySetNodePool>()];
    const _: [u8; 0x4] = [0; core::mem::offset_of!(WordKeySetPoolChunk, capacity)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(WordKeySetPoolChunk, arena)];
    const _: [u8; 0xc] = [0; core::mem::size_of::<WordKeySetPoolChunk>()];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(WordKeySet, header)];
    const _: [u8; 0x14] = [0; core::mem::offset_of!(WordKeySet, node_count)];
    const _: [u8; 0x18] = [0; core::mem::offset_of!(WordKeySet, multi_insert)];
    const _: [u8; 0x19] = [0; core::mem::offset_of!(WordKeySet, comparator)];
}

/// `#[inline(never)]` front-end for the checked operator new @
/// 0x08266c70 (ported in heap/veneers.rs): on device the original
/// allocator reaches it with `bl` from both allocation sites, and
/// letting LLVM inline the null-check + new-handler path into the
/// allocator nearly doubles its size and destroys the structural match
/// (the `pool_operator_new` rationale in `cxx/byte_key_map.rs`).
#[inline(never)]
fn pool_operator_new(size: usize) -> *mut u8 {
    unsafe { crate::heap::veneers::operator_new_checked(size) }
}

/// word_key_set_allocate_node — original: `FUN_083c00dc` @ 0x083c00dc
/// (184 bytes, 0x083c00dc..0x083c0194, no literal pool — the next
/// function's `ldr r2,[r1,#12]` starts at 0x083c0194; 20 call sites,
/// all unconditional `bl`, none predicated and no plain `b` tail call,
/// verified by decoding every B/BL word of osos.dec).
///
/// libstdc++'s pool allocator for the word-keyed set family's 0x14-byte
/// tree nodes — the third twin of the ported
/// [`byte_key_tree_allocate_node`](crate::cxx::byte_key_map) @
/// 0x083b7f40 (0x20-byte nodes) and
/// [`string_key_tree_allocate_node`](crate::cxx::string_map) @
/// 0x083c311c (0x18-byte nodes). Same free-list / bump / growth
/// sequence; only the stride differs, so the original multiplies by
/// `#0x14` (`mov r0,#0x14; mul r0,r6,r0`) and forms the arena end with
/// `add r1,r6,r6,lsl #2` + `lsl #2` where the byte-keyed twin folds
/// 0x20 into `lsl #5`.
///
/// If the free list at set+4 is non-empty, pop its head (the next
/// pointer is threaded through the node's +0xc word, its right link).
/// Else bump-allocate from the current arena (cursor at set+8, end at
/// set+0xc); when the cursor has reached the end, grow first: the new
/// capacity is `max(prev + 0x20, prev + prev/2 + prev/8)` of the newest
/// chunk's capacity, or 0x20 when there is no chunk yet, then a
/// 0xc-byte chunk header and a `capacity * 0x14` arena are carved by
/// two calls to the checked operator new @ 0x08266c70, the chunk is
/// pushed at set+0 (prev link, capacity, arena pointer) and the arena
/// becomes the new bump range. The handed-out node gets its
/// parent/left/right words at +4/+8/+0xc nulled and its color byte at
/// +0 set to 0 (red); the element word at +0x10 is deliberately left
/// as it was — `_M_insert` @ 0x083c09d8 stores it immediately after.
///
/// Exported `pub` with no ops slot: nothing in the crate calls it yet
/// (this family's `_M_insert` @ 0x083c09d8 is unported), the
/// `string_key_tree_allocate_node` precedent.
///
/// Deviations:
/// - Ghidra types the original `void`
///   (`decomp/c/036/083c00dc_FUN_083c00dc.c`), but it leaves the node
///   pointer in r0 — only r4-r8/lr are stacked — and `_M_insert`
///   consumes it (`adds r1,r0,#16` / `mov r5,r0` @ 0x083c09f8). The
///   port returns it, like both twins.
/// - The node stride and chunk-header size go through `size_of`
///   (0x14 / 0xc on the 32-bit target — the original's `#0x14` / `#0xc`
///   immediates — wider on 64-bit hosts, where that is what keeps the
///   fields disjoint).
/// - The original passes a dead `r1 = 0` second argument to
///   0x08266c70 (the callee only stack-saves it); the ported
///   `operator_new_checked` takes the size alone and is reached through
///   the `#[inline(never)]` [`pool_operator_new`] front-end to preserve
///   the original's two `bl` boundaries.
/// - The original stacks r8 without ever using it (`push {r4-r8,lr}`,
///   an eight-word alignment pad); nothing to reproduce.
/// - Like the original there is no null check on the checked-new
///   results: its new-handler path aborts @ 0x08266abc, and a
///   hypothetical null would fault on the chunk-header store exactly as
///   the original does.
///
/// # Safety
/// `set` must point at a live container whose first 0x10 bytes are the
/// pool state ([`WordKeySetNodePool`]); on a freshly constructed
/// container those four words are zero (no chunks, empty free list,
/// empty bump range), which the growth path handles. The returned
/// node's element word is uninitialised — the caller must store it
/// before any read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_key_set_allocate_node(
    set: *mut WordKeySet,
) -> *mut WordKeySetNode {
    const NODE_SIZE: usize = core::mem::size_of::<WordKeySetNode>();
    let pool = set.cast::<WordKeySetNodePool>();
    let node: *mut WordKeySetNode;
    let free = (*pool).free_list;
    if !free.is_null() {
        // Free-list pop: the next pointer rides the node's right link.
        node = free;
        (*pool).free_list = (*free).right;
    } else {
        let mut bump = (*pool).bump;
        if bump == (*pool).bump_end {
            // Growth: 1.625x the newest chunk's capacity, floored at
            // prev + 0x20; 0x20 nodes for the very first chunk.
            let capacity: u32 = match (*pool).chunk_head.is_null() {
                true => 0x20,
                false => {
                    let prev = (*(*pool).chunk_head).capacity;
                    let grown =
                        prev.wrapping_add(prev >> 1).wrapping_add(prev >> 3);
                    prev.wrapping_add(0x20).max(grown)
                }
            };
            let chunk =
                pool_operator_new(core::mem::size_of::<WordKeySetPoolChunk>())
                    .cast::<WordKeySetPoolChunk>();
            let arena =
                pool_operator_new((capacity as usize).wrapping_mul(NODE_SIZE));
            (*chunk).arena = arena;
            (*chunk).prev = (*pool).chunk_head;
            (*chunk).capacity = capacity;
            (*pool).chunk_head = chunk;
            bump = arena;
            (*pool).bump_end =
                arena.add((capacity as usize).wrapping_mul(NODE_SIZE));
        }
        node = bump.cast::<WordKeySetNode>();
        (*pool).bump = bump.add(NODE_SIZE);
    }
    (*node).parent = core::ptr::null_mut();
    (*node).left = core::ptr::null_mut();
    (*node).right = core::ptr::null_mut();
    (*node).color = 0; // red
    node
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Bump arena backing the heap-ops `alloc` slot: the real heap core
    /// is not exercised on the host, and the shared mock in
    /// heap/veneers hands out a fixed fake address that cannot be
    /// written (the pool-test pattern in `cxx/string_map.rs`).
    const POOL_ARENA_SIZE: usize = 0x10000;

    #[repr(C, align(8))]
    struct PoolArena([u8; POOL_ARENA_SIZE]);

    static mut POOL_ARENA: PoolArena = PoolArena([0; POOL_ARENA_SIZE]);
    static mut POOL_ARENA_USED: usize = 0;
    /// Every size the pool asked the checked operator new for, in
    /// order — the heap-traffic log.
    static mut POOL_ALLOC_SIZES: Vec<usize> = Vec::new();

    unsafe extern "C" fn pool_arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = POOL_ARENA_USED;
        let aligned = (size + 7) & !7;
        if used + aligned > POOL_ARENA_SIZE {
            return core::ptr::null_mut();
        }
        POOL_ARENA_USED = used + aligned;
        (*core::ptr::addr_of_mut!(POOL_ALLOC_SIZES)).push(size);
        core::ptr::addr_of_mut!(POOL_ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn pool_arena_create(
        desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        desc as *mut HeapDescriptorDescriptor
    }

    /// Installs the arena over the shared heap-ops table, under the
    /// same lock heap/veneers' own tests use. One guard per test
    /// function (a second, shadowed guard would self-deadlock).
    fn pool_heap() -> MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            POOL_ARENA_USED = 0;
            (*core::ptr::addr_of_mut!(POOL_ALLOC_SIZES)).clear();
            let ops = core::ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = pool_arena_alloc;
            (*ops).create = pool_arena_create;
        }
        guard
    }

    fn alloc_sizes() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(POOL_ALLOC_SIZES)).clone() }
    }

    /// A fresh container's pool words (all zero: no chunks, empty free
    /// list, empty bump range — which reads as exhausted).
    fn fresh_pool() -> WordKeySetNodePool {
        WordKeySetNodePool {
            chunk_head: core::ptr::null_mut(),
            free_list: core::ptr::null_mut(),
            bump: core::ptr::null_mut(),
            bump_end: core::ptr::null_mut(),
        }
    }

    /// A node pre-filled with garbage the allocator must clear (or, for
    /// the element word, must leave alone).
    fn test_node() -> WordKeySetNode {
        WordKeySetNode {
            color: 0xff,
            _pad: [0xff; 3],
            parent: core::ptr::dangling_mut(),
            left: core::ptr::dangling_mut(),
            right: core::ptr::dangling_mut(),
            key: 0xdead_beef,
        }
    }

    /// First allocation on a fresh container: one 0xc-byte chunk header
    /// and one 0x20-node arena from the checked operator new, in that
    /// order; the chunk pushed at set+0 with a null prev; the bump
    /// range covering the arena; and the returned node — the arena base
    /// — initialised red with three null links.
    #[test]
    fn fresh_container_carves_first_chunk() {
        let _heap = pool_heap();
        unsafe {
            let node_size = core::mem::size_of::<WordKeySetNode>();
            let chunk_size = core::mem::size_of::<WordKeySetPoolChunk>();
            let mut pool = fresh_pool();
            let pool_ptr = core::ptr::addr_of_mut!(pool);

            let node = word_key_set_allocate_node(pool_ptr.cast::<WordKeySet>());

            assert_eq!(alloc_sizes(), [chunk_size, 0x20 * node_size]);
            let chunk = pool.chunk_head;
            assert!(!chunk.is_null());
            assert_eq!((*chunk).prev, core::ptr::null_mut());
            assert_eq!((*chunk).capacity, 0x20);
            let arena = (*chunk).arena;
            assert_eq!(node, arena.cast::<WordKeySetNode>());
            assert_eq!(pool.bump, arena.add(node_size));
            assert_eq!(pool.bump_end, arena.add(0x20 * node_size));
            assert_eq!(pool.free_list, core::ptr::null_mut());
            assert_eq!((*node).color, 0); // red
            assert_eq!((*node).parent, core::ptr::null_mut());
            assert_eq!((*node).left, core::ptr::null_mut());
            assert_eq!((*node).right, core::ptr::null_mut());
        }
    }

    /// The bump range hands out the whole arena one 0x14-byte node at a
    /// time with no further heap traffic; the allocation past the end
    /// grows a second chunk at max(0x20+0x20, 0x20+0x10+4) = 0x40 and
    /// links it ahead of the first.
    #[test]
    fn bump_exhaustion_grows_second_chunk() {
        let _heap = pool_heap();
        unsafe {
            let node_size = core::mem::size_of::<WordKeySetNode>();
            let chunk_size = core::mem::size_of::<WordKeySetPoolChunk>();
            let mut pool = fresh_pool();
            let set = core::ptr::addr_of_mut!(pool).cast::<WordKeySet>();

            let first = word_key_set_allocate_node(set);
            let first_chunk = pool.chunk_head;
            let first_arena = (*first_chunk).arena;
            assert_eq!(first, first_arena.cast());
            for i in 1..0x20usize {
                let node = word_key_set_allocate_node(set);
                assert_eq!(node, first_arena.add(i * node_size).cast());
            }
            // Header + arena so far, nothing more.
            assert_eq!(alloc_sizes(), [chunk_size, 0x20 * node_size]);

            let node = word_key_set_allocate_node(set);
            let grown = pool.chunk_head;
            assert!(grown != first_chunk);
            assert_eq!((*grown).prev, first_chunk);
            assert_eq!((*grown).capacity, 0x40);
            assert_eq!(node, (*grown).arena.cast());
            assert_eq!(pool.bump, (*grown).arena.add(node_size));
            assert_eq!(pool.bump_end, (*grown).arena.add(0x40 * node_size));
            assert_eq!(
                alloc_sizes(),
                [chunk_size, 0x20 * node_size, chunk_size, 0x40 * node_size]
            );
        }
    }

    /// The growth formula max(prev + 0x20, prev + prev/2 + prev/8): the
    /// +0x20 floor wins for small capacities (8 -> 0x28 against 8+4+1),
    /// the 1.625x term for large ones (0x100 -> 0x1a0 against 0x120).
    /// Both start from a hand-crafted exhausted pool.
    #[test]
    fn growth_capacity_formula() {
        let _heap = pool_heap();
        unsafe {
            let node_size = core::mem::size_of::<WordKeySetNode>();
            let chunk_size = core::mem::size_of::<WordKeySetPoolChunk>();
            for (prev_cap, want) in [(8u32, 0x28u32), (0x100, 0x1a0)] {
                POOL_ARENA_USED = 0;
                (*core::ptr::addr_of_mut!(POOL_ALLOC_SIZES)).clear();
                let mut old_chunk = WordKeySetPoolChunk {
                    prev: core::ptr::null_mut(),
                    capacity: prev_cap,
                    arena: core::ptr::null_mut(),
                };
                let mut sentinel = 0u8;
                let bump = core::ptr::addr_of_mut!(sentinel);
                let mut pool = WordKeySetNodePool {
                    chunk_head: core::ptr::addr_of_mut!(old_chunk),
                    free_list: core::ptr::null_mut(),
                    bump,
                    bump_end: bump, // exhausted
                };

                let node = word_key_set_allocate_node(
                    core::ptr::addr_of_mut!(pool).cast::<WordKeySet>(),
                );

                let chunk = pool.chunk_head;
                assert_eq!((*chunk).prev, core::ptr::addr_of_mut!(old_chunk));
                assert_eq!((*chunk).capacity, want);
                assert_eq!(node, (*chunk).arena.cast());
                assert_eq!(alloc_sizes(), [chunk_size, want as usize * node_size]);
            }
        }
    }

    /// The free list pops before any bump or heap traffic: head first,
    /// the next pointer threaded through the node's +0xc right link,
    /// and each recycled node re-initialised (color 0, links null).
    #[test]
    fn free_list_pop_recycles_nodes() {
        let _heap = pool_heap();
        unsafe {
            let mut a = test_node();
            let mut b = test_node();
            let pa = core::ptr::addr_of_mut!(a);
            let pb = core::ptr::addr_of_mut!(b);
            (*pa).right = pb; // free-list next
            (*pa).parent = pb; // garbage the pop must clear
            (*pb).parent = pa;
            (*pb).right = core::ptr::null_mut();
            let mut pool = fresh_pool();
            pool.free_list = pa;
            // The bump range reads exhausted (null == null) but must
            // never be reached while the free list is non-empty.
            let set = core::ptr::addr_of_mut!(pool).cast::<WordKeySet>();

            let first = word_key_set_allocate_node(set);
            assert_eq!(first, pa);
            assert_eq!(pool.free_list, pb);
            assert_eq!((*pa).color, 0);
            assert_eq!((*pa).parent, core::ptr::null_mut());
            assert_eq!((*pa).left, core::ptr::null_mut());
            assert_eq!((*pa).right, core::ptr::null_mut());
            assert!(alloc_sizes().is_empty(), "no heap traffic on a pop");

            let second = word_key_set_allocate_node(set);
            assert_eq!(second, pb);
            assert_eq!(pool.free_list, core::ptr::null_mut());
            assert_eq!((*pb).color, 0);
            assert_eq!((*pb).parent, core::ptr::null_mut());
            assert!(alloc_sizes().is_empty());
        }
    }

    /// The element word at +0x10 is never touched: the original writes
    /// only +4/+8/+0xc and the byte at +0, leaving `_M_insert` to store
    /// the element. A recycled node therefore still carries its stale
    /// value on the way out.
    #[test]
    fn element_word_is_left_uninitialised() {
        let _heap = pool_heap();
        unsafe {
            let mut recycled = test_node();
            let pr = core::ptr::addr_of_mut!(recycled);
            (*pr).right = core::ptr::null_mut();
            let mut pool = fresh_pool();
            pool.free_list = pr;

            let node = word_key_set_allocate_node(
                core::ptr::addr_of_mut!(pool).cast::<WordKeySet>(),
            );

            assert_eq!(node, pr);
            assert_eq!((*node).key, 0xdead_beef);
        }
    }
}
