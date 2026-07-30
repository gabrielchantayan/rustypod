//! Find-or-insert on a red-black-tree map keyed by a single byte — the
//! `map<u8, V>::operator[]` shape the application layer uses to fetch the
//! mapped value for a one-byte key (26 `bl` call sites).
//!
//! - [`byte_key_map_find`] — original: `FUN_083db038` @ 0x083db038
//!   (88 bytes; 26 `bl` call sites, the only copy).
//!
//! Algorithm (from the disassembly): build a 16-byte key/value pair on
//! the stack — the key byte read from `*key` at +0, a zeroed 12-byte
//! mapped value at +4 (the original zeroes a separate 12-byte temporary
//! with `stmia` and block-copies it into the pair, the copy-construction
//! of a default-constructed value) — then run the tree insert-unique
//! operation @ 0x083b867c(&result, map, &pair) and return the resulting
//! node pointer plus 0x14, i.e. `&node->value`: the node header is
//! 0x10 bytes (color/flag at +0, parent +4, left +8, right +0xc) with
//! the key pair at +0x10, so +0x14 is the mapped value inside the pair.
//!
//! Contract of the tree operation @ 0x083b867c — now ported below as
//! [`byte_key_tree_insert_unique`], the shipped default of the
//! [`BYTE_KEY_MAP_OPS`] dispatch slot (house pattern — see
//! `cxx/pair_header.rs`):
//!
//! ```text
//! void insert_unique(result *r0, map *r1, const pair *r2)
//!   r0 +0  <- node pointer (existing or newly inserted)
//!   r0 +4  <- inserted flag byte (1 = newly linked, 0 = key present)
//!   r1     container: +0x10 header node (header+4 = root, header+8 =
//!          leftmost), +0x18 multi-insert flag byte (nonzero skips the
//!          uniqueness test — multimap semantics), +0x19 comparator
//!   r2     the 16-byte key pair above; node keys sit at node+0x10
//! ```
//!
//! The body is libstdc++'s `_Rb_tree::_M_insert_unique`: descend from
//! the root comparing keys through the comparator @ 0x083d73bc (nonzero
//! -> descend left at +8, else right at +0xc), remember the last node,
//! then — via the iterator-equality helper @ 0x083cf740 against the
//! leftmost header child and an inline predecessor/successor walk —
//! either return the existing node with the flag clear or link a fresh
//! node through 0x083b8844 (`_M_insert`, which allocates, copies the
//! pair and rebalances) and return it flagged. Every path stores the
//! node word at result+0 and the flag byte at result+4, which is the
//! whole contract the find relies on. The comparator, the iterator
//! equality and the key accessor @ 0x083b6a44 are one-instruction
//! leaves, inlined into the port; `_M_insert` @ 0x083b8844 is ported
//! below as [`byte_key_tree_insert_node`], the shipped default of the
//! [`BYTE_KEY_TREE_OPS`] dispatch slot, with its pool allocator @
//! 0x083b7f40 ported as [`byte_key_tree_allocate_node`], the shipped
//! default of the [`BYTE_KEY_ALLOC_OPS`] slot.
//!
//! Deviations:
//! - The pair's three padding bytes at +1..+4 are zeroed; the original
//!   leaves them as uninitialised stack. Nothing observes them (the
//!   comparator reads only the key byte; the node copy's pad word is
//!   never read back).
//! - 0x083b867c is dispatched through [`BYTE_KEY_MAP_OPS`], whose
//!   shipped default is the port [`byte_key_tree_insert_unique`] in
//!   this module; the find's tests still install stubs/mocks through
//!   the slot. The tree insert in turn dispatches `_M_insert` through
//!   [`BYTE_KEY_TREE_OPS`] (shipped default: the port
//!   [`byte_key_tree_insert_node`]), which allocates through
//!   [`BYTE_KEY_ALLOC_OPS`] (shipped default: the ported pool
//!   allocator [`byte_key_tree_allocate_node`], carving nodes out of
//!   `operator_new_checked` arenas — with the whole chain at its
//!   shipped defaults an insertion really links a node).
//! - The final `node + 0x14` is a wrapping add (the original's plain
//!   `add r0, r0, #0x14`); with a real node installed the value is
//!   identical.

/// The 16-byte key/value pair the find builds on its stack frame and
/// hands to the tree operation: key byte at +0, padding at +1..+4,
/// default-constructed (zeroed) 12-byte mapped value at +4. Matches the
/// original's stack layout at sp+0x14..sp+0x24 exactly.
#[repr(C)]
pub struct ByteKeyPair {
    /// +0: the key byte, read from `*key`.
    pub key: u8,
    /// +1..+4: padding (zeroed here; stack garbage in the original).
    pub pad: [u8; 3],
    /// +4: the zeroed 12-byte mapped value.
    pub value: [u32; 3],
}

// The pair is all 4-byte-aligned members, so the original's offsets
// hold on every host — asserted unconditionally.
const _VALUE_OFFSET: [u8; 4] = [0; core::mem::offset_of!(ByteKeyPair, value)];
const _PAIR_SIZE: [u8; 16] = [0; core::mem::size_of::<ByteKeyPair>()];

/// The result the tree operation @ 0x083b867c writes through its first
/// argument: node pointer at +0, inserted-flag byte at +4. The find
/// consumes only the node word.
#[repr(C)]
pub struct ByteKeyInsertResult {
    /// +0: node pointer — the existing node for `key`, or the freshly
    /// linked one.
    pub node: *mut u8,
    /// +4: inserted flag byte (1 = newly linked, 0 = key was present).
    pub inserted: u8,
}

/// The byte-keyed map container. Opaque to this port — only its address
/// is forwarded to the insert hook. Scouted layout, from 0x083b867c's
/// reads: +0x10 header node (header+4 = root, header+8 = leftmost),
/// +0x18 multi-insert flag byte, +0x19 key-comparator object.
#[repr(C)]
pub struct ByteKeyMap {
    _opaque: [u8; 0],
}

/// Indirect dispatch for the not-yet-ported tree insert-unique
/// operation @ 0x083b867c (the `PairHeaderOps` precedent in
/// `cxx/pair_header.rs`).
#[derive(Clone, Copy)]
pub struct ByteKeyMapOps {
    /// The container operation @ 0x083b867c: writes the node pointer at
    /// `result + 0` and the inserted-flag byte at `result + 4`. See the
    /// module header for the full scouted contract.
    pub insert_unique: unsafe extern "C" fn(
        result: *mut ByteKeyInsertResult,
        map: *mut ByteKeyMap,
        key: *const ByteKeyPair,
    ),
}

/// Default stub from before 0x083b867c was ported: no tree wired, so
/// report "not found, not inserted" with a null node — the find then
/// returns 0x14 (null + 0x14), an obviously invalid value pointer. The
/// shipped default is now the port below; retained for the host tests
/// (a null node can never come out of the real operation — the header
/// node always exists).
#[allow(dead_code)] // test-only since 0x083b867c was ported
unsafe extern "C" fn missing_insert_unique(
    result: *mut ByteKeyInsertResult,
    _map: *mut ByteKeyMap,
    _key: *const ByteKeyPair,
) {
    (*result).node = core::ptr::null_mut();
    (*result).inserted = 0;
}

/// The active tree-operation slot. The shipped default is the port
/// [`byte_key_tree_insert_unique`] below; host tests install recording
/// mocks (and the documented stub above) through the slot. Written once
/// at init on target; tests serialize access.
pub static mut BYTE_KEY_MAP_OPS: ByteKeyMapOps = ByteKeyMapOps {
    insert_unique: byte_key_tree_insert_unique,
};

/// byte_key_map_find — original: `FUN_083db038` @ 0x083db038
/// (88 bytes; 26 `bl` call sites, the only copy).
///
/// Finds (or inserts) the node for the single byte at `*key` in `map`
/// and returns a pointer to its mapped value, `node + 0x14`. Builds the
/// 16-byte key pair (key byte + zeroed 12-byte value) on the stack and
/// runs the tree insert-unique operation @ 0x083b867c through
/// [`BYTE_KEY_MAP_OPS`]; only the result's node word is consumed, the
/// inserted-flag byte is dropped.
///
/// # Safety
/// `key` must point at a readable byte and `map` at a live container
/// whose layout matches the scouted one in the module header. The
/// installed `insert_unique` must honour the 0x083b867c contract (node
/// word at result+0, flag byte at result+4); the shipped default is
/// the port below, which — with the whole slot chain at its shipped
/// defaults — inserts through the ported `_M_insert` and pool
/// allocator. (Only a test-installed stub reports a null fresh node;
/// the returned pointer is then 0x14 and must not be dereferenced.)
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_map_find(map: *mut ByteKeyMap, key: *const u8) -> *mut u8 {
    let pair = ByteKeyPair {
        key: key.read(),
        pad: [0; 3],
        value: [0; 3],
    };
    let mut result = ByteKeyInsertResult {
        node: core::ptr::null_mut(),
        inserted: 0,
    };
    // Reads the fn-pointer field directly rather than through a
    // whole-table read (the timer_schedule_shim gotcha).
    let insert_unique =
        core::ptr::addr_of!(BYTE_KEY_MAP_OPS.insert_unique).read_volatile();
    insert_unique(&mut result, map, &pair);
    result.node.wrapping_add(0x14)
}

// ---------------------------------------------------------------------------
// The tree insert-unique operation itself (@ 0x083b867c).
// ---------------------------------------------------------------------------

/// A red-black tree node: the 0x10-byte header (color byte, parent /
/// left / right links) followed by the key pair at +0x10. Fields are
/// typed struct members, never literal byte offsets: the 32-bit target
/// layout is exact (asserted below) while a 64-bit host keeps the
/// fields disjoint (the `NodeList` precedent in `app/node_list.rs`).
#[repr(C)]
pub struct ByteKeyTreeNode {
    /// +0: red-black color byte (0 = red; the header node is red).
    pub color: u8,
    /// +1..+4: padding.
    pub _pad: [u8; 3],
    /// +4: parent link.
    pub parent: *mut ByteKeyTreeNode,
    /// +8: left child (smaller keys), null when absent.
    pub left: *mut ByteKeyTreeNode,
    /// +0xc: right child, null when absent.
    pub right: *mut ByteKeyTreeNode,
    /// +0x10: the 16-byte key pair (key byte at +0x10).
    pub key: ByteKeyPair,
}

/// The container as this operation reads it: the header node pointer
/// at +0x10 (header.parent = root, header.left = leftmost), the node
/// count at +0x14 (written by `_M_insert`, not read here) and the
/// multi-insert flag byte at +0x18. +0x19 is the stateless comparator
/// object, which the byte comparator never reads.
#[repr(C)]
pub struct ByteKeyTree {
    /// +0..+0x10: the node pool state [`byte_key_tree_allocate_node`]
    /// owns — see [`ByteKeyNodePool`]. Sized off that struct so the
    /// fields stay disjoint on a 64-bit host (the pool's pointers
    /// widen past 0x10 there); exactly 0x10 on the 32-bit target,
    /// where the layout checks below pin `header` at +0x10.
    pub _opaque: [u8; core::mem::size_of::<ByteKeyNodePool>()],
    /// +0x10: the header node.
    pub header: *mut ByteKeyTreeNode,
    /// +0x14: live node count.
    pub node_count: u32,
    /// +0x18: multi-insert flag byte (nonzero = multimap semantics:
    /// skip the uniqueness test, always link a fresh node).
    pub multi_insert: u8,
    /// +0x19: key-comparator object (stateless `less<u8>`; never read).
    pub comparator: u8,
}

// Target-exact layout; on a 64-bit host the pointer fields widen and
// the offsets shift — harmless, all access goes through the structs.
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x4] = [0; core::mem::offset_of!(ByteKeyTreeNode, parent)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(ByteKeyTreeNode, left)];
    const _: [u8; 0xc] = [0; core::mem::offset_of!(ByteKeyTreeNode, right)];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(ByteKeyTreeNode, key)];
    const _: [u8; 0x20] = [0; core::mem::size_of::<ByteKeyTreeNode>()];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(ByteKeyTree, header)];
    const _: [u8; 0x14] = [0; core::mem::offset_of!(ByteKeyTree, node_count)];
    const _: [u8; 0x18] = [0; core::mem::offset_of!(ByteKeyTree, multi_insert)];
    const _: [u8; 0x19] = [0; core::mem::offset_of!(ByteKeyTree, comparator)];
}

/// byte-key less-than comparator — the body of `FUN_083d73bc` @
/// 0x083d73bc (20 bytes), the `less<u8>::operator()` instantiation this
/// tree was compiled with: `return *a < *b` on the pairs' unsigned key
/// bytes (`ldrb`/`cmp`/`movcs`/`movcc`). Inlined here; the original
/// calls it by `bl` with the comparator object at map+0x19 in r0, which
/// the stateless body ignores.
#[inline(always)]
unsafe fn byte_key_less(a: *const ByteKeyPair, b: *const ByteKeyPair) -> bool {
    (*a).key < (*b).key
}

/// Iterator decrement (predecessor) — the walk the original emits
/// inline at 0x083b8768-0x083b87c4 (old libstdc++ `_Rb_tree_decrement`;
/// the iterator-equality helper @ 0x083cf740 is a one-word compare,
/// folded into the caller's `position == begin` test). The header node
/// is recognised by its red (0) color byte plus the parent->parent
/// self-loop and steps to its rightmost child; otherwise descend the
/// left subtree to its rightmost node, or ascend while the current
/// node is its parent's left child. In this function the walk only
/// ever runs on a non-header node with a null left child (the begin()
/// check catches the header, and a non-null left would have been
/// descended into), so only the ascend loop is reachable — the other
/// branches are kept for fidelity with the original.
#[inline(always)]
unsafe fn rb_tree_predecessor(
    mut node: *mut ByteKeyTreeNode,
) -> *mut ByteKeyTreeNode {
    if (*node).color == 0 && (*(*node).parent).parent == node {
        return (*node).right;
    }
    let left = (*node).left;
    if !left.is_null() {
        let mut rightmost = left;
        loop {
            let next = (*rightmost).right;
            if next.is_null() {
                return rightmost;
            }
            rightmost = next;
        }
    }
    let mut parent = (*node).parent;
    while (*parent).left == node {
        node = parent;
        parent = (*parent).parent;
    }
    parent
}

/// Indirect dispatch for the node linker `_M_insert` @ 0x083b8844
/// (480 bytes; allocates a node @ 0x083b7f40, copies the pair, links
/// it under `parent` and rebalances via the rotations @ 0x083b8090 /
/// 0x083b80e4). Now ported as [`byte_key_tree_insert_node`] below, the
/// shipped default of the slot. The `PairHeaderOps` precedent in
/// `cxx/pair_header.rs`.
#[derive(Clone, Copy)]
pub struct ByteKeyTreeOps {
    /// `_M_insert` @ 0x083b8844(result, map, insert_position, parent,
    /// key): links a fresh node carrying `key` under `parent` (as its
    /// left child when `insert_position` is nonzero, else by comparing
    /// the key pair against `parent`'s), rebalances, and writes the new
    /// node pointer at `result + 0`. The insert-unique port always
    /// calls it with `insert_position == 0`, matching the original
    /// (r2 = the null child the descent stopped at).
    pub insert_node: unsafe extern "C" fn(
        result: *mut *mut u8,
        map: *mut ByteKeyMap,
        insert_position: *mut u8,
        parent: *mut u8,
        key: *const ByteKeyPair,
    ),
}

/// Default stub from before 0x083b8844 was ported: report a null fresh
/// node — an insert then stores null at result+0 with the flag set,
/// and the find returns 0x14. The shipped default is now the port
/// below; retained for the host tests.
#[allow(dead_code)] // test-only since 0x083b8844 was ported
unsafe extern "C" fn missing_insert_node(
    result: *mut *mut u8,
    _map: *mut ByteKeyMap,
    _insert_position: *mut u8,
    _parent: *mut u8,
    _key: *const ByteKeyPair,
) {
    result.write(core::ptr::null_mut());
}

/// The active node-linker slot. The shipped default is the port
/// [`byte_key_tree_insert_node`] below; host tests install recording
/// mocks (and the documented stub above) through the slot. Written
/// once at init on target; tests serialize access.
pub static mut BYTE_KEY_TREE_OPS: ByteKeyTreeOps = ByteKeyTreeOps {
    insert_node: byte_key_tree_insert_node,
};

/// Indirect dispatch for the tree's node allocator @ 0x083b7f40 (176
/// bytes; a 0x20-byte-node pool with a free list threaded through
/// node+0xc and 1.5x growth chunks from `operator new` @ 0x08266c70 —
/// itself a throwing wrapper over `FUN_082aadd4`). Ported as
/// [`byte_key_tree_allocate_node`] below, the shipped default of the
/// slot; the ported [`byte_key_tree_insert_node`] rides this slot.
#[derive(Clone, Copy)]
pub struct ByteKeyTreeAllocOps {
    /// Node allocator @ 0x083b7f40(map) -> node: hands out a fresh
    /// 0x20-byte tree node with the color byte at +0 set to 0 (red),
    /// parent/left/right at +4/+8/+0xc nulled, and the key pair at
    /// +0x10 uninitialised (the caller copy-constructs it). Never
    /// returns null in the original — a failed `operator new` throws
    /// (abort path @ 0x08266abc), so `_M_insert` has no null check.
    pub allocate_node:
        unsafe extern "C" fn(map: *mut ByteKeyMap) -> *mut ByteKeyTreeNode,
}

/// Stub from before 0x083b7f40 was ported: report null — the ported
/// `_M_insert` then writes a null fresh node at its result and returns
/// (a documented deviation; the original cannot fail here). The
/// shipped default is now the port below; retained for the host tests.
#[allow(dead_code)] // test-only since 0x083b7f40 was ported
unsafe extern "C" fn missing_allocate_node(
    _map: *mut ByteKeyMap,
) -> *mut ByteKeyTreeNode {
    core::ptr::null_mut()
}

/// The active node-allocator slot. The shipped default is the port
/// [`byte_key_tree_allocate_node`] below; host tests install arena
/// mocks (and the documented stub above) through the slot. Written
/// once at init on target; tests serialize access.
pub static mut BYTE_KEY_ALLOC_OPS: ByteKeyTreeAllocOps = ByteKeyTreeAllocOps {
    allocate_node: byte_key_tree_allocate_node,
};

/// Links a fresh node for `key` under `parent` through the
/// [`BYTE_KEY_TREE_OPS`] slot and reports it flagged as inserted — the
/// original's three identical `bl 0x083b8844` tails (0x083b86e4,
/// 0x083b873c and the multi-insert fall-through), each passing
/// insert_position = 0.
#[inline(always)]
unsafe fn link_fresh_node(
    result: *mut ByteKeyInsertResult,
    map: *mut ByteKeyMap,
    parent: *mut ByteKeyTreeNode,
    key: *const ByteKeyPair,
) {
    // Reads the fn-pointer field directly rather than through a
    // whole-table read (the timer_schedule_shim gotcha).
    let insert_node = core::ptr::addr_of!(BYTE_KEY_TREE_OPS.insert_node).read_volatile();
    let mut fresh: *mut u8 = core::ptr::null_mut();
    insert_node(&mut fresh, map, core::ptr::null_mut(), parent.cast::<u8>(), key);
    (*result).node = fresh;
    (*result).inserted = 1;
}

/// byte_key_tree_insert_unique — original: `FUN_083b867c` @ 0x083b867c
/// (396 bytes; called from `byte_key_map_find` @ 0x083db038 and its
/// siblings).
///
/// libstdc++ `_Rb_tree::_M_insert_unique` for a byte-keyed map: descend
/// from the root (`header->parent`; the header node pointer is at
/// map+0x10) comparing the new pair's key byte against each node's key
/// at node+0x10 — less-than goes left (+8), else right (+0xc) — and
/// remember the last node (`parent`) and the last direction. With the
/// multi-insert byte at map+0x18 clear (map semantics): if the last
/// step went left, a `position == header->left` (begin) test decides an
/// immediate insert, else `position` becomes its in-order predecessor;
/// the candidate's key is then compared against the new key — an
/// existing key (`!(pos_key < new_key)`) returns the existing node with
/// the inserted flag 0, otherwise a fresh node is linked under `parent`
/// via `_M_insert` @ 0x083b8844 and returned flagged 1. With the
/// multi-insert byte set (multimap semantics) the uniqueness test is
/// skipped and every call links a fresh node.
///
/// The result contract (see the module header): node pointer at
/// `result + 0`, inserted-flag byte at `result + 4`.
///
/// Deviations:
/// - The comparator @ 0x083d73bc (unsigned byte less-than), the
///   iterator-equality helper @ 0x083cf740 (one-word compare) and the
///   key accessor @ 0x083b6a44 (`node + 0x10`) are one-/few-instruction
///   leaves and are inlined; the original reaches them by `bl`.
/// - `_M_insert` @ 0x083b8844 is ported as
///   [`byte_key_tree_insert_node`], the shipped default of the
///   [`BYTE_KEY_TREE_OPS`] slot; its allocator is ported as
///   [`byte_key_tree_allocate_node`], the shipped default of
///   [`BYTE_KEY_ALLOC_OPS`].
/// - The original zeroes two stack result words per descent step
///   (`str r10, [sp,#0xc]/[sp,#0x10]` inside the loop) — dead scratch
///   stores, dropped here.
///
/// # Safety
/// `result` must point at 8 writable bytes, `map` at a live container
/// matching the scouted layout (module header), and `key` at a readable
/// 16-byte pair. The installed `insert_node` must honour the 0x083b8844
/// contract (fresh node pointer at its result+0).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_tree_insert_unique(
    result: *mut ByteKeyInsertResult,
    map: *mut ByteKeyMap,
    key: *const ByteKeyPair,
) {
    let tree = map.cast::<ByteKeyTree>();
    let header = (*tree).header;
    let mut node = (*header).parent;
    let mut parent = header;
    let mut went_left = true;
    while !node.is_null() {
        went_left = byte_key_less(key, core::ptr::addr_of!((*node).key));
        parent = node;
        node = if went_left { (*node).left } else { (*node).right };
    }

    if (*tree).multi_insert == 0 {
        let mut position = parent;
        if went_left {
            // header.left is the leftmost node (begin()); the original
            // compares the two iterator words through 0x083cf740.
            if position == (*header).left {
                link_fresh_node(result, map, parent, key);
                return;
            }
            position = rb_tree_predecessor(position);
        }
        if byte_key_less(core::ptr::addr_of!((*position).key), key) {
            link_fresh_node(result, map, parent, key);
            return;
        }
        (*result).node = position.cast::<u8>();
        (*result).inserted = 0;
        return;
    }
    link_fresh_node(result, map, parent, key);
}

// ---------------------------------------------------------------------------
// The node linker `_M_insert` itself (@ 0x083b8844), with the two
// rotations it rebalances through (@ 0x083b8090 / 0x083b80e4).
// ---------------------------------------------------------------------------

/// byte_key_tree_rotate_left — original: `FUN_083b8090` @ 0x083b8090
/// (84 bytes; `_Rb_tree_rotate_left`, called by `_M_insert` and the
/// erase rebalance).
///
/// Left rotation around `node`: `right` takes `node`'s place (under
/// the root pointer at header+4 when `node` is the root, else under
/// `node`'s parent on the side `node` hangs from), `node` adopts
/// `right`'s left subtree as its right child (re-parenting it when
/// non-null) and becomes `right`'s left child.
#[inline(never)]
unsafe fn byte_key_tree_rotate_left(
    tree: *mut ByteKeyTree,
    node: *mut ByteKeyTreeNode,
) {
    let right = (*node).right;
    (*node).right = (*right).left;
    if !(*right).left.is_null() {
        (*(*right).left).parent = node;
    }
    (*right).parent = (*node).parent;
    let root_slot = core::ptr::addr_of_mut!((*(*tree).header).parent);
    if *root_slot == node {
        *root_slot = right;
    } else {
        let parent = (*node).parent;
        if (*parent).left == node {
            (*parent).left = right;
        } else {
            (*parent).right = right;
        }
    }
    (*right).left = node;
    (*node).parent = right;
}

/// byte_key_tree_rotate_right — original: `FUN_083b80e4` @ 0x083b80e4
/// (84 bytes; `_Rb_tree_rotate_right`, the mirror of 0x083b8090).
///
/// Right rotation around `node`: `left` takes `node`'s place (root
/// pointer first, else the matching side of `node`'s parent), `node`
/// adopts `left`'s right subtree as its left child and becomes
/// `left`'s right child.
#[inline(never)]
unsafe fn byte_key_tree_rotate_right(
    tree: *mut ByteKeyTree,
    node: *mut ByteKeyTreeNode,
) {
    let left = (*node).left;
    (*node).left = (*left).right;
    if !(*left).right.is_null() {
        (*(*left).right).parent = node;
    }
    (*left).parent = (*node).parent;
    let root_slot = core::ptr::addr_of_mut!((*(*tree).header).parent);
    if *root_slot == node {
        *root_slot = left;
    } else {
        let parent = (*node).parent;
        if (*parent).right == node {
            (*parent).right = left;
        } else {
            (*parent).left = left;
        }
    }
    (*left).right = node;
    (*node).parent = left;
}

/// byte_key_tree_insert_node — original: `FUN_083b8844` @ 0x083b8844
/// (480 bytes; libstdc++ `_Rb_tree::_M_insert` for the byte-keyed map
/// family, the node-link + rebalance path — its caller
/// [`byte_key_tree_insert_unique`] @ 0x083b867c is the ported
/// insert-unique above).
///
/// Allocates a fresh 0x20-byte node through the pool allocator @
/// 0x083b7f40 (dispatched via [`BYTE_KEY_ALLOC_OPS`], shipped default
/// the port [`byte_key_tree_allocate_node`]; it initialises
/// color = 0/red and nulls the three links), copy-constructs the
/// 16-byte pair into node+0x10 and bumps the node count at map+0x14.
/// Linking: when `parent` is the header (map+0x10) or
/// `insert_position` is nonzero, the node becomes `parent`'s left
/// child (+8) — a header parent also takes it as root (header+4) and
/// rightmost (header+0xc), otherwise the leftmost pointer (header+8)
/// follows when `parent` was the leftmost. Otherwise the pair's key is
/// compared against `parent`'s through the byte comparator @
/// 0x083d73bc: less-than links left (same leftmost follow-up), else
/// links right (+0xc) with the rightmost pointer following when
/// `parent` was the rightmost. The node is then re-parented to
/// `parent` and rebalanced exactly like
/// `_Rb_tree_rebalance_for_insert`: while the node is not the root and
/// its parent is red (color 0), a red uncle recolors parent/uncle
/// black (1) and grandparent red (0) and ascends two levels; a
/// black/absent uncle rotates — inner child first rotates the parent
/// down (left case: rotate_left @ 0x083b8090 on the parent, then
/// rotate_right @ 0x083b80e4 on the grandparent; mirrored on the
/// right) — then parent black, grandparent red. The loop exits with
/// the root recolored black and the new node written at `result + 0`.
///
/// Deviations:
/// - The allocator never returns null in the original (`operator new`
///   throws, abort @ 0x08266abc), so the original has no null check;
///   with the test-only [`BYTE_KEY_ALLOC_OPS`] stub this port writes a
///   null fresh node at `result + 0` and returns without touching the
///   tree (the stub's documented contract).
/// - The placement-new guard `node + 0x10 != null` around the pair
///   copy can only fail for a null node (handled above) and is
///   dropped.
/// - The comparator @ 0x083d73bc (unsigned byte less-than) is a
///   one-instruction leaf, inlined; the rotations are kept as separate
///   `#[inline(never)]` functions to preserve the original's `bl`
///   boundaries. The original passes dead extra register arguments to
///   the rotations (r2-r5 garbage at one site); dropped.
///
/// # Safety
/// `result` must point at a writable word, `map` at a live container
/// matching the scouted [`ByteKeyTree`] layout, `parent` at a live
/// node (or the header), and `key` at a readable 16-byte pair. The
/// installed `allocate_node` must honour the 0x083b7f40 contract
/// (fresh node: color 0, links null) or return null to abort.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_tree_insert_node(
    result: *mut *mut u8,
    map: *mut ByteKeyMap,
    insert_position: *mut u8,
    parent: *mut u8,
    key: *const ByteKeyPair,
) {
    let tree = map.cast::<ByteKeyTree>();
    // Reads the fn-pointer field directly rather than through a
    // whole-table read (the timer_schedule_shim gotcha).
    let allocate_node =
        core::ptr::addr_of!(BYTE_KEY_ALLOC_OPS.allocate_node).read_volatile();
    let node = allocate_node(map);
    if node.is_null() {
        // Unreachable in the original (operator new throws); only the
        // documented stub lands here.
        result.write(core::ptr::null_mut());
        return;
    }
    let fresh = node;
    (*node).key = core::ptr::read(key);
    (*tree).node_count = (*tree).node_count.wrapping_add(1);

    let header = (*tree).header;
    let parent_node = parent.cast::<ByteKeyTreeNode>();
    let mut link_left = parent_node == header || !insert_position.is_null();
    if !link_left {
        link_left = byte_key_less(key, core::ptr::addr_of!((*parent_node).key));
    }
    if link_left {
        (*parent_node).left = node;
        if parent_node == header {
            (*header).parent = node; // root
            (*header).right = node; // rightmost
        } else if (*header).left == parent_node {
            (*header).left = node; // new leftmost
        }
    } else {
        (*parent_node).right = node;
        if (*header).right == parent_node {
            (*header).right = node; // new rightmost
        }
    }
    (*node).parent = parent_node;

    // Rebalance (0 = red, 1 = black): ascend while the parent is red.
    let mut node = node;
    while (*header).parent != node && (*(*node).parent).color == 0 {
        let parent = (*node).parent;
        let grandparent = (*parent).parent;
        if parent == (*grandparent).left {
            let uncle = (*grandparent).right;
            if !uncle.is_null() && (*uncle).color == 0 {
                (*parent).color = 1;
                (*uncle).color = 1;
                (*grandparent).color = 0;
                node = grandparent;
            } else {
                if (*parent).right == node {
                    byte_key_tree_rotate_left(tree, parent);
                    node = parent;
                }
                let parent = (*node).parent;
                (*parent).color = 1;
                let grandparent = (*parent).parent;
                (*grandparent).color = 0;
                byte_key_tree_rotate_right(tree, grandparent);
            }
        } else {
            let uncle = (*grandparent).left;
            if !uncle.is_null() && (*uncle).color == 0 {
                (*parent).color = 1;
                (*uncle).color = 1;
                (*grandparent).color = 0;
                node = grandparent;
            } else {
                if (*parent).left == node {
                    byte_key_tree_rotate_right(tree, parent);
                    node = parent;
                }
                let parent = (*node).parent;
                (*parent).color = 1;
                let grandparent = (*parent).parent;
                (*grandparent).color = 0;
                byte_key_tree_rotate_left(tree, grandparent);
            }
        }
    }
    (*(*header).parent).color = 1;
    result.write(fresh.cast::<u8>());
}

// ---------------------------------------------------------------------------
// The pool allocator itself (@ 0x083b7f40).
// ---------------------------------------------------------------------------

/// The node pool state the allocator owns in the container's first
/// 0x10 bytes (the `_opaque` head of [`ByteKeyTree`]; the container
/// base subobject doubles as the node pool — libstdc++'s old
/// `_Rb_tree` kept its allocator's pool in the same words). Fields are
/// typed struct members, never literal byte offsets: the 32-bit target
/// layout is exact (asserted below) while a 64-bit host keeps the
/// fields disjoint (the `NodeList` precedent in `app/node_list.rs`).
#[repr(C)]
pub struct ByteKeyNodePool {
    /// +0: newest growth-chunk header (0xc bytes: prev / capacity /
    /// arena); null until the first arena is carved.
    pub chunk_head: *mut ByteKeyPoolChunk,
    /// +4: free-list head, threaded through the freed node's +0xc word
    /// (its right link).
    pub free_list: *mut ByteKeyTreeNode,
    /// +8: bump cursor into the current arena.
    pub bump: *mut u8,
    /// +0xc: end of the current arena; `bump == bump_end` means grow.
    pub bump_end: *mut u8,
}

/// A growth-chunk header (0xc bytes): the intrusive list of arenas the
/// pool carved, newest first.
#[repr(C)]
pub struct ByteKeyPoolChunk {
    /// +0: the previous (older) chunk header.
    pub prev: *mut ByteKeyPoolChunk,
    /// +4: node capacity of this chunk's arena.
    pub capacity: u32,
    /// +8: the arena — `capacity` nodes of 0x20 bytes each.
    pub arena: *mut u8,
}

// Target-exact layout; on a 64-bit host the pointer fields widen and
// the offsets shift — harmless, all access goes through the structs.
#[cfg(target_pointer_width = "32")]
mod pool_layout_checks {
    use super::*;
    const _: [u8; 0x4] = [0; core::mem::offset_of!(ByteKeyNodePool, free_list)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(ByteKeyNodePool, bump)];
    const _: [u8; 0xc] = [0; core::mem::offset_of!(ByteKeyNodePool, bump_end)];
    const _: [u8; 0x10] = [0; core::mem::size_of::<ByteKeyNodePool>()];
    const _: [u8; 0x4] = [0; core::mem::offset_of!(ByteKeyPoolChunk, capacity)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(ByteKeyPoolChunk, arena)];
    const _: [u8; 0xc] = [0; core::mem::size_of::<ByteKeyPoolChunk>()];
    const _: [u8; 0x20] = [0; core::mem::size_of::<ByteKeyTreeNode>()];
}

/// `#[inline(never)]` front-end for the checked operator new @
/// 0x08266c70 (ported in heap/veneers.rs): on device the original
/// allocator reaches it with `bl` from both allocation sites, and
/// letting LLVM inline the null-check + new-handler path into the
/// allocator nearly doubles its size and destroys the structural
/// match (the `operator_new` `inline(never)` rationale in
/// heap/veneers.rs).
#[inline(never)]
fn pool_operator_new(size: usize) -> *mut u8 {
    unsafe { crate::heap::veneers::operator_new_checked(size) }
}

/// byte_key_tree_allocate_node — original: `FUN_083b7f40` @ 0x083b7f40
/// (176 bytes; called from `_M_insert` @ 0x083b8844 — the ported
/// [`byte_key_tree_insert_node`] — and one sibling site @ 0x08258b24).
///
/// libstdc++'s pool allocator for the byte-keyed map family's 0x20-byte
/// tree nodes. If the free list at map+4 is non-empty, pop its head
/// (the next pointer is threaded through the node's +0xc word). Else
/// bump-allocate from the current arena (cursor at map+8, end at
/// map+0xc); when the cursor reaches the end, grow first: capacity is
/// `max(prev + 0x20, prev + prev/2 + prev/8)` of the newest chunk's
/// capacity (0x20 for the first chunk), then a 0xc-byte chunk header
/// and a `capacity * 0x20` arena are carved by two calls to the checked
/// operator new @ 0x08266c70, the chunk is pushed at map+0 (prev link,
/// capacity, arena pointer), and the arena becomes the new bump range.
/// The handed-out node gets its parent/left/right words at +4/+8/+0xc
/// nulled and its color byte at +0 set to 0 (red); the key pair at
/// +0x10 is left uninitialised for the caller to copy-construct.
///
/// Deviations:
/// - The node stride and chunk-header size go through `size_of`
///   (0x20 / 0xc on the 32-bit target — the original's `#0x20` / `#0xc`
///   immediates — wider on 64-bit hosts, where that keeps the fields
///   disjoint; the `NodeList` precedent).
/// - The original passes a dead `r1 = 0` second argument to
///   0x08266c70 (the callee only stack-saves it); the ported
///   `operator_new_checked` (heap/veneers.rs) takes the size alone and
///   is reached through the `#[inline(never)]` [`pool_operator_new`]
///   front-end to preserve the original's two `bl` boundaries.
/// - Like the original, there is no null check on the checked-new
///   results: the original's new-handler path (abort @ 0x08266abc)
///   cannot produce a usable null, and a hypothetical one would fault
///   on the chunk-header store exactly as the original would.
///
/// # Safety
/// `map` must point at a live container whose first 0x10 bytes are the
/// pool state ([`ByteKeyNodePool`]); on a freshly constructed container
/// those words are zero (no chunks, empty free list, empty bump range),
/// which the growth path handles. The returned node's key pair is
/// uninitialised — the caller must construct it before any read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_tree_allocate_node(
    map: *mut ByteKeyMap,
) -> *mut ByteKeyTreeNode {
    const NODE_SIZE: usize = core::mem::size_of::<ByteKeyTreeNode>();
    let pool = map.cast::<ByteKeyNodePool>();
    let node: *mut ByteKeyTreeNode;
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
                    let grown = prev
                        .wrapping_add(prev >> 1)
                        .wrapping_add(prev >> 3);
                    prev.wrapping_add(0x20).max(grown)
                }
            };
            let chunk = pool_operator_new(
                core::mem::size_of::<ByteKeyPoolChunk>(),
            )
            .cast::<ByteKeyPoolChunk>();
            let arena = pool_operator_new(
                (capacity as usize).wrapping_mul(NODE_SIZE),
            );
            (*chunk).arena = arena;
            (*chunk).prev = (*pool).chunk_head;
            (*chunk).capacity = capacity;
            (*pool).chunk_head = chunk;
            bump = arena;
            (*pool).bump_end =
                arena.add((capacity as usize).wrapping_mul(NODE_SIZE));
        }
        node = bump.cast::<ByteKeyTreeNode>();
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
    use std::sync::Mutex as StdMutex;
    use std::vec::Vec;

    /// Ops-table swaps are global; serialize the tests.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    struct OpsGuard;

    impl OpsGuard {
        fn install(ops: ByteKeyMapOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_MAP_OPS).write_volatile(ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_MAP_OPS).write_volatile(
                    ByteKeyMapOps {
                        insert_unique: missing_insert_unique,
                    },
                );
            }
        }
    }

    /// With the default stub the hook reports a null node and the find
    /// returns null + 0x14 — and the map/key pointers are never
    /// dereferenced beyond the key byte itself.
    #[test]
    fn default_stub_returns_null_plus_header() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: missing_insert_unique,
        });
        unsafe {
            let key: u8 = 0x42;
            let value = byte_key_map_find(core::ptr::null_mut(), &key);
            assert_eq!(value as usize, 0x14);
        }
    }

    /// The hook receives the map pointer unchanged and a pair carrying
    /// the key byte at +0 with a fully zeroed 12-byte value; the find
    /// returns the hook's node plus 0x14.
    #[test]
    fn pair_shape_and_return_offset() {
        let _lock = OPS_LOCK.lock().unwrap();

        static mut SEEN_MAP: usize = 0;
        static mut SEEN_KEY: u8 = 0;
        static mut SEEN_VALUE: [u32; 3] = [1; 3];
        /// Fake node storage; the hook hands out its base.
        static mut NODE: [u8; 0x20] = [0; 0x20];

        unsafe extern "C" fn recording_insert_unique(
            result: *mut ByteKeyInsertResult,
            map: *mut ByteKeyMap,
            key: *const ByteKeyPair,
        ) {
            core::ptr::addr_of_mut!(SEEN_MAP).write_volatile(map as usize);
            core::ptr::addr_of_mut!(SEEN_KEY).write_volatile((*key).key);
            core::ptr::addr_of_mut!(SEEN_VALUE).write_volatile((*key).value);
            (*result).node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            (*result).inserted = 1;
        }

        let _guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: recording_insert_unique,
        });
        unsafe {
            let mut map_storage = Vec::from([0u8; 0x20]);
            let map = map_storage.as_mut_ptr().cast::<ByteKeyMap>();
            let key: u8 = 0xa5;
            let value = byte_key_map_find(map, &key);

            assert_eq!(
                core::ptr::addr_of!(SEEN_MAP).read_volatile(),
                map as usize
            );
            assert_eq!(core::ptr::addr_of!(SEEN_KEY).read_volatile(), 0xa5);
            assert_eq!(core::ptr::addr_of!(SEEN_VALUE).read_volatile(), [0; 3]);
            let node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            assert_eq!(value, node.add(0x14));
        }
    }

    /// A found-not-inserted result (flag byte 0) still yields node +
    /// 0x14; the find never reads the flag.
    #[test]
    fn existing_node_ignores_inserted_flag() {
        let _lock = OPS_LOCK.lock().unwrap();

        static mut NODE: [u8; 0x20] = [0; 0x20];

        unsafe extern "C" fn found_insert_unique(
            result: *mut ByteKeyInsertResult,
            _map: *mut ByteKeyMap,
            _key: *const ByteKeyPair,
        ) {
            (*result).node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            (*result).inserted = 0;
        }

        let _guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: found_insert_unique,
        });
        unsafe {
            let key: u8 = 0x00;
            let value = byte_key_map_find(core::ptr::null_mut(), &key);
            let node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            assert_eq!(value, node.add(0x14));
        }
    }

    // --- byte_key_tree_insert_unique (@ 0x083b867c) -------------------

    struct TreeOpsGuard;

    impl TreeOpsGuard {
        fn install(ops: ByteKeyTreeOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_TREE_OPS).write_volatile(ops);
            }
            TreeOpsGuard
        }
    }

    impl Drop for TreeOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_TREE_OPS).write_volatile(
                    ByteKeyTreeOps {
                        insert_node: missing_insert_node,
                    },
                );
            }
        }
    }

    /// A pair carrying just a key byte, like the find builds.
    fn key_pair(key: u8) -> ByteKeyPair {
        ByteKeyPair {
            key,
            pad: [0; 3],
            value: [0; 3],
        }
    }

    /// A black tree node carrying `key` (black = color 1, so the
    /// header self-loop check in the predecessor walk never fires on a
    /// real node).
    fn test_node(key: u8) -> ByteKeyTreeNode {
        ByteKeyTreeNode {
            color: 1,
            _pad: [0; 3],
            parent: core::ptr::null_mut(),
            left: core::ptr::null_mut(),
            right: core::ptr::null_mut(),
            key: key_pair(key),
        }
    }

    /// A red header node (libstdc++ marks the header red), no root,
    /// leftmost pointing at itself — the empty-tree shape.
    fn test_header() -> ByteKeyTreeNode {
        let mut header = test_node(0);
        header.color = 0;
        header
    }

    /// A container wired to `header`, uniqueness test on.
    fn test_tree(header: *mut ByteKeyTreeNode) -> ByteKeyTree {
        ByteKeyTree {
            _opaque: [0; core::mem::size_of::<ByteKeyNodePool>()],
            header,
            node_count: 0,
            multi_insert: 0,
            comparator: 0,
        }
    }

    // Recording state for the mock `_M_insert`.
    static mut INSERT_CALLS: usize = 0;
    static mut SEEN_MAP: usize = 0;
    static mut SEEN_POSITION: usize = 0;
    static mut SEEN_PARENT: usize = 0;
    static mut SEEN_KEY: u8 = 0;
    /// Fake fresh node the mock hands out.
    static mut FRESH_NODE: [u8; 0x30] = [0; 0x30];

    fn reset_recording() {
        unsafe {
            core::ptr::addr_of_mut!(INSERT_CALLS).write_volatile(0);
            core::ptr::addr_of_mut!(SEEN_MAP).write_volatile(0);
            core::ptr::addr_of_mut!(SEEN_POSITION).write_volatile(1);
            core::ptr::addr_of_mut!(SEEN_PARENT).write_volatile(0);
            core::ptr::addr_of_mut!(SEEN_KEY).write_volatile(0);
        }
    }

    unsafe extern "C" fn recording_insert_node(
        result: *mut *mut u8,
        map: *mut ByteKeyMap,
        insert_position: *mut u8,
        parent: *mut u8,
        key: *const ByteKeyPair,
    ) {
        let calls = core::ptr::addr_of!(INSERT_CALLS).read_volatile();
        core::ptr::addr_of_mut!(INSERT_CALLS).write_volatile(calls + 1);
        core::ptr::addr_of_mut!(SEEN_MAP).write_volatile(map as usize);
        core::ptr::addr_of_mut!(SEEN_POSITION).write_volatile(insert_position as usize);
        core::ptr::addr_of_mut!(SEEN_PARENT).write_volatile(parent as usize);
        core::ptr::addr_of_mut!(SEEN_KEY).write_volatile((*key).key);
        result.write(core::ptr::addr_of_mut!(FRESH_NODE).cast::<u8>());
    }

    /// Runs the port against `tree`; returns the result and the
    /// fresh-node pointer the mock hands out.
    unsafe fn run_insert(
        tree: *mut ByteKeyTree,
        key: u8,
    ) -> (ByteKeyInsertResult, *mut u8) {
        let pair = key_pair(key);
        let mut result = ByteKeyInsertResult {
            node: core::ptr::null_mut(),
            inserted: 0xaa,
        };
        byte_key_tree_insert_unique(&mut result, tree.cast::<ByteKeyMap>(), &pair);
        (result, core::ptr::addr_of_mut!(FRESH_NODE).cast::<u8>())
    }

    /// Empty tree (root null, leftmost == header): the begin() test
    /// hits immediately and the fresh node is linked under the header,
    /// flagged 1.
    #[test]
    fn empty_tree_inserts_under_header() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: recording_insert_node,
        });
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            (*header_ptr).left = header_ptr; // leftmost == header
            let mut tree = test_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let (result, fresh) = run_insert(tree_ptr, 5);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 1);
            assert_eq!(
                core::ptr::addr_of!(SEEN_PARENT).read_volatile(),
                header_ptr as usize
            );
            assert_eq!(core::ptr::addr_of!(SEEN_POSITION).read_volatile(), 0);
            assert_eq!(
                core::ptr::addr_of!(SEEN_MAP).read_volatile(),
                tree_ptr.cast::<ByteKeyMap>() as usize
            );
            assert_eq!(core::ptr::addr_of!(SEEN_KEY).read_volatile(), 5);
            assert_eq!(result.node, fresh);
            assert_eq!(result.inserted, 1);
        }
    }

    /// Single-node tree, same key: the descent goes right (equal keys
    /// are not less), the reverse compare fails too, so the existing
    /// node comes back with the flag clear and no linker call.
    #[test]
    fn existing_key_returns_node_flag_clear() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: recording_insert_node,
        });
        unsafe {
            let mut header = test_header();
            let mut node = test_node(7);
            let header_ptr = core::ptr::addr_of_mut!(header);
            let node_ptr = core::ptr::addr_of_mut!(node);
            (*node_ptr).parent = header_ptr;
            (*header_ptr).parent = node_ptr; // root
            (*header_ptr).left = node_ptr; // leftmost
            let mut tree = test_tree(header_ptr);

            let (result, _) = run_insert(core::ptr::addr_of_mut!(tree), 7);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 0);
            assert_eq!(result.node, node_ptr.cast::<u8>());
            assert_eq!(result.inserted, 0);
        }
    }

    /// Builds the common single-node tree: header's root and leftmost
    /// are the one node (boxed so the pointers stay put).
    fn single_node_tree(
        key: u8,
    ) -> (
        std::boxed::Box<ByteKeyTreeNode>,
        std::boxed::Box<ByteKeyTreeNode>,
        std::boxed::Box<ByteKeyTree>,
    ) {
        let mut header = std::boxed::Box::new(test_header());
        let mut node = std::boxed::Box::new(test_node(key));
        node.parent = &mut *header;
        header.parent = &mut *node; // root
        header.left = &mut *node; // leftmost
        let tree = std::boxed::Box::new(test_tree(&mut *header));
        (header, node, tree)
    }

    /// Single-node tree, smaller key: the descent goes left, position
    /// is the leftmost (begin) node, so the fresh node links right away
    /// under that node, flagged 1.
    #[test]
    fn new_minimum_inserts_at_begin() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: recording_insert_node,
        });
        unsafe {
            let (_header, node, mut tree) = single_node_tree(7);
            let node_ptr = core::ptr::addr_of!(*node).cast_mut();

            let (result, fresh) = run_insert(core::ptr::addr_of_mut!(*tree), 3);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 1);
            assert_eq!(
                core::ptr::addr_of!(SEEN_PARENT).read_volatile(),
                node_ptr as usize
            );
            assert_eq!(result.node, fresh);
            assert_eq!(result.inserted, 1);
        }
    }

    /// Single-node tree, larger key: right descent, the candidate's key
    /// compares less than the new key, so a fresh node links under it.
    #[test]
    fn new_maximum_inserts_after_right_descent() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: recording_insert_node,
        });
        unsafe {
            let (_header, node, mut tree) = single_node_tree(7);
            let node_ptr = core::ptr::addr_of!(*node).cast_mut();

            let (result, fresh) = run_insert(core::ptr::addr_of_mut!(*tree), 9);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 1);
            assert_eq!(
                core::ptr::addr_of!(SEEN_PARENT).read_volatile(),
                node_ptr as usize
            );
            assert_eq!(result.node, fresh);
            assert_eq!(result.inserted, 1);
        }
    }

    /// The predecessor walk's ascend loop: tree 7 -> right 10 -> left 8
    /// (8 has a null left child), inserting the duplicate key 7. The
    /// descent ends going left at node 8; the walk ascends through 10
    /// (8 is 10's left child) to 7, whose key is not less than the new
    /// key — the existing node 7 comes back, flag clear, no linker
    /// call.
    #[test]
    fn ascend_predecessor_walk_finds_duplicate() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: recording_insert_node,
        });
        unsafe {
            let mut header = test_header();
            let mut n7 = test_node(7);
            let mut n10 = test_node(10);
            let mut n8 = test_node(8);
            let h = core::ptr::addr_of_mut!(header);
            let p7 = core::ptr::addr_of_mut!(n7);
            let p10 = core::ptr::addr_of_mut!(n10);
            let p8 = core::ptr::addr_of_mut!(n8);
            (*p7).parent = h;
            (*p7).right = p10;
            (*p10).parent = p7;
            (*p10).left = p8;
            (*p8).parent = p10;
            (*h).parent = p7; // root
            (*h).left = p7; // leftmost
            let mut tree = test_tree(h);

            let (result, _) = run_insert(core::ptr::addr_of_mut!(tree), 7);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 0);
            assert_eq!(result.node, p7.cast::<u8>());
            assert_eq!(result.inserted, 0);
        }
    }

    /// Same tree shape, new key 6: the descent ends going left at node
    /// 8's left-child... here 5 -> right 8 -> left 7, inserting 6 ends
    /// going left at node 7 (non-begin); the walk ascends through 8 to
    /// 5, whose key is less than 6, so a fresh node links under the
    /// descent parent (node 7 — not the predecessor), flagged 1.
    #[test]
    fn predecessor_less_than_key_inserts_under_descent_parent() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: recording_insert_node,
        });
        unsafe {
            let mut header = test_header();
            let mut n5 = test_node(5);
            let mut n8 = test_node(8);
            let mut n7 = test_node(7);
            let h = core::ptr::addr_of_mut!(header);
            let p5 = core::ptr::addr_of_mut!(n5);
            let p8 = core::ptr::addr_of_mut!(n8);
            let p7 = core::ptr::addr_of_mut!(n7);
            (*p5).parent = h;
            (*p5).right = p8;
            (*p8).parent = p5;
            (*p8).left = p7;
            (*p7).parent = p8;
            (*h).parent = p5; // root
            (*h).left = p5; // leftmost
            let mut tree = test_tree(h);

            let (result, fresh) = run_insert(core::ptr::addr_of_mut!(tree), 6);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 1);
            assert_eq!(
                core::ptr::addr_of!(SEEN_PARENT).read_volatile(),
                p7 as usize
            );
            assert_eq!(result.node, fresh);
            assert_eq!(result.inserted, 1);
        }
    }

    /// The comparator is an unsigned byte less-than: in a tree
    /// 0x40 -> right 0x80, key 0x80 is NOT less than 0x40 (a signed
    /// compare would read 0x80 as -128 and go left, inserting at
    /// begin). The duplicate comes back with the flag clear.
    #[test]
    fn comparator_is_unsigned() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: recording_insert_node,
        });
        unsafe {
            let mut header = test_header();
            let mut lo = test_node(0x40);
            let mut hi = test_node(0x80);
            let h = core::ptr::addr_of_mut!(header);
            let plo = core::ptr::addr_of_mut!(lo);
            let phi = core::ptr::addr_of_mut!(hi);
            (*plo).parent = h;
            (*plo).right = phi;
            (*phi).parent = plo;
            (*h).parent = plo; // root
            (*h).left = plo; // leftmost
            let mut tree = test_tree(h);

            let (result, _) = run_insert(core::ptr::addr_of_mut!(tree), 0x80);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 0);
            assert_eq!(result.node, phi.cast::<u8>());
            assert_eq!(result.inserted, 0);
        }
    }

    /// The multi-insert byte at map+0x18 skips the uniqueness test
    /// entirely: an already-present key still links a fresh node,
    /// flagged 1 (multimap semantics).
    #[test]
    fn multi_insert_flag_skips_uniqueness_test() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: recording_insert_node,
        });
        unsafe {
            let (_header, node, mut tree) = single_node_tree(7);
            tree.multi_insert = 1;
            let node_ptr = core::ptr::addr_of!(*node).cast_mut();

            let (result, fresh) = run_insert(core::ptr::addr_of_mut!(*tree), 7);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 1);
            assert_eq!(
                core::ptr::addr_of!(SEEN_PARENT).read_volatile(),
                node_ptr as usize
            );
            assert_eq!(result.node, fresh);
            assert_eq!(result.inserted, 1);
        }
    }

    /// With the default (stub) linker an insertion reports a null fresh
    /// node with the flag set — the find then returns 0x14.
    #[test]
    fn default_tree_ops_stub_reports_null_fresh_node() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: missing_insert_node,
        });
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            (*header_ptr).left = header_ptr; // leftmost == header
            let mut tree = test_tree(header_ptr);

            let pair = key_pair(5);
            let mut result = ByteKeyInsertResult {
                node: core::ptr::null_mut(),
                inserted: 0xaa,
            };
            byte_key_tree_insert_unique(
                &mut result,
                core::ptr::addr_of_mut!(tree).cast::<ByteKeyMap>(),
                &pair,
            );
            assert_eq!(result.node, core::ptr::null_mut());
            assert_eq!(result.inserted, 1);
        }
    }

    /// End-to-end through the find with the shipped default chain: the
    /// find dispatches the ported insert-unique, which drives a mini
    /// linker that really builds the first node. The first lookup
    /// inserts; the second finds the same node (no second linker call)
    /// and returns the same value pointer.
    #[test]
    fn find_end_to_end_through_shipped_default() {
        let _lock = OPS_LOCK.lock().unwrap();
        reset_recording();

        /// 8-aligned so the typed node writes through it stay aligned
        /// on a 64-bit host (a bare `[u8; N]` static is 1-aligned).
        #[repr(align(8))]
        struct AlignedNode([u8; 0x30]);
        static mut MINI_NODE: AlignedNode = AlignedNode([0; 0x30]);

        /// A minimal `_M_insert` good for the first node of an empty
        /// tree: parent is always the header here, so link the node as
        /// root (header.parent) and leftmost (header.left).
        unsafe extern "C" fn mini_insert_node(
            result: *mut *mut u8,
            _map: *mut ByteKeyMap,
            _insert_position: *mut u8,
            parent: *mut u8,
            key: *const ByteKeyPair,
        ) {
            let calls = core::ptr::addr_of!(INSERT_CALLS).read_volatile();
            core::ptr::addr_of_mut!(INSERT_CALLS).write_volatile(calls + 1);
            let node = core::ptr::addr_of_mut!(MINI_NODE).cast::<ByteKeyTreeNode>();
            (*node).color = 1; // black
            (*node).parent = parent.cast::<ByteKeyTreeNode>();
            (*node).left = core::ptr::null_mut();
            (*node).right = core::ptr::null_mut();
            (*node).key = core::ptr::read(key);
            let header = parent.cast::<ByteKeyTreeNode>();
            (*header).parent = node;
            (*header).left = node;
            result.write(node.cast::<u8>());
        }

        let _tree_guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: mini_insert_node,
        });
        let _map_guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: byte_key_tree_insert_unique,
        });
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            (*header_ptr).left = header_ptr; // leftmost == header
            let mut tree = test_tree(header_ptr);
            let map = core::ptr::addr_of_mut!(tree).cast::<ByteKeyMap>();
            let mini = core::ptr::addr_of_mut!(MINI_NODE).cast::<u8>();

            let key: u8 = 0x42;
            let first = byte_key_map_find(map, &key);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 1);
            assert_eq!(first, mini.add(0x14));

            let second = byte_key_map_find(map, &key);
            assert_eq!(core::ptr::addr_of!(INSERT_CALLS).read_volatile(), 1);
            assert_eq!(second, first);
        }
    }

    // --- byte_key_tree_insert_node (@ 0x083b8844) -------------------

    struct AllocOpsGuard;

    impl AllocOpsGuard {
        fn install(ops: ByteKeyTreeAllocOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_ALLOC_OPS).write_volatile(ops);
            }
            AllocOpsGuard
        }
    }

    impl Drop for AllocOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(BYTE_KEY_ALLOC_OPS).write_volatile(
                    ByteKeyTreeAllocOps {
                        allocate_node: missing_allocate_node,
                    },
                );
            }
        }
    }

    /// Arena backing the mock allocator; boxes stay put while a test's
    /// tree is live and are freed by `free_arena`.
    static mut ARENA: Vec<*mut ByteKeyTreeNode> = Vec::new();

    /// Mock for the pool allocator @ 0x083b7f40: hands out a fresh
    /// node honouring its contract — color 0 (red), links null, pair
    /// uninitialised (zeroed here; nothing reads it before the copy).
    unsafe extern "C" fn arena_allocate_node(
        _map: *mut ByteKeyMap,
    ) -> *mut ByteKeyTreeNode {
        let node = std::boxed::Box::into_raw(std::boxed::Box::new(ByteKeyTreeNode {
            color: 0,
            _pad: [0; 3],
            parent: core::ptr::null_mut(),
            left: core::ptr::null_mut(),
            right: core::ptr::null_mut(),
            key: key_pair(0),
        }));
        (*core::ptr::addr_of_mut!(ARENA)).push(node);
        node
    }

    fn install_arena_allocator() -> AllocOpsGuard {
        AllocOpsGuard::install(ByteKeyTreeAllocOps {
            allocate_node: arena_allocate_node,
        })
    }

    fn free_arena() {
        unsafe {
            for node in (*core::ptr::addr_of_mut!(ARENA)).drain(..) {
                drop(std::boxed::Box::from_raw(node));
            }
        }
    }

    fn arena_len() -> usize {
        unsafe { (*core::ptr::addr_of!(ARENA)).len() }
    }

    /// Red-black + BST + count validator for a tree under `header`:
    /// BST ordering by strict unsigned key bounds, no red node (0)
    /// with a red child, equal black height on every null path, and
    /// exactly `expected` nodes. Returns the sorted in-order keys.
    unsafe fn validate_tree(
        header: *mut ByteKeyTreeNode,
        expected: usize,
    ) -> Vec<u8> {
        fn walk(
            node: *mut ByteKeyTreeNode,
            lo: Option<u8>,
            hi: Option<u8>,
            keys: &mut Vec<u8>,
            count: &mut usize,
        ) -> usize {
            if node.is_null() {
                return 1; // null leaves are black
            }
            unsafe {
                let key = (*node).key.key;
                if let Some(lo) = lo {
                    assert!(key > lo, "BST lower bound violated at {key}");
                }
                if let Some(hi) = hi {
                    assert!(key < hi, "BST upper bound violated at {key}");
                }
                let red = (*node).color == 0;
                if red {
                    for child in [(*node).left, (*node).right] {
                        if !child.is_null() {
                            assert_eq!((*child).color, 1, "red node with red child");
                        }
                    }
                    assert_eq!((*(*node).parent).color, 1, "red node with red parent");
                }
                *count += 1;
                let left_height = walk((*node).left, lo, Some(key), keys, count);
                keys.push(key);
                let right_height = walk((*node).right, Some(key), hi, keys, count);
                assert_eq!(left_height, right_height, "black height mismatch");
                left_height + usize::from(!red)
            }
        }
        let mut keys = Vec::new();
        let mut count = 0;
        let root = (*header).parent;
        assert!(!root.is_null());
        assert_eq!((*root).color, 1, "root must be black");
        assert_eq!((*root).parent, header, "root's parent must be the header");
        walk(root, None, None, &mut keys, &mut count);
        assert_eq!(count, expected, "node count");
        keys
    }

    /// The header's leftmost/rightmost pointers track the extremes.
    unsafe fn validate_extremes(header: *mut ByteKeyTreeNode, keys: &[u8]) {
        let min = *keys.first().unwrap();
        let max = *keys.last().unwrap();
        assert_eq!((*(*header).left).key.key, min, "leftmost");
        assert_eq!((*(*header).right).key.key, max, "rightmost");
    }

    /// An empty tree: root null, leftmost and rightmost pointing at
    /// the header itself (the libstdc++ empty shape).
    unsafe fn make_empty_tree(
        header: *mut ByteKeyTreeNode,
    ) -> ByteKeyTree {
        (*header).left = header;
        (*header).right = header;
        test_tree(header)
    }

    /// Calls the port directly (the `_M_insert` contract): fresh node
    /// pointer at result+0.
    unsafe fn run_insert_node(
        tree: *mut ByteKeyTree,
        insert_position: *mut u8,
        parent: *mut ByteKeyTreeNode,
        key: u8,
    ) -> *mut u8 {
        let pair = key_pair(key);
        let mut fresh: *mut u8 = core::ptr::null_mut();
        byte_key_tree_insert_node(
            &mut fresh,
            tree.cast::<ByteKeyMap>(),
            insert_position,
            parent.cast::<u8>(),
            &pair,
        );
        fresh
    }

    /// With the default allocator stub the port reports a null fresh
    /// node and leaves the tree completely untouched.
    #[test]
    fn default_alloc_stub_reports_null_and_untouched_tree() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = AllocOpsGuard::install(ByteKeyTreeAllocOps {
            allocate_node: missing_allocate_node,
        });
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let fresh = run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, 5);
            assert_eq!(fresh, core::ptr::null_mut());
            assert_eq!((*header_ptr).parent, core::ptr::null_mut());
            assert_eq!(tree.node_count, 0);
        }
    }

    /// First node of an empty tree (parent == header): linked as root,
    /// leftmost and rightmost, recolored black, count bumped, pair
    /// copied, result carries the node.
    #[test]
    fn first_insert_becomes_black_root() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let fresh = run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, 5);
            assert!(!fresh.is_null());
            let node = fresh.cast::<ByteKeyTreeNode>();
            assert_eq!((*header_ptr).parent, node); // root
            assert_eq!((*header_ptr).left, node); // leftmost
            assert_eq!((*header_ptr).right, node); // rightmost
            assert_eq!((*node).parent, header_ptr);
            assert_eq!((*node).color, 1); // root recolored black
            assert_eq!((*node).key.key, 5);
            assert_eq!(tree.node_count, 1);
            assert_eq!(validate_tree(header_ptr, 1), [5]);
            validate_extremes(header_ptr, &[5]);
        }
        free_arena();
    }

    /// Comparator-driven left link (insert_position == 0, key less
    /// than parent's): the node becomes the parent's left child and
    /// the leftmost pointer follows the old leftmost.
    #[test]
    fn left_link_updates_leftmost() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let root = run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, 7)
                .cast::<ByteKeyTreeNode>();
            let fresh = run_insert_node(tree_ptr, core::ptr::null_mut(), root, 3)
                .cast::<ByteKeyTreeNode>();
            assert_eq!((*root).left, fresh);
            assert_eq!((*fresh).parent, root);
            assert_eq!((*header_ptr).left, fresh); // new leftmost
            assert_eq!((*header_ptr).right, root); // rightmost unchanged
            assert_eq!(tree.node_count, 2);
            assert_eq!(validate_tree(header_ptr, 2), [3, 7]);
            validate_extremes(header_ptr, &[3, 7]);
        }
        free_arena();
    }

    /// Comparator-driven right link: right child plus rightmost
    /// follow-up.
    #[test]
    fn right_link_updates_rightmost() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let root = run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, 7)
                .cast::<ByteKeyTreeNode>();
            let fresh = run_insert_node(tree_ptr, core::ptr::null_mut(), root, 9)
                .cast::<ByteKeyTreeNode>();
            assert_eq!((*root).right, fresh);
            assert_eq!((*header_ptr).right, fresh); // new rightmost
            assert_eq!((*header_ptr).left, root); // leftmost unchanged
            assert_eq!(validate_tree(header_ptr, 2), [7, 9]);
            validate_extremes(header_ptr, &[7, 9]);
        }
        free_arena();
    }

    /// A nonzero insert_position forces the left link even when the
    /// key compares greater than the parent's (multimap equal-key
    /// path).
    #[test]
    fn insert_position_forces_left_link() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let root = run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, 7)
                .cast::<ByteKeyTreeNode>();
            let mut nonzero: u8 = 1;
            let fresh = run_insert_node(tree_ptr, &mut nonzero, root, 9)
                .cast::<ByteKeyTreeNode>();
            assert_eq!((*root).left, fresh);
            assert_eq!((*root).right, core::ptr::null_mut());
            assert_eq!((*header_ptr).left, fresh); // leftmost followed
            assert_eq!((*header_ptr).right, root);
        }
        free_arena();
    }

    /// Rebalance stress: three key orders over unique keys — ascending
    /// (right-rotate path), descending (left-rotate), and a fixed
    /// zigzag permutation (double rotations and recolor ascents) —
    /// validating the full red-black/BST/count contract and the
    /// leftmost/rightmost pointers after every single insert.
    #[test]
    fn rebalance_keeps_red_black_invariants() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();

        let mut orders: Vec<Vec<u8>> = Vec::new();
        orders.push((1u8..=40).collect());
        orders.push((1u8..=40).rev().collect());
        // Deterministic zigzag: mid, mid-1, mid+1, mid-2, mid+2, ...
        let mut zigzag = Vec::new();
        let mid = 20u8;
        zigzag.push(mid);
        for d in 1..20u8 {
            zigzag.push(mid - d);
            zigzag.push(mid + d);
        }
        orders.push(zigzag);

        for order in orders {
            unsafe {
                let mut header = test_header();
                let header_ptr = core::ptr::addr_of_mut!(header);
                let mut tree = make_empty_tree(header_ptr);
                let tree_ptr = core::ptr::addr_of_mut!(tree);

                let mut inserted: Vec<u8> = Vec::new();
                for (i, key) in order.iter().enumerate() {
                    // Descend like the insert-unique caller does to
                    // find the link parent (keeps this test honest
                    // about the _M_insert contract: parent + position).
                    let mut parent = header_ptr;
                    let mut node = (*header_ptr).parent;
                    while !node.is_null() {
                        parent = node;
                        node = if *key < (*node).key.key {
                            (*node).left
                        } else {
                            (*node).right
                        };
                    }
                    let fresh =
                        run_insert_node(tree_ptr, core::ptr::null_mut(), parent, *key);
                    assert!(!fresh.is_null());
                    assert_eq!(tree.node_count as usize, i + 1);
                    inserted.push(*key);
                    let keys = validate_tree(header_ptr, i + 1);
                    let mut sorted = inserted.clone();
                    sorted.sort_unstable();
                    assert_eq!(keys, sorted);
                    validate_extremes(header_ptr, &sorted);
                }
            }
        }
        free_arena();
        assert_eq!(arena_len(), 0);
    }

    /// End-to-end through the shipped defaults: find -> ported
    /// insert-unique -> ported _M_insert, with only the allocator
    /// mocked. Insert several keys, then re-find them all (no further
    /// allocations, duplicates return the same node), and the value
    /// pointer is node + 0x14.
    #[test]
    fn find_end_to_end_through_shipped_insert_node() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _alloc_guard = install_arena_allocator();
        let _map_guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: byte_key_tree_insert_unique,
        });
        // BYTE_KEY_TREE_OPS ships with the port as its default; make
        // that explicit in case another test left a mock installed.
        let _tree_guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: byte_key_tree_insert_node,
        });
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);
            let map = tree_ptr.cast::<ByteKeyMap>();

            let keys = [7u8, 3, 9, 3, 7, 0x80, 1];
            let mut value_ptrs: Vec<*mut u8> = Vec::new();
            for key in keys {
                let value = byte_key_map_find(map, &key);
                assert!(!value.is_null());
                assert!((value as usize) >= 0x14);
                value_ptrs.push(value);
            }
            // Five unique keys -> five allocations, one node each.
            assert_eq!(arena_len(), 5);
            assert_eq!(tree.node_count, 5);
            // Duplicates returned the very same node + 0x14.
            assert_eq!(value_ptrs[1], value_ptrs[3]);
            assert_eq!(value_ptrs[0], value_ptrs[4]);
            let sorted = validate_tree(header_ptr, 5);
            assert_eq!(sorted, [1, 3, 7, 9, 0x80]);
            validate_extremes(header_ptr, &sorted);
            // The value pointer minus the find's literal +0x14 is the
            // node base on any host (the struct's own key field then
            // sits wherever the host layout puts it).
            for (i, key) in [7u8, 3, 9, 0x80, 1].iter().enumerate() {
                let node = value_ptrs[[0, 1, 2, 5, 6][i]]
                    .sub(0x14)
                    .cast::<ByteKeyTreeNode>();
                assert_eq!((*node).key.key, *key);
            }
        }
        free_arena();
    }

    // --- byte_key_tree_allocate_node (@ 0x083b7f40) -------------------

    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::MutexGuard;

    /// Bump arena backing the heap-ops `alloc` slot for the pool
    /// tests: the real heap core is not exercised on the host, and the
    /// shared mock in heap/veneers hands out a fixed fake address that
    /// cannot be written (the cxx/string.rs pattern).
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
    /// function (a second, shadowed guard in the same function would
    /// self-deadlock).
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

    /// A fresh container's pool words (all zero: no chunks, empty free
    /// list, empty bump range — which reads as exhausted).
    fn fresh_pool() -> ByteKeyNodePool {
        ByteKeyNodePool {
            chunk_head: core::ptr::null_mut(),
            free_list: core::ptr::null_mut(),
            bump: core::ptr::null_mut(),
            bump_end: core::ptr::null_mut(),
        }
    }

    fn alloc_sizes() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(POOL_ALLOC_SIZES)).clone() }
    }

    /// First allocation on a fresh container: one chunk header and one
    /// 0x20-node arena from the checked operator new (in that order),
    /// the chunk pushed at map+0, the bump range covering the arena,
    /// and the returned node — the arena base — initialised (color
    /// 0/red, the three links null).
    #[test]
    fn fresh_container_carves_first_chunk() {
        let _heap = pool_heap();
        unsafe {
            let node_size = core::mem::size_of::<ByteKeyTreeNode>();
            let chunk_size = core::mem::size_of::<ByteKeyPoolChunk>();
            let mut pool = fresh_pool();
            let pool_ptr = core::ptr::addr_of_mut!(pool);

            let node = byte_key_tree_allocate_node(pool_ptr.cast::<ByteKeyMap>());

            assert_eq!(alloc_sizes(), [chunk_size, 0x20 * node_size]);
            let chunk = pool.chunk_head;
            assert!(!chunk.is_null());
            assert_eq!((*chunk).prev, core::ptr::null_mut());
            assert_eq!((*chunk).capacity, 0x20);
            let arena = (*chunk).arena;
            assert_eq!(node, arena.cast::<ByteKeyTreeNode>());
            assert_eq!(pool.bump, arena.add(node_size));
            assert_eq!(pool.bump_end, arena.add(0x20 * node_size));
            assert_eq!(pool.free_list, core::ptr::null_mut());
            assert_eq!((*node).color, 0); // red
            assert_eq!((*node).parent, core::ptr::null_mut());
            assert_eq!((*node).left, core::ptr::null_mut());
            assert_eq!((*node).right, core::ptr::null_mut());
        }
    }

    /// The bump range hands out the whole arena a node at a time with
    /// no further heap traffic; the allocation past the end grows a
    /// second chunk at max(0x20+0x20, 0x20 + 0x20/2 + 0x20/8) = 0x40
    /// and links it ahead of the first.
    #[test]
    fn bump_exhaustion_grows_second_chunk() {
        let _heap = pool_heap();
        unsafe {
            let node_size = core::mem::size_of::<ByteKeyTreeNode>();
            let chunk_size = core::mem::size_of::<ByteKeyPoolChunk>();
            let mut pool = fresh_pool();
            let pool_ptr = core::ptr::addr_of_mut!(pool);
            let map = pool_ptr.cast::<ByteKeyMap>();

            let first_chunk;
            let first_arena;
            let first = byte_key_tree_allocate_node(map);
            first_chunk = pool.chunk_head;
            first_arena = (*first_chunk).arena;
            assert_eq!(first, first_arena.cast());
            for i in 1..0x20usize {
                let node = byte_key_tree_allocate_node(map);
                assert_eq!(node, first_arena.add(i * node_size).cast());
            }
            // Header + arena so far, nothing more.
            assert_eq!(alloc_sizes(), [chunk_size, 0x20 * node_size]);

            let node = byte_key_tree_allocate_node(map);
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

    /// The growth formula max(prev + 0x20, prev + prev/2 + prev/8):
    /// the +0x20 floor wins for small capacities (8 -> 0x28 against
    /// 8+4+1), the 1.625x term for large ones (0x100 -> 0x1a0 against
    /// 0x120). Both cases start from a hand-crafted exhausted pool.
    #[test]
    fn growth_capacity_formula() {
        let _heap = pool_heap();
        unsafe {
            let node_size = core::mem::size_of::<ByteKeyTreeNode>();
            let chunk_size = core::mem::size_of::<ByteKeyPoolChunk>();
            for (prev_cap, want) in [(8u32, 0x28u32), (0x100, 0x1a0)] {
                POOL_ARENA_USED = 0;
                (*core::ptr::addr_of_mut!(POOL_ALLOC_SIZES)).clear();
                let mut old_chunk = ByteKeyPoolChunk {
                    prev: core::ptr::null_mut(),
                    capacity: prev_cap,
                    arena: core::ptr::null_mut(),
                };
                let mut sentinel = 0u8;
                let bump = core::ptr::addr_of_mut!(sentinel);
                let mut pool = ByteKeyNodePool {
                    chunk_head: core::ptr::addr_of_mut!(old_chunk),
                    free_list: core::ptr::null_mut(),
                    bump,
                    bump_end: bump, // exhausted
                };

                let node = byte_key_tree_allocate_node(
                    core::ptr::addr_of_mut!(pool).cast::<ByteKeyMap>(),
                );

                let chunk = pool.chunk_head;
                assert_eq!((*chunk).prev, core::ptr::addr_of_mut!(old_chunk));
                assert_eq!((*chunk).capacity, want);
                assert_eq!(node, (*chunk).arena.cast());
                assert_eq!(
                    alloc_sizes(),
                    [chunk_size, want as usize * node_size]
                );
            }
        }
    }

    /// The free list pops before any bump/heap traffic: head first,
    /// the next pointer threaded through the node's +0xc right link,
    /// and the recycled node re-initialised (color 0, links null).
    #[test]
    fn free_list_pop_recycles_nodes() {
        let _heap = pool_heap();
        unsafe {
            let mut a = test_node(0xaa);
            let mut b = test_node(0xbb);
            let pa = core::ptr::addr_of_mut!(a);
            let pb = core::ptr::addr_of_mut!(b);
            (*pa).right = pb; // free-list next
            (*pa).parent = pb; // garbage the pop must clear
            (*pb).parent = pa;
            let mut pool = fresh_pool();
            pool.free_list = pa;
            // The bump range reads exhausted (null == null) but must
            // never be reached while the free list is non-empty.
            let map = core::ptr::addr_of_mut!(pool).cast::<ByteKeyMap>();

            let first = byte_key_tree_allocate_node(map);
            assert_eq!(first, pa);
            assert_eq!(pool.free_list, pb);
            assert_eq!((*pa).color, 0);
            assert_eq!((*pa).parent, core::ptr::null_mut());
            assert_eq!((*pa).left, core::ptr::null_mut());
            assert_eq!((*pa).right, core::ptr::null_mut());
            assert!(alloc_sizes().is_empty(), "no heap traffic on a pop");

            let second = byte_key_tree_allocate_node(map);
            assert_eq!(second, pb);
            assert_eq!(pool.free_list, core::ptr::null_mut());
            assert_eq!((*pb).color, 0);
            assert_eq!((*pb).parent, core::ptr::null_mut());
            assert!(alloc_sizes().is_empty());
        }
    }

    /// End-to-end with the whole slot chain at its shipped defaults:
    /// find -> ported insert-unique -> ported _M_insert -> ported pool
    /// allocator -> checked operator new (heap mocked by the arena).
    /// Inserts really link pool-carved nodes, duplicates return the
    /// same node, and the red-black invariants hold.
    #[test]
    fn find_end_to_end_through_shipped_allocator() {
        let _heap = pool_heap();
        let _lock = OPS_LOCK.lock().unwrap();
        // All three slots ship with the ports as their defaults; make
        // that explicit in case another test left a mock installed.
        let _alloc_guard = AllocOpsGuard::install(ByteKeyTreeAllocOps {
            allocate_node: byte_key_tree_allocate_node,
        });
        let _tree_guard = TreeOpsGuard::install(ByteKeyTreeOps {
            insert_node: byte_key_tree_insert_node,
        });
        let _map_guard = OpsGuard::install(ByteKeyMapOps {
            insert_unique: byte_key_tree_insert_unique,
        });
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);
            let map = tree_ptr.cast::<ByteKeyMap>();

            let keys = [5u8, 3, 9, 5, 1, 0x80, 3];
            let mut value_ptrs: Vec<*mut u8> = Vec::new();
            for key in keys {
                let value = byte_key_map_find(map, &key);
                assert!(!value.is_null());
                value_ptrs.push(value);
            }
            assert_eq!(tree.node_count, 5);
            assert_eq!(value_ptrs[0], value_ptrs[3]); // 5 again
            assert_eq!(value_ptrs[1], value_ptrs[6]); // 3 again
            let sorted = validate_tree(header_ptr, 5);
            assert_eq!(sorted, [1, 3, 5, 9, 0x80]);
            validate_extremes(header_ptr, &sorted);

            // Every unique key's node came out of the pool's first
            // 0x20-node arena, at a node-sized stride.
            let pool = tree_ptr.cast::<ByteKeyNodePool>();
            let chunk = (*pool).chunk_head;
            assert_eq!((*chunk).capacity, 0x20);
            let arena = (*chunk).arena as usize;
            let node_size = core::mem::size_of::<ByteKeyTreeNode>();
            for i in [0usize, 1, 2, 4, 5] {
                let offset = value_ptrs[i].sub(0x14) as usize - arena;
                assert_eq!(offset % node_size, 0);
                assert!(offset < 0x20 * node_size);
            }
        }
    }
}
