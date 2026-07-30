//! Find-or-insert on a red-black-tree map keyed by a COW `basic_string` —
//! the `map<string, V>::operator[]` shape the application layer uses to
//! fetch the mapped value word for a string key (40 `bl` call sites).
//!
//! - [`string_map_lookup_or_insert`] — original: `FUN_083db4c4` @
//!   0x083db4c4 (76 bytes; 40 `bl` call sites, the only copy).
//! - [`string_key_tree_rotate_left`] — original: `FUN_083c31d4` @
//!   0x083c31d4 (84 bytes; `_Rb_tree_rotate_left`, the rebalance
//!   rotation of the not-yet-ported `_M_insert` @ 0x083c3408).
//! - [`string_key_tree_rotate_right`] — original: `FUN_083c3228` @
//!   0x083c3228 (84 bytes; `_Rb_tree_rotate_right`, the mirror
//!   rotation).
//! - [`string_key_tree_allocate_node`] — original: `FUN_083c311c` @
//!   0x083c311c (184 bytes; the node pool allocator `_M_insert` @
//!   0x083c3408 carves fresh 0x18-byte nodes through).
//!
//! Algorithm (from the disassembly): copy-construct a temporary
//! `basic_string` from the caller's string object into the key half of
//! an 8-byte pair on the stack (real `cxx_string_copy_ctor` @ 0x083d8c30
//! call — the COW share), zero the word after it (the default-
//! constructed one-word mapped value), run the tree insert-unique
//! operation @ 0x083c327c(&result, map, &pair), then release the
//! temporary (`cxx_string_release` @ 0x083d8b04) and return the
//! resulting node pointer plus 0x14, i.e. `&node->value`: the node
//! header is 0x10 bytes (color/flag at +0, parent +4, left +8, right
//! +0xc) with the key pair at +0x10, so +0x14 is the mapped value
//! inside the pair.
//!
//! Contract of the tree operation @ 0x083c327c — scouted, not yet
//! ported, so dispatched through the [`STRING_KEY_MAP_OPS`] slot with a
//! fail-closed default (house pattern — see `cxx/pair_header.rs` and
//! the pre-port history of `cxx/byte_key_map.rs`):
//!
//! ```text
//! void insert_unique(result *r0, map *r1, const pair *r2)
//!   r0 +0  <- node pointer (existing or newly inserted)
//!   r0 +4  <- inserted flag byte (1 = newly linked, 0 = key present)
//!   r1     container: +0x10 header node (header+4 = root, header+8 =
//!          leftmost), +0x14 node count, +0x18 multi-insert flag byte,
//!          +0x19 comparator object
//!   r2     the 8-byte key pair above; node keys sit at node+0x10
//! ```
//!
//! The body (392 bytes, 0x083c327c-0x083c3404) is libstdc++'s
//! `_Rb_tree::_M_insert_unique`, the same shape as its ported byte-keyed
//! twin @ 0x083b867c (`byte_key_tree_insert_unique` in
//! `cxx/byte_key_map.rs`): descend from the root comparing keys through
//! the string comparator @ 0x083d74f4 (the ported `cxx_string_less`;
//! nonzero -> descend left at +8, else right at +0xc), remember the
//! last node, then — via the iterator-equality helper @ 0x083cf818
//! against the leftmost header child and an inline predecessor walk —
//! either return the existing node with the flag clear or link a fresh
//! node through `_M_insert` @ 0x083c3408 (which allocates a node @
//! 0x083c311c — ported below as [`string_key_tree_allocate_node`] —
//! copy-constructs the pair into it — string via
//! `cxx_string_copy_ctor` plus the one value word — and rebalances via
//! the rotations @ 0x083c31d4 and 0x083c3228 — ported below as
//! [`string_key_tree_rotate_left`] and
//! [`string_key_tree_rotate_right`]) and return it
//! flagged.
//! `_M_insert` takes the key pair as a fifth argument on the stack.
//! Every path stores the node word at result+0 and the flag byte at
//! result+4, which is the whole contract the lookup relies on.
//!
//! Deviations:
//! - 0x083c327c is dispatched through [`STRING_KEY_MAP_OPS`], whose
//!   shipped default is the fail-closed stub below (no tree wired: a
//!   null node with the flag clear, so the lookup returns null + 0x14
//!   — an obviously invalid value pointer, matching the pre-port
//!   `byte_key_map_find` behaviour). The lookup's tests install
//!   recording mocks through the slot.
//! - The original spills the result's node word to the stack across the
//!   release call (`str r0,[sp,#0]` / `ldr r0,[sp,#0]`); a Rust local
//!   serves the same purpose.
//! - The final `node + 0x14` is a wrapping add (the original's plain
//!   `add r0, r0, #0x14`); with a real node installed the value is
//!   identical.

use crate::cxx::string::{cxx_string_copy_ctor, cxx_string_release};

/// The 8-byte key/value pair the lookup builds on its stack frame and
/// hands to the tree operation: the copy-constructed key string object
/// (one word — the rep data pointer) at +0, the default-constructed
/// (zeroed) one-word mapped value at +4. Matches the original's stack
/// layout at sp+4..sp+0xc exactly.
#[repr(C)]
pub struct StringKeyPair {
    /// +0: the key string object (a COW `basic_string` — the rep data
    /// pointer), copy-constructed from the caller's key.
    pub key: *mut u8,
    /// +4: the zeroed mapped-value word.
    pub value: u32,
}

/// The result the tree operation @ 0x083c327c writes through its first
/// argument: node pointer at +0, inserted-flag byte at +4. The lookup
/// consumes only the node word.
#[repr(C)]
pub struct StringKeyInsertResult {
    /// +0: node pointer — the existing node for `key`, or the freshly
    /// linked one.
    pub node: *mut u8,
    /// +4: inserted flag byte (1 = newly linked, 0 = key was present).
    pub inserted: u8,
}

/// The string-keyed map container. Opaque to this port — only its
/// address is forwarded to the tree-operation slot. Scouted layout,
/// from 0x083c327c's reads: +0x10 header node (header+4 = root,
/// header+8 = leftmost), +0x14 node count, +0x18 multi-insert flag
/// byte, +0x19 key-comparator object.
#[repr(C)]
pub struct StringKeyMap {
    _opaque: [u8; 0],
}

/// Indirect dispatch for the not-yet-ported tree insert-unique
/// operation @ 0x083c327c (the `PairHeaderOps` precedent in
/// `cxx/pair_header.rs`).
#[derive(Clone, Copy)]
pub struct StringKeyMapOps {
    /// The container operation @ 0x083c327c: writes the node pointer at
    /// `result + 0` and the inserted-flag byte at `result + 4`. See the
    /// module header for the full scouted contract.
    pub insert_unique: unsafe extern "C" fn(
        result: *mut StringKeyInsertResult,
        map: *mut StringKeyMap,
        key: *const StringKeyPair,
    ),
}

/// Fail-closed default: no tree wired, so report "not found, not
/// inserted" with a null node — the lookup then returns 0x14 (null +
/// 0x14), an obviously invalid value pointer. A null node can never
/// come out of the real operation (the header node always exists).
unsafe extern "C" fn missing_insert_unique(
    result: *mut StringKeyInsertResult,
    _map: *mut StringKeyMap,
    _key: *const StringKeyPair,
) {
    (*result).node = core::ptr::null_mut();
    (*result).inserted = 0;
}

/// The active tree-operation slot. The shipped default is the
/// documented fail-closed stub above; host tests install recording
/// mocks through the slot. Written once at init on target; tests
/// serialize access.
pub static mut STRING_KEY_MAP_OPS: StringKeyMapOps = StringKeyMapOps {
    insert_unique: missing_insert_unique,
};

/// `#[inline(never)]` front-end for `cxx_string_copy_ctor` @ 0x083d8c30:
/// the original reaches it by `bl`, and letting LLVM inline the COW
/// share/deep-copy branch into the lookup quadruples its size and
/// destroys the structural match (the `pool_operator_new` rationale in
/// `cxx/byte_key_map.rs`).
#[inline(never)]
fn pair_string_copy_ctor(dst: *mut *mut u8, src: *const *mut u8) -> *mut *mut u8 {
    unsafe { cxx_string_copy_ctor(dst, src) }
}

/// `#[inline(never)]` front-end for `cxx_string_release` @ 0x083d8b04 —
/// same `bl`-boundary rationale as [`pair_string_copy_ctor`].
#[inline(never)]
fn pair_string_release(string: *mut *mut u8) {
    unsafe { cxx_string_release(string) }
}

/// string_map_lookup_or_insert — original: `FUN_083db4c4` @ 0x083db4c4
/// (76 bytes; 40 `bl` call sites, the only copy).
///
/// Finds (or inserts) the node for the string `key` in `map` and
/// returns a pointer to its mapped value word, `node + 0x14`. Copy-
/// constructs a temporary string from `key` into an 8-byte pair on the
/// stack (zeroing the value word after it), runs the tree insert-unique
/// operation @ 0x083c327c through [`STRING_KEY_MAP_OPS`], releases the
/// temporary and returns. Only the result's node word is consumed; the
/// inserted-flag byte is dropped.
///
/// # Safety
/// `key` must point at a live `basic_string` object and `map` at a live
/// container whose layout matches the scouted one in the module header.
/// The installed `insert_unique` must honour the 0x083c327c contract
/// (node word at result+0, flag byte at result+4). The shipped default
/// reports a null node, and the returned pointer is then 0x14 and must
/// not be dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_map_lookup_or_insert(
    map: *mut StringKeyMap,
    key: *const *mut u8,
) -> *mut u8 {
    let mut pair = StringKeyPair {
        key: core::ptr::null_mut(),
        value: 0,
    };
    pair_string_copy_ctor(core::ptr::addr_of_mut!(pair.key), key);
    pair.value = 0;
    let mut result = StringKeyInsertResult {
        node: core::ptr::null_mut(),
        inserted: 0,
    };
    // Reads the fn-pointer field directly rather than through a
    // whole-table read (the timer_schedule_shim gotcha).
    let insert_unique =
        core::ptr::addr_of!(STRING_KEY_MAP_OPS.insert_unique).read_volatile();
    insert_unique(&mut result, map, &pair);
    let node = result.node;
    pair_string_release(core::ptr::addr_of_mut!(pair.key));
    node.wrapping_add(0x14)
}

// ---------------------------------------------------------------------------
// The rebalance rotations of `_M_insert` @ 0x083c3408.
// ---------------------------------------------------------------------------

/// A red-black tree node of the string-keyed map family: the same
/// 0x10-byte header as the byte-keyed tree (color byte, parent / left /
/// right links) with the 8-byte key pair — the COW string word plus the
/// one mapped-value word — at +0x10. Fields are typed struct members,
/// never literal byte offsets: the 32-bit target layout is exact
/// (asserted below) while a 64-bit host keeps the fields disjoint (the
/// `NodeList` precedent in `app/node_list.rs`).
#[repr(C)]
pub struct StringKeyTreeNode {
    /// +0: red-black color byte (0 = red; the header node is red).
    pub color: u8,
    /// +1..+4: padding.
    pub _pad: [u8; 3],
    /// +4: parent link.
    pub parent: *mut StringKeyTreeNode,
    /// +8: left child (smaller keys), null when absent.
    pub left: *mut StringKeyTreeNode,
    /// +0xc: right child, null when absent.
    pub right: *mut StringKeyTreeNode,
    /// +0x10: the 8-byte key pair (string word at +0x10, mapped value
    /// at +0x14).
    pub key: StringKeyPair,
}

/// The container as the rotations read it: only the header node pointer
/// at +0x10 (header.parent = root). The first 0x10 bytes are the node
/// pool state the ported allocator [`string_key_tree_allocate_node`]
/// owns — see [`StringKeyNodePool`]. Sized off that struct so the
/// fields stay disjoint on a 64-bit host (the pool's pointers widen
/// past 0x10 there); exactly 0x10 on the 32-bit target, where the
/// layout checks below pin `header` at +0x10 (the `ByteKeyTree`
/// precedent in `cxx/byte_key_map.rs`).
#[repr(C)]
pub struct StringKeyTree {
    /// +0..+0x10: the node pool state [`StringKeyNodePool`].
    pub _opaque: [u8; core::mem::size_of::<StringKeyNodePool>()],
    /// +0x10: the header node.
    pub header: *mut StringKeyTreeNode,
}

// Target-exact layout; on a 64-bit host the pointer fields widen and
// the offsets shift — harmless, all access goes through the structs.
#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x4] = [0; core::mem::offset_of!(StringKeyTreeNode, parent)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(StringKeyTreeNode, left)];
    const _: [u8; 0xc] = [0; core::mem::offset_of!(StringKeyTreeNode, right)];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(StringKeyTreeNode, key)];
    const _: [u8; 0x18] = [0; core::mem::size_of::<StringKeyTreeNode>()];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(StringKeyTree, header)];
}

/// string_key_tree_rotate_left — original: `FUN_083c31d4` @ 0x083c31d4
/// (84 bytes; libstdc++ `_Rb_tree_rotate_left` for the string-keyed map
/// family, called by `_M_insert` @ 0x083c3408 — `bl` @ 0x083c35a8 — and
/// the erase rebalance).
///
/// NOTE on the address: the scouting note for 0x083c327c cited this
/// rotation as 0x083c31f4, but that address is mid-function (the
/// `ldr r0,[r0,#0x10]` header reload); the real entry — and the only
/// `bl` target — is 0x083c31d4 (FUN_083c31d4, 84 bytes).
///
/// Instruction-identical to the byte-keyed rotate_left @ 0x083b8090
/// ([`byte_key_tree_rotate_left`](crate::cxx::byte_key_map) — verified
/// against osos.asm word for word). Left rotation around `node`:
/// `right` takes `node`'s place (under the root pointer at header+4
/// when `node` is the root, else under `node`'s parent on the side
/// `node` hangs from), `node` adopts `right`'s left subtree as its
/// right child (re-parenting it when non-null) and becomes `right`'s
/// left child.
///
/// Exported `pub` (unlike the byte-keyed twin, a private helper of its
/// ported `_M_insert`): the string-keyed `_M_insert` @ 0x083c3408 is
/// not yet ported, so there is no in-crate caller yet — the export
/// keeps the symbol in the staticlib for match.py review and for the
/// future `_M_insert` port to call.
///
/// # Safety
/// `tree` must point at a live container matching the scouted
/// [`StringKeyTree`] layout, and `node` at a live node of that tree
/// whose right child is non-null (a red-black rotation precondition the
/// callers guarantee; the original has no check either).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_key_tree_rotate_left(
    tree: *mut StringKeyTree,
    node: *mut StringKeyTreeNode,
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

/// string_key_tree_rotate_right — original: `FUN_083c3228` @
/// 0x083c3228 (84 bytes; libstdc++ `_Rb_tree_rotate_right` for the
/// string-keyed map family, called by `_M_insert` @ 0x083c3408 —
/// `bl` @ 0x083c3534, `bleq` @ 0x083c3584 — and the erase rebalance).
///
/// Instruction-identical to the byte-keyed rotate_right @ 0x083b80e4
/// ([`byte_key_tree_rotate_right`](crate::cxx::byte_key_map) — verified
/// against osos.asm word for word). Right rotation around `node`:
/// `left` takes `node`'s place (under the root pointer at header+4
/// when `node` is the root, else under `node`'s parent on the side
/// `node` hangs from), `node` adopts `left`'s right subtree as its
/// left child (re-parenting it when non-null) and becomes `left`'s
/// right child. The exact mirror of [`string_key_tree_rotate_left`].
///
/// Exported `pub` for the same reason as rotate_left: the string-keyed
/// `_M_insert` @ 0x083c3408 is not yet ported, so there is no in-crate
/// caller yet — the export keeps the symbol in the staticlib for
/// match.py review and for the future `_M_insert` port to call.
///
/// # Safety
/// `tree` must point at a live container matching the scouted
/// [`StringKeyTree`] layout, and `node` at a live node of that tree
/// whose left child is non-null (a red-black rotation precondition the
/// callers guarantee; the original has no check either).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_key_tree_rotate_right(
    tree: *mut StringKeyTree,
    node: *mut StringKeyTreeNode,
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

// ---------------------------------------------------------------------------
// The pool allocator itself (@ 0x083c311c).
// ---------------------------------------------------------------------------

/// The node pool state the allocator owns in the container's first
/// 0x10 bytes (the `_opaque` head of [`StringKeyTree`]; the container
/// base subobject doubles as the node pool — libstdc++'s old
/// `_Rb_tree` kept its allocator's pool in the same words). Fields are
/// typed struct members, never literal byte offsets: the 32-bit target
/// layout is exact (asserted below) while a 64-bit host keeps the
/// fields disjoint (the `ByteKeyNodePool` precedent in
/// `cxx/byte_key_map.rs`).
#[repr(C)]
pub struct StringKeyNodePool {
    /// +0: newest growth-chunk header (0xc bytes: prev / capacity /
    /// arena); null until the first arena is carved.
    pub chunk_head: *mut StringKeyPoolChunk,
    /// +4: free-list head, threaded through the freed node's +0xc word
    /// (its right link).
    pub free_list: *mut StringKeyTreeNode,
    /// +8: bump cursor into the current arena.
    pub bump: *mut u8,
    /// +0xc: end of the current arena; `bump == bump_end` means grow.
    pub bump_end: *mut u8,
}

/// A growth-chunk header (0xc bytes): the intrusive list of arenas the
/// pool carved, newest first.
#[repr(C)]
pub struct StringKeyPoolChunk {
    /// +0: the previous (older) chunk header.
    pub prev: *mut StringKeyPoolChunk,
    /// +4: node capacity of this chunk's arena.
    pub capacity: u32,
    /// +8: the arena — `capacity` nodes of 0x18 bytes each.
    pub arena: *mut u8,
}

// Target-exact layout; on a 64-bit host the pointer fields widen and
// the offsets shift — harmless, all access goes through the structs.
#[cfg(target_pointer_width = "32")]
mod pool_layout_checks {
    use super::*;
    const _: [u8; 0x4] = [0; core::mem::offset_of!(StringKeyNodePool, free_list)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(StringKeyNodePool, bump)];
    const _: [u8; 0xc] = [0; core::mem::offset_of!(StringKeyNodePool, bump_end)];
    const _: [u8; 0x10] = [0; core::mem::size_of::<StringKeyNodePool>()];
    const _: [u8; 0x4] = [0; core::mem::offset_of!(StringKeyPoolChunk, capacity)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(StringKeyPoolChunk, arena)];
    const _: [u8; 0xc] = [0; core::mem::size_of::<StringKeyPoolChunk>()];
}

/// `#[inline(never)]` front-end for the checked operator new @
/// 0x08266c70 (ported in heap/veneers.rs): on device the original
/// allocator reaches it with `bl` from both allocation sites, and
/// letting LLVM inline the null-check + new-handler path into the
/// allocator nearly doubles its size and destroys the structural
/// match (the `pool_operator_new` rationale in `cxx/byte_key_map.rs`).
#[inline(never)]
fn pool_operator_new(size: usize) -> *mut u8 {
    unsafe { crate::heap::veneers::operator_new_checked(size) }
}

/// string_key_tree_allocate_node — original: `FUN_083c311c` @
/// 0x083c311c (184 bytes; called from `_M_insert` @ 0x083c3408 —
/// `bl` @ 0x083c3424, which consumes the returned node in r0 — and one
/// sibling site @ 0x081a0b28).
///
/// libstdc++'s pool allocator for the string-keyed map family's
/// 0x18-byte tree nodes — the near-instruction-identical twin of the
/// ported byte-keyed allocator @ 0x083b7f40
/// ([`byte_key_tree_allocate_node`](crate::cxx::byte_key_map);
/// verified against osos.asm: same free-list/bump/growth instruction
/// sequence, differing only in the node stride — 0x18 here vs 0x20
/// there, so a `mul` by 0x18 and an `add r1,r6,r6,lsl#1` + `lsl#3`
/// arena-end computation where the twin folds 0x20 into `lsl#5`
/// shifts). If the free list at map+4 is non-empty, pop its head (the
/// next pointer is threaded through the node's +0xc word). Else
/// bump-allocate from the current arena (cursor at map+8, end at
/// map+0xc); when the cursor reaches the end, grow first: capacity is
/// `max(prev + 0x20, prev + prev/2 + prev/8)` of the newest chunk's
/// capacity (0x20 for the first chunk), then a 0xc-byte chunk header
/// and a `capacity * 0x18` arena are carved by two calls to the
/// checked operator new @ 0x08266c70, the chunk is pushed at map+0
/// (prev link, capacity, arena pointer), and the arena becomes the new
/// bump range. The handed-out node gets its parent/left/right words at
/// +4/+8/+0xc nulled and its color byte at +0 set to 0 (red); the key
/// pair at +0x10 is left uninitialised for the caller to
/// copy-construct.
///
/// Exported `pub` for the same reason as the rotations above: the
/// string-keyed `_M_insert` @ 0x083c3408 that calls this allocator is
/// not yet ported, so there is no in-crate caller yet — the export
/// keeps the symbol in the staticlib for match.py review and for the
/// future `_M_insert` port to call (which, like its byte-keyed twin,
/// will dispatch it through an ops slot).
///
/// Deviations:
/// - Ghidra types the original `void`, but it leaves the node pointer
///   in r0 (only r4-r8/lr are stacked) and `_M_insert` consumes it
///   (`mov r5,r0` @ 0x083c3428) — the port returns it, like the
///   byte-keyed twin.
/// - The node stride and chunk-header size go through `size_of`
///   (0x18 / 0xc on the 32-bit target — the original's `#0x18` / `#0xc`
///   immediates — wider on 64-bit hosts, where that keeps the fields
///   disjoint; the `ByteKeyNodePool` precedent).
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
/// pool state ([`StringKeyNodePool`]); on a freshly constructed
/// container those words are zero (no chunks, empty free list, empty
/// bump range), which the growth path handles. The returned node's key
/// pair is uninitialised — the caller must construct it before any
/// read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_key_tree_allocate_node(
    map: *mut StringKeyMap,
) -> *mut StringKeyTreeNode {
    const NODE_SIZE: usize = core::mem::size_of::<StringKeyTreeNode>();
    let pool = map.cast::<StringKeyNodePool>();
    let node: *mut StringKeyTreeNode;
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
                core::mem::size_of::<StringKeyPoolChunk>(),
            )
            .cast::<StringKeyPoolChunk>();
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
        node = bump.cast::<StringKeyTreeNode>();
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
    use crate::cxx::string::{empty_rep_data, StringRep};
    use std::sync::Mutex as StdMutex;

    /// Ops-table swaps are global; serialize the tests.
    static OPS_LOCK: StdMutex<()> = StdMutex::new(());

    struct OpsGuard;

    impl OpsGuard {
        fn install(ops: StringKeyMapOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(STRING_KEY_MAP_OPS).write_volatile(ops);
            }
            OpsGuard
        }
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_KEY_MAP_OPS).write_volatile(
                    StringKeyMapOps {
                        insert_unique: missing_insert_unique,
                    },
                );
            }
        }
    }

    /// A non-empty COW string standing on its own rep (refcount 0 =
    /// sole owner): the copy constructor shares it (`++refcount`), the
    /// release drops the share back — no allocator involved either way.
    #[repr(C, align(4))]
    struct FakeString {
        rep: StringRep,
        data: [u8; 8],
    }

    fn fake_string() -> FakeString {
        FakeString {
            rep: StringRep {
                refcount: 0,
                capacity: 7,
                length: 3,
            },
            data: *b"foo\0\0\0\0\0",
        }
    }

    /// With the default stub the slot reports a null node and the
    /// lookup returns null + 0x14 — and the map pointer is never
    /// dereferenced.
    #[test]
    fn default_stub_returns_null_plus_header() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = OpsGuard::install(StringKeyMapOps {
            insert_unique: missing_insert_unique,
        });
        unsafe {
            let key: *mut u8 = empty_rep_data();
            let value =
                string_map_lookup_or_insert(core::ptr::null_mut(), &key);
            assert_eq!(value as usize, 0x14);
        }
    }

    /// The slot receives the map pointer unchanged and a pair carrying
    /// the *shared* key string (COW copy: same data pointer, refcount
    /// bumped for the duration) with a zeroed value word; the lookup
    /// returns the slot's node plus 0x14, and the temporary is released
    /// on the way out (refcount back to sole-owner 0).
    #[test]
    fn pair_shape_copy_release_and_return_offset() {
        let _lock = OPS_LOCK.lock().unwrap();

        static mut SEEN_MAP: usize = 0;
        static mut SEEN_KEY: usize = 0;
        static mut SEEN_VALUE: u32 = 1;
        static mut SEEN_REFCOUNT: i32 = -2;
        /// Fake node storage; the slot hands out its base.
        static mut NODE: [u8; 0x20] = [0; 0x20];

        unsafe extern "C" fn recording_insert_unique(
            result: *mut StringKeyInsertResult,
            map: *mut StringKeyMap,
            key: *const StringKeyPair,
        ) {
            core::ptr::addr_of_mut!(SEEN_MAP).write_volatile(map as usize);
            core::ptr::addr_of_mut!(SEEN_KEY).write_volatile((*key).key as usize);
            core::ptr::addr_of_mut!(SEEN_VALUE).write_volatile((*key).value);
            // The temporary must be alive (shared) while the tree runs.
            let rep = ((*key).key as *mut StringRep).sub(1);
            core::ptr::addr_of_mut!(SEEN_REFCOUNT).write_volatile((*rep).refcount);
            (*result).node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            (*result).inserted = 1;
        }

        let _guard = OpsGuard::install(StringKeyMapOps {
            insert_unique: recording_insert_unique,
        });
        unsafe {
            let mut fake = fake_string();
            let fake_ptr = core::ptr::addr_of_mut!(fake);
            let data = core::ptr::addr_of_mut!((*fake_ptr).data).cast::<u8>();
            let key: *mut u8 = data;
            let mut map_storage = [0u8; 0x20];
            let map = map_storage.as_mut_ptr().cast::<StringKeyMap>();

            let value = string_map_lookup_or_insert(map, &key);

            assert_eq!(
                core::ptr::addr_of!(SEEN_MAP).read_volatile(),
                map as usize
            );
            // COW share: the pair's string word is the same data pointer.
            assert_eq!(core::ptr::addr_of!(SEEN_KEY).read_volatile(), data as usize);
            assert_eq!(core::ptr::addr_of!(SEEN_VALUE).read_volatile(), 0);
            // Shared during the tree walk, released after it.
            assert_eq!(core::ptr::addr_of!(SEEN_REFCOUNT).read_volatile(), 1);
            assert_eq!((*fake_ptr).rep.refcount, 0);
            let node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            assert_eq!(value, node.add(0x14));
        }
    }

    /// A found-not-inserted result (flag byte 0) still yields node +
    /// 0x14; the lookup never reads the flag.
    #[test]
    fn existing_node_ignores_inserted_flag() {
        let _lock = OPS_LOCK.lock().unwrap();

        static mut NODE: [u8; 0x20] = [0; 0x20];

        unsafe extern "C" fn found_insert_unique(
            result: *mut StringKeyInsertResult,
            _map: *mut StringKeyMap,
            _key: *const StringKeyPair,
        ) {
            (*result).node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            (*result).inserted = 0;
        }

        let _guard = OpsGuard::install(StringKeyMapOps {
            insert_unique: found_insert_unique,
        });
        unsafe {
            let key: *mut u8 = empty_rep_data();
            let value =
                string_map_lookup_or_insert(core::ptr::null_mut(), &key);
            let node = core::ptr::addr_of_mut!(NODE).cast::<u8>();
            assert_eq!(value, node.add(0x14));
        }
    }

    // --- string_key_tree_rotate_left (@ 0x083c31d4) -----------------

    /// A black tree node with no links (the key pair is never read by
    /// the rotation).
    fn test_node() -> StringKeyTreeNode {
        StringKeyTreeNode {
            color: 1,
            _pad: [0; 3],
            parent: core::ptr::null_mut(),
            left: core::ptr::null_mut(),
            right: core::ptr::null_mut(),
            key: StringKeyPair {
                key: core::ptr::null_mut(),
                value: 0,
            },
        }
    }

    /// A red header node (libstdc++ marks the header red).
    fn test_header() -> StringKeyTreeNode {
        let mut header = test_node();
        header.color = 0;
        header
    }

    /// A container wired to `header`.
    fn test_tree(header: *mut StringKeyTreeNode) -> StringKeyTree {
        StringKeyTree {
            _opaque: [0; core::mem::size_of::<StringKeyNodePool>()],
            header,
        }
    }

    /// Rotating at the root: `right` becomes the root (header.parent),
    /// `node` becomes its left child and adopts `right`'s old left
    /// subtree, re-parented.
    #[test]
    fn rotate_left_at_root() {
        unsafe {
            let mut header = std::boxed::Box::new(test_header());
            let mut node = std::boxed::Box::new(test_node());
            let mut right = std::boxed::Box::new(test_node());
            let mut adopted = std::boxed::Box::new(test_node());
            let header_ptr = core::ptr::addr_of_mut!(*header);
            let node_ptr = core::ptr::addr_of_mut!(*node);
            let right_ptr = core::ptr::addr_of_mut!(*right);
            let adopted_ptr = core::ptr::addr_of_mut!(*adopted);

            node.parent = header_ptr;
            node.right = right_ptr;
            right.parent = node_ptr;
            right.left = adopted_ptr;
            adopted.parent = right_ptr;
            header.parent = node_ptr; // root
            let mut tree = std::boxed::Box::new(test_tree(header_ptr));

            string_key_tree_rotate_left(
                core::ptr::addr_of_mut!(*tree),
                node_ptr,
            );

            assert_eq!(header.parent, right_ptr); // new root
            assert_eq!(right.parent, header_ptr);
            assert_eq!(right.left, node_ptr);
            assert_eq!(node.parent, right_ptr);
            assert_eq!(node.right, adopted_ptr); // adopted subtree
            assert_eq!(adopted.parent, node_ptr);
        }
    }

    /// Rotating under a left-child parent: the parent's left link
    /// swings to `right`; a null adopted subtree leaves node's right
    /// link null.
    #[test]
    fn rotate_left_under_left_child() {
        unsafe {
            let mut header = std::boxed::Box::new(test_header());
            let mut grand = std::boxed::Box::new(test_node());
            let mut node = std::boxed::Box::new(test_node());
            let mut right = std::boxed::Box::new(test_node());
            let header_ptr = core::ptr::addr_of_mut!(*header);
            let grand_ptr = core::ptr::addr_of_mut!(*grand);
            let node_ptr = core::ptr::addr_of_mut!(*node);
            let right_ptr = core::ptr::addr_of_mut!(*right);

            grand.parent = header_ptr;
            grand.left = node_ptr;
            node.parent = grand_ptr;
            node.right = right_ptr;
            right.parent = node_ptr; // right.left null: nothing adopted
            header.parent = grand_ptr; // root is the grandparent
            let mut tree = std::boxed::Box::new(test_tree(header_ptr));

            string_key_tree_rotate_left(
                core::ptr::addr_of_mut!(*tree),
                node_ptr,
            );

            assert_eq!(header.parent, grand_ptr); // root unchanged
            assert_eq!(grand.left, right_ptr); // took node's place
            assert_eq!(right.parent, grand_ptr);
            assert_eq!(right.left, node_ptr);
            assert_eq!(node.parent, right_ptr);
            assert_eq!(node.right, core::ptr::null_mut());
        }
    }

    /// Rotating under a right-child parent: the parent's right link
    /// swings to `right`.
    #[test]
    fn rotate_left_under_right_child() {
        unsafe {
            let mut header = std::boxed::Box::new(test_header());
            let mut grand = std::boxed::Box::new(test_node());
            let mut node = std::boxed::Box::new(test_node());
            let mut right = std::boxed::Box::new(test_node());
            let header_ptr = core::ptr::addr_of_mut!(*header);
            let grand_ptr = core::ptr::addr_of_mut!(*grand);
            let node_ptr = core::ptr::addr_of_mut!(*node);
            let right_ptr = core::ptr::addr_of_mut!(*right);

            grand.parent = header_ptr;
            grand.right = node_ptr;
            node.parent = grand_ptr;
            node.right = right_ptr;
            right.parent = node_ptr;
            header.parent = grand_ptr;
            let mut tree = std::boxed::Box::new(test_tree(header_ptr));

            string_key_tree_rotate_left(
                core::ptr::addr_of_mut!(*tree),
                node_ptr,
            );

            assert_eq!(grand.right, right_ptr); // took node's place
            assert_eq!(right.parent, grand_ptr);
            assert_eq!(right.left, node_ptr);
            assert_eq!(node.parent, right_ptr);
        }
    }

    /// The BST invariant: an in-order walk yields the same node
    /// sequence before and after the rotation (a 5-node tree rotated
    /// at the root).
    #[test]
    fn rotate_left_preserves_inorder_sequence() {
        unsafe {
            let mut header = std::boxed::Box::new(test_header());
            let mut nodes: std::vec::Vec<std::boxed::Box<StringKeyTreeNode>> =
                (0..5).map(|_| std::boxed::Box::new(test_node())).collect();
            let mut ptr = |i: usize| core::ptr::addr_of_mut!(*nodes[i]);
            let header_ptr = core::ptr::addr_of_mut!(*header);

            //       2      rotate       3
            //      / \     left        / \
            //     0   3     @ 2  ->   2   4
            //        / \             / \
            //       1   4           0   1
            (*ptr(2)).left = ptr(0);
            (*ptr(2)).right = ptr(3);
            (*ptr(2)).parent = header_ptr;
            (*ptr(0)).parent = ptr(2);
            (*ptr(3)).parent = ptr(2);
            (*ptr(3)).left = ptr(1);
            (*ptr(3)).right = ptr(4);
            (*ptr(1)).parent = ptr(3);
            (*ptr(4)).parent = ptr(3);
            header.parent = ptr(2); // root
            let mut tree = std::boxed::Box::new(test_tree(header_ptr));

            fn inorder(
                node: *mut StringKeyTreeNode,
                out: &mut std::vec::Vec<*mut StringKeyTreeNode>,
            ) {
                unsafe {
                    if node.is_null() {
                        return;
                    }
                    inorder((*node).left, out);
                    out.push(node);
                    inorder((*node).right, out);
                }
            }
            let mut before = std::vec::Vec::new();
            inorder(header.parent, &mut before);

            string_key_tree_rotate_left(
                core::ptr::addr_of_mut!(*tree),
                ptr(2),
            );

            let mut after = std::vec::Vec::new();
            inorder(header.parent, &mut after);
            assert_eq!(before, after);
            assert_eq!(
                before,
                std::vec![ptr(0), ptr(2), ptr(1), ptr(3), ptr(4)]
            );
            assert_eq!(header.parent, ptr(3)); // new root
        }
    }

    // --- string_key_tree_rotate_right (@ 0x083c3228) ----------------

    /// Rotating at the root: `left` becomes the root (header.parent),
    /// `node` becomes its right child and adopts `left`'s old right
    /// subtree, re-parented.
    #[test]
    fn rotate_right_at_root() {
        unsafe {
            let mut header = std::boxed::Box::new(test_header());
            let mut node = std::boxed::Box::new(test_node());
            let mut left = std::boxed::Box::new(test_node());
            let mut adopted = std::boxed::Box::new(test_node());
            let header_ptr = core::ptr::addr_of_mut!(*header);
            let node_ptr = core::ptr::addr_of_mut!(*node);
            let left_ptr = core::ptr::addr_of_mut!(*left);
            let adopted_ptr = core::ptr::addr_of_mut!(*adopted);

            node.parent = header_ptr;
            node.left = left_ptr;
            left.parent = node_ptr;
            left.right = adopted_ptr;
            adopted.parent = left_ptr;
            header.parent = node_ptr; // root
            let mut tree = std::boxed::Box::new(test_tree(header_ptr));

            string_key_tree_rotate_right(
                core::ptr::addr_of_mut!(*tree),
                node_ptr,
            );

            assert_eq!(header.parent, left_ptr); // new root
            assert_eq!(left.parent, header_ptr);
            assert_eq!(left.right, node_ptr);
            assert_eq!(node.parent, left_ptr);
            assert_eq!(node.left, adopted_ptr); // adopted subtree
            assert_eq!(adopted.parent, node_ptr);
        }
    }

    /// Rotating under a right-child parent: the parent's right link
    /// swings to `left`; a null adopted subtree leaves node's left
    /// link null.
    #[test]
    fn rotate_right_under_right_child() {
        unsafe {
            let mut header = std::boxed::Box::new(test_header());
            let mut grand = std::boxed::Box::new(test_node());
            let mut node = std::boxed::Box::new(test_node());
            let mut left = std::boxed::Box::new(test_node());
            let header_ptr = core::ptr::addr_of_mut!(*header);
            let grand_ptr = core::ptr::addr_of_mut!(*grand);
            let node_ptr = core::ptr::addr_of_mut!(*node);
            let left_ptr = core::ptr::addr_of_mut!(*left);

            grand.parent = header_ptr;
            grand.right = node_ptr;
            node.parent = grand_ptr;
            node.left = left_ptr;
            left.parent = node_ptr; // left.right null: nothing adopted
            header.parent = grand_ptr; // root is the grandparent
            let mut tree = std::boxed::Box::new(test_tree(header_ptr));

            string_key_tree_rotate_right(
                core::ptr::addr_of_mut!(*tree),
                node_ptr,
            );

            assert_eq!(header.parent, grand_ptr); // root unchanged
            assert_eq!(grand.right, left_ptr); // took node's place
            assert_eq!(left.parent, grand_ptr);
            assert_eq!(left.right, node_ptr);
            assert_eq!(node.parent, left_ptr);
            assert_eq!(node.left, core::ptr::null_mut());
        }
    }

    /// Rotating under a left-child parent: the parent's left link
    /// swings to `left`.
    #[test]
    fn rotate_right_under_left_child() {
        unsafe {
            let mut header = std::boxed::Box::new(test_header());
            let mut grand = std::boxed::Box::new(test_node());
            let mut node = std::boxed::Box::new(test_node());
            let mut left = std::boxed::Box::new(test_node());
            let header_ptr = core::ptr::addr_of_mut!(*header);
            let grand_ptr = core::ptr::addr_of_mut!(*grand);
            let node_ptr = core::ptr::addr_of_mut!(*node);
            let left_ptr = core::ptr::addr_of_mut!(*left);

            grand.parent = header_ptr;
            grand.left = node_ptr;
            node.parent = grand_ptr;
            node.left = left_ptr;
            left.parent = node_ptr;
            header.parent = grand_ptr;
            let mut tree = std::boxed::Box::new(test_tree(header_ptr));

            string_key_tree_rotate_right(
                core::ptr::addr_of_mut!(*tree),
                node_ptr,
            );

            assert_eq!(grand.left, left_ptr); // took node's place
            assert_eq!(left.parent, grand_ptr);
            assert_eq!(left.right, node_ptr);
            assert_eq!(node.parent, left_ptr);
        }
    }

    /// The BST invariant: an in-order walk yields the same node
    /// sequence before and after the rotation (a 5-node tree rotated
    /// at the root).
    #[test]
    fn rotate_right_preserves_inorder_sequence() {
        unsafe {
            let mut header = std::boxed::Box::new(test_header());
            let mut nodes: std::vec::Vec<std::boxed::Box<StringKeyTreeNode>> =
                (0..5).map(|_| std::boxed::Box::new(test_node())).collect();
            let mut ptr = |i: usize| core::ptr::addr_of_mut!(*nodes[i]);
            let header_ptr = core::ptr::addr_of_mut!(*header);

            //         2     rotate      0
            //        / \     right     / \
            //       0   4    @ 2  ->  1   2
            //      / \                   / \
            //     1   3                 3   4
            (*ptr(2)).left = ptr(0);
            (*ptr(2)).right = ptr(4);
            (*ptr(2)).parent = header_ptr;
            (*ptr(4)).parent = ptr(2);
            (*ptr(0)).parent = ptr(2);
            (*ptr(0)).left = ptr(1);
            (*ptr(0)).right = ptr(3);
            (*ptr(1)).parent = ptr(0);
            (*ptr(3)).parent = ptr(0);
            header.parent = ptr(2); // root
            let mut tree = std::boxed::Box::new(test_tree(header_ptr));

            fn inorder(
                node: *mut StringKeyTreeNode,
                out: &mut std::vec::Vec<*mut StringKeyTreeNode>,
            ) {
                unsafe {
                    if node.is_null() {
                        return;
                    }
                    inorder((*node).left, out);
                    out.push(node);
                    inorder((*node).right, out);
                }
            }
            let mut before = std::vec::Vec::new();
            inorder(header.parent, &mut before);

            string_key_tree_rotate_right(
                core::ptr::addr_of_mut!(*tree),
                ptr(2),
            );

            let mut after = std::vec::Vec::new();
            inorder(header.parent, &mut after);
            assert_eq!(before, after);
            assert_eq!(
                before,
                std::vec![ptr(1), ptr(0), ptr(3), ptr(2), ptr(4)]
            );
            assert_eq!(header.parent, ptr(0)); // new root
        }
    }

    // --- string_key_tree_allocate_node (@ 0x083c311c) -----------------

    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Bump arena backing the heap-ops `alloc` slot for the pool
    /// tests: the real heap core is not exercised on the host, and the
    /// shared mock in heap/veneers hands out a fixed fake address that
    /// cannot be written (the byte-keyed pool-test pattern in
    /// cxx/byte_key_map.rs).
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
    fn fresh_pool() -> StringKeyNodePool {
        StringKeyNodePool {
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
            let node_size = core::mem::size_of::<StringKeyTreeNode>();
            let chunk_size = core::mem::size_of::<StringKeyPoolChunk>();
            let mut pool = fresh_pool();
            let pool_ptr = core::ptr::addr_of_mut!(pool);

            let node = string_key_tree_allocate_node(pool_ptr.cast::<StringKeyMap>());

            assert_eq!(alloc_sizes(), [chunk_size, 0x20 * node_size]);
            let chunk = pool.chunk_head;
            assert!(!chunk.is_null());
            assert_eq!((*chunk).prev, core::ptr::null_mut());
            assert_eq!((*chunk).capacity, 0x20);
            let arena = (*chunk).arena;
            assert_eq!(node, arena.cast::<StringKeyTreeNode>());
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
            let node_size = core::mem::size_of::<StringKeyTreeNode>();
            let chunk_size = core::mem::size_of::<StringKeyPoolChunk>();
            let mut pool = fresh_pool();
            let pool_ptr = core::ptr::addr_of_mut!(pool);
            let map = pool_ptr.cast::<StringKeyMap>();

            let first_chunk;
            let first_arena;
            let first = string_key_tree_allocate_node(map);
            first_chunk = pool.chunk_head;
            first_arena = (*first_chunk).arena;
            assert_eq!(first, first_arena.cast());
            for i in 1..0x20usize {
                let node = string_key_tree_allocate_node(map);
                assert_eq!(node, first_arena.add(i * node_size).cast());
            }
            // Header + arena so far, nothing more.
            assert_eq!(alloc_sizes(), [chunk_size, 0x20 * node_size]);

            let node = string_key_tree_allocate_node(map);
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
            let node_size = core::mem::size_of::<StringKeyTreeNode>();
            let chunk_size = core::mem::size_of::<StringKeyPoolChunk>();
            for (prev_cap, want) in [(8u32, 0x28u32), (0x100, 0x1a0)] {
                POOL_ARENA_USED = 0;
                (*core::ptr::addr_of_mut!(POOL_ALLOC_SIZES)).clear();
                let mut old_chunk = StringKeyPoolChunk {
                    prev: core::ptr::null_mut(),
                    capacity: prev_cap,
                    arena: core::ptr::null_mut(),
                };
                let mut sentinel = 0u8;
                let bump = core::ptr::addr_of_mut!(sentinel);
                let mut pool = StringKeyNodePool {
                    chunk_head: core::ptr::addr_of_mut!(old_chunk),
                    free_list: core::ptr::null_mut(),
                    bump,
                    bump_end: bump, // exhausted
                };

                let node = string_key_tree_allocate_node(
                    core::ptr::addr_of_mut!(pool).cast::<StringKeyMap>(),
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
            let mut a = test_node();
            let mut b = test_node();
            let pa = core::ptr::addr_of_mut!(a);
            let pb = core::ptr::addr_of_mut!(b);
            (*pa).right = pb; // free-list next
            (*pa).parent = pb; // garbage the pop must clear
            (*pb).parent = pa;
            let mut pool = fresh_pool();
            pool.free_list = pa;
            // The bump range reads exhausted (null == null) but must
            // never be reached while the free list is non-empty.
            let map = core::ptr::addr_of_mut!(pool).cast::<StringKeyMap>();

            let first = string_key_tree_allocate_node(map);
            assert_eq!(first, pa);
            assert_eq!(pool.free_list, pb);
            assert_eq!((*pa).color, 0);
            assert_eq!((*pa).parent, core::ptr::null_mut());
            assert_eq!((*pa).left, core::ptr::null_mut());
            assert_eq!((*pa).right, core::ptr::null_mut());
            assert!(alloc_sizes().is_empty(), "no heap traffic on a pop");

            let second = string_key_tree_allocate_node(map);
            assert_eq!(second, pb);
            assert_eq!(pool.free_list, core::ptr::null_mut());
            assert_eq!((*pb).color, 0);
            assert_eq!((*pb).parent, core::ptr::null_mut());
            assert!(alloc_sizes().is_empty());
        }
    }
}
