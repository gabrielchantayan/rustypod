//! Find-or-insert on a red-black-tree map keyed by a COW `basic_string` —
//! the `map<string, V>::operator[]` shape the application layer uses to
//! fetch the mapped value word for a string key (40 `bl` call sites).
//!
//! - [`string_map_lookup_or_insert`] — original: `FUN_083db4c4` @
//!   0x083db4c4 (76 bytes; 40 `bl` call sites, the only copy).
//! - [`string_key_tree_rotate_left`] — original: `FUN_083c31d4` @
//!   0x083c31d4 (84 bytes; `_Rb_tree_rotate_left`, the rebalance
//!   rotation of `_M_insert` @ 0x083c3408).
//! - [`string_key_tree_rotate_right`] — original: `FUN_083c3228` @
//!   0x083c3228 (84 bytes; `_Rb_tree_rotate_right`, the mirror
//!   rotation).
//! - [`string_key_tree_allocate_node`] — original: `FUN_083c311c` @
//!   0x083c311c (184 bytes; the node pool allocator `_M_insert` @
//!   0x083c3408 carves fresh 0x18-byte nodes through).
//! - [`string_key_tree_insert_node`] — original: `FUN_083c3408` @
//!   0x083c3408 (476 bytes; libstdc++ `_Rb_tree::_M_insert` for the
//!   string-keyed map family — the node link + rebalance the
//!   insert-unique @ 0x083c327c calls, built on the three pieces
//!   above).
//! - [`string_key_tree_insert_unique`] — original: `FUN_083c327c` @
//!   0x083c327c (396 bytes; libstdc++ `_Rb_tree::_M_insert_unique` —
//!   the find-or-insert walk the lookup dispatches to, built on
//!   `_M_insert` above).
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
//! Contract of the tree operation @ 0x083c327c — now ported below as
//! [`string_key_tree_insert_unique`], the shipped default of the
//! [`STRING_KEY_MAP_OPS`] dispatch slot (house pattern — see
//! `cxx/pair_header.rs` and `cxx/byte_key_map.rs`):
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
//! The body (396 bytes) is libstdc++'s `_Rb_tree::_M_insert_unique`,
//! the same shape as its ported byte-keyed twin @ 0x083b867c
//! (`byte_key_tree_insert_unique` in `cxx/byte_key_map.rs`) — ported
//! below as [`string_key_tree_insert_unique`]: descend from the root comparing keys through
//! the string comparator @ 0x083d74f4 (the ported `cxx_string_less`;
//! nonzero -> descend left at +8, else right at +0xc), remember the
//! last node, then — via the iterator-equality helper @ 0x083cf818
//! against the leftmost header child and an inline predecessor walk —
//! either return the existing node with the flag clear or link a fresh
//! node through `_M_insert` @ 0x083c3408 — ported below as
//! [`string_key_tree_insert_node`] — (which allocates a node @
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
//!   shipped default is the port [`string_key_tree_insert_unique`] in
//!   this module (the pre-port fail-closed stub is retained for the
//!   host tests); the lookup's tests install recording mocks through
//!   the slot. The tree insert in turn calls the ported `_M_insert`
//!   [`string_key_tree_insert_node`] directly (no slot, unlike the
//!   byte-keyed family), which allocates through
//!   [`STRING_KEY_ALLOC_OPS`] (shipped default: the ported pool
//!   allocator [`string_key_tree_allocate_node`]) — with the whole
//!   chain at its shipped defaults an insertion really links a node.
//! - The original spills the result's node word to the stack across the
//!   release call (`str r0,[sp,#0]` / `ldr r0,[sp,#0]`); a Rust local
//!   serves the same purpose.
//! - The final `node + 0x14` is a wrapping add (the original's plain
//!   `add r0, r0, #0x14`); with a real node installed the value is
//!   identical.

use crate::cxx::string::{
    cxx_string_copy_ctor, cxx_string_less, cxx_string_release,
};

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

/// Indirect dispatch for the tree insert-unique operation @
/// 0x083c327c, now ported as [`string_key_tree_insert_unique`] below —
/// the shipped default of the slot (the `PairHeaderOps` precedent in
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

/// Default stub from before 0x083c327c was ported: no tree wired, so
/// report "not found, not inserted" with a null node — the lookup then
/// returns 0x14 (null + 0x14), an obviously invalid value pointer. The
/// shipped default is now the port below; retained for the host tests
/// (a null node can never come out of the real operation — the header
/// node always exists).
#[allow(dead_code)] // test-only since 0x083c327c was ported
unsafe extern "C" fn missing_insert_unique(
    result: *mut StringKeyInsertResult,
    _map: *mut StringKeyMap,
    _key: *const StringKeyPair,
) {
    (*result).node = core::ptr::null_mut();
    (*result).inserted = 0;
}

/// The active tree-operation slot. The shipped default is the port
/// [`string_key_tree_insert_unique`] below; host tests install
/// recording mocks (and the documented stub above) through the slot.
/// Written once at init on target; tests serialize access.
pub static mut STRING_KEY_MAP_OPS: StringKeyMapOps = StringKeyMapOps {
    insert_unique: string_key_tree_insert_unique,
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
/// (node word at result+0, flag byte at result+4); the shipped default
/// is the port below, which — with the whole slot chain at its shipped
/// defaults — inserts through the ported `_M_insert` and pool
/// allocator. (Only a test-installed stub reports a null node; the
/// returned pointer is then 0x14 and must not be dereferenced.)
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
// The tree insert-unique operation itself (@ 0x083c327c).
// ---------------------------------------------------------------------------

/// Iterator decrement (predecessor) — the walk the original emits
/// inline at 0x083c3368-0x083c33c4 (old libstdc++ `_Rb_tree_decrement`;
/// the iterator-equality helper @ 0x083cf818 is a one-word compare,
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
    mut node: *mut StringKeyTreeNode,
) -> *mut StringKeyTreeNode {
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

/// Links a fresh node for `key` under `parent` through the ported
/// `_M_insert` [`string_key_tree_insert_node`] and reports it flagged
/// as inserted — the original's two `bl 0x083c3408` sites (the shared
/// multimap / not-found tail @ 0x083c32f8 and the begin() insert @
/// 0x083c3350), each passing insert_position = 0 (r2 = r4, the null
/// child the descent stopped at).
#[inline(always)]
unsafe fn link_fresh_node(
    result: *mut StringKeyInsertResult,
    map: *mut StringKeyMap,
    parent: *mut StringKeyTreeNode,
    key: *const StringKeyPair,
) {
    let mut fresh: *mut u8 = core::ptr::null_mut();
    string_key_tree_insert_node(
        &mut fresh,
        map,
        core::ptr::null_mut(),
        parent.cast::<u8>(),
        key,
    );
    (*result).node = fresh;
    (*result).inserted = 1;
}

/// string_key_tree_insert_unique — original: `FUN_083c327c` @
/// 0x083c327c (396 bytes; called from `string_map_lookup_or_insert` @
/// 0x083db4c4 and its siblings through the [`STRING_KEY_MAP_OPS`] slot,
/// whose shipped default is this port).
///
/// libstdc++ `_Rb_tree::_M_insert_unique` for the string-keyed map
/// family — the twin of the ported byte-keyed insert-unique @
/// 0x083b867c
/// ([`byte_key_tree_insert_unique`](crate::cxx::byte_key_map)),
/// differing only in the comparator (the string less @ 0x083d74f4
/// instead of an inlined byte compare). Descend from the root
/// (`header->parent`; the header node pointer is at map+0x10) comparing
/// the new pair's key string against each node's key at node+0x10
/// through `cxx_string_less` — less-than goes left (+8), else right
/// (+0xc) — and remember the last node (`parent`) and the last
/// direction. With the multi-insert byte at map+0x18 clear (map
/// semantics): if the last step went left, a `position == header->left`
/// (begin) test decides an immediate insert, else `position` becomes
/// its in-order predecessor; the candidate's key is then compared
/// against the new key — an existing key (`!(pos_key < new_key)`)
/// returns the existing node with the inserted flag 0, otherwise a
/// fresh node is linked under `parent` via `_M_insert` @ 0x083c3408 —
/// the ported [`string_key_tree_insert_node`] — and returned flagged 1.
/// With the multi-insert byte set (multimap semantics) the uniqueness
/// test is skipped and every call links a fresh node.
///
/// The result contract (see the module header): node pointer at
/// `result + 0`, inserted-flag byte at `result + 4`.
///
/// Deviations:
/// - The string comparator @ 0x083d74f4 (the ported `cxx_string_less`)
///   is reached through the `#[inline(never)]` [`pair_string_less`]
///   front-end to preserve the original's `bl` boundaries (the
///   `pool_operator_new` rationale in `cxx/byte_key_map.rs`); the
///   iterator-equality helper @ 0x083cf818 (a one-word compare of the
///   two iterator words) is inlined, like the byte-keyed twin's
///   0x083cf740.
/// - The original's not-found insert shares the multimap insert tail
///   (`bne 0x083c32e4` into the `bl 0x083c3408` @ 0x083c32f8) rather
///   than having its own call site; the port expresses all three
///   inserts through [`link_fresh_node`] (LLVM keeps three call
///   sites — same calls, different tail sharing).
/// - The original passes the key pair to `_M_insert` as a fifth
///   argument on the stack (ARM AAPCS r0-r3 + stack); the ported
///   [`string_key_tree_insert_node`] takes it as an ordinary fifth
///   parameter.
/// - The original zeroes two dead stack scratch words per descent step
///   (`str r10,[sp,#0xc]/[sp,#0x10]` inside the loop) and two more
///   before the final compare (`[sp,#0x1c]/[sp,#0x10]`) — dead scratch
///   stores, dropped here (the byte-keyed twin's deviation).
///
/// # Safety
/// `result` must point at 8 writable bytes, `map` at a live container
/// matching the scouted [`StringKeyTree`] layout (module header), and
/// `key` at a readable 8-byte pair whose string word is a live
/// `basic_string` object. The `_M_insert` port's `allocate_node` slot
/// must honour the 0x083c311c contract (fresh node: color 0, links
/// null) or return null to abort — a null fresh node then propagates
/// to `result + 0` with the flag set, like the byte-keyed twin.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_key_tree_insert_unique(
    result: *mut StringKeyInsertResult,
    map: *mut StringKeyMap,
    key: *const StringKeyPair,
) {
    let tree = map.cast::<StringKeyTree>();
    let comparator = core::ptr::addr_of!((*tree).comparator);
    let header = (*tree).header;
    let mut node = (*header).parent;
    let mut parent = header;
    let mut went_left = true;
    while !node.is_null() {
        went_left = pair_string_less(
            comparator,
            core::ptr::addr_of!((*key).key),
            core::ptr::addr_of!((*node).key.key),
        ) != 0;
        parent = node;
        node = if went_left { (*node).left } else { (*node).right };
    }

    if (*tree).multi_insert == 0 {
        let mut position = parent;
        if went_left {
            // header.left is the leftmost node (begin()); the original
            // compares the two iterator words through 0x083cf818.
            if position == (*header).left {
                link_fresh_node(result, map, parent, key);
                return;
            }
            position = rb_tree_predecessor(position);
        }
        if pair_string_less(
            comparator,
            core::ptr::addr_of!((*position).key.key),
            core::ptr::addr_of!((*key).key),
        ) != 0 {
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

/// The container as the tree operations read it: the header node
/// pointer at +0x10 (header.parent = root, header.left = leftmost,
/// header.right = rightmost), the node count at +0x14 (written by
/// `_M_insert`, not read here) and the comparator object at +0x19
/// (only its address is passed to `cxx_string_less`, which ignores
/// it). The first 0x10 bytes are the node pool state the ported
/// allocator [`string_key_tree_allocate_node`] owns — see
/// [`StringKeyNodePool`]. Sized off that struct so the fields stay
/// disjoint on a 64-bit host (the pool's pointers widen past 0x10
/// there); exactly 0x10 on the 32-bit target, where the layout checks
/// below pin `header` at +0x10 (the `ByteKeyTree` precedent in
/// `cxx/byte_key_map.rs`).
#[repr(C)]
pub struct StringKeyTree {
    /// +0..+0x10: the node pool state [`StringKeyNodePool`].
    pub _opaque: [u8; core::mem::size_of::<StringKeyNodePool>()],
    /// +0x10: the header node.
    pub header: *mut StringKeyTreeNode,
    /// +0x14: live node count.
    pub node_count: u32,
    /// +0x18: multi-insert flag byte (nonzero = multimap semantics;
    /// read by the ported insert-unique @ 0x083c327c, never by
    /// `_M_insert`).
    pub multi_insert: u8,
    /// +0x19: key-comparator object (stateless `less<string>`; only
    /// its address is passed to `cxx_string_less`, which ignores it).
    pub comparator: u8,
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
    const _: [u8; 0x14] = [0; core::mem::offset_of!(StringKeyTree, node_count)];
    const _: [u8; 0x18] = [0; core::mem::offset_of!(StringKeyTree, multi_insert)];
    const _: [u8; 0x19] = [0; core::mem::offset_of!(StringKeyTree, comparator)];
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
/// ported `_M_insert`): called by the ported
/// [`string_key_tree_insert_node`] below; the export also keeps the
/// symbol in the staticlib for match.py review.
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
/// Exported `pub` for the same reason as rotate_left: called by the
/// ported [`string_key_tree_insert_node`] below; the export also keeps
/// the symbol in the staticlib for match.py review.
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
/// Exported `pub` for the same reason as the rotations above; the
/// ported [`string_key_tree_insert_node`] below calls it through the
/// [`STRING_KEY_ALLOC_OPS`] slot (the `BYTE_KEY_ALLOC_OPS` precedent),
/// whose shipped default is this port.
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

// ---------------------------------------------------------------------------
// The node linker `_M_insert` itself (@ 0x083c3408).
// ---------------------------------------------------------------------------

/// Indirect dispatch for the tree's node allocator @ 0x083c311c,
/// introduced now that its caller `_M_insert` @ 0x083c3408 is ported
/// (the `BYTE_KEY_ALLOC_OPS` precedent in `cxx/byte_key_map.rs`; the
/// allocator's own port note anticipated the slot). The shipped
/// default is the ported pool allocator
/// [`string_key_tree_allocate_node`].
#[derive(Clone, Copy)]
pub struct StringKeyAllocOps {
    /// Node allocator @ 0x083c311c(map) -> node: hands out a fresh
    /// 0x18-byte tree node with the color byte at +0 set to 0 (red),
    /// parent/left/right at +4/+8/+0xc nulled, and the key pair at
    /// +0x10 uninitialised (the caller copy-constructs it). Never
    /// returns null in the original — a failed `operator new` throws
    /// (abort path @ 0x08266abc), so `_M_insert` has no null check.
    pub allocate_node:
        unsafe extern "C" fn(map: *mut StringKeyMap) -> *mut StringKeyTreeNode,
}

/// Stub for the host tests: report null — the ported `_M_insert` then
/// writes a null fresh node at its result and returns (a documented
/// deviation; the original cannot fail here).
#[allow(dead_code)] // test-only
unsafe extern "C" fn missing_allocate_node(
    _map: *mut StringKeyMap,
) -> *mut StringKeyTreeNode {
    core::ptr::null_mut()
}

/// The active node-allocator slot. The shipped default is the port
/// [`string_key_tree_allocate_node`]; host tests install arena mocks
/// (and the documented stub above) through the slot. Written once at
/// init on target; tests serialize access.
pub static mut STRING_KEY_ALLOC_OPS: StringKeyAllocOps = StringKeyAllocOps {
    allocate_node: string_key_tree_allocate_node,
};

/// `#[inline(never)]` front-end for `cxx_string_less` @ 0x083d74f4:
/// the original reaches it by `bl` for the link-direction compare, and
/// letting LLVM inline the memcmp/length body into `_M_insert` destroys
/// the structural match (the `pool_operator_new` rationale in
/// `cxx/byte_key_map.rs`).
#[inline(never)]
fn pair_string_less(
    comparator: *const u8,
    a: *const *mut u8,
    b: *const *mut u8,
) -> u32 {
    unsafe { cxx_string_less(comparator, a, b) }
}

/// string_key_tree_insert_node — original: `FUN_083c3408` @ 0x083c3408
/// (476 bytes; libstdc++ `_Rb_tree::_M_insert` for the string-keyed map
/// family, the node-link + rebalance path its caller — the ported
/// [`string_key_tree_insert_unique`] @ 0x083c327c — reaches by `bl` @
/// 0x083c32f8 and 0x083c3350, passing the key pair as a fifth argument
/// on the stack).
///
/// Allocates a fresh 0x18-byte node through the pool allocator @
/// 0x083c311c (dispatched via [`STRING_KEY_ALLOC_OPS`], shipped default
/// the port [`string_key_tree_allocate_node`]; it initialises
/// color = 0/red and nulls the three links), copy-constructs the
/// 8-byte pair into node+0x10 — the key string via
/// `cxx_string_copy_ctor` @ 0x083d8c30 (the COW share, a real `bl`
/// through [`pair_string_copy_ctor`]) plus the one mapped-value word —
/// and bumps the node count at map+0x14. Linking: when `parent` is the
/// header (map+0x10) or `insert_position` is nonzero, the node becomes
/// `parent`'s left child (+8) — a header parent also takes it as root
/// (header+4) and rightmost (header+0xc), otherwise the leftmost
/// pointer (header+8) follows when `parent` was the leftmost.
/// Otherwise the pair's key is compared against `parent`'s through the
/// string comparator @ 0x083d74f4 (reached with the comparator object
/// at map+0x19 in r0, like the original): less-than links left (same
/// leftmost follow-up), else links right (+0xc) with the rightmost
/// pointer following when `parent` was the rightmost. The node is then
/// re-parented to `parent` and rebalanced exactly like
/// `_Rb_tree_rebalance_for_insert`: while the node is not the root and
/// its parent is red (color 0), a red uncle recolors parent/uncle
/// black (1) and grandparent red (0) and ascends two levels; a
/// black/absent uncle rotates — inner child first rotates the parent
/// down (left case: rotate_left @ 0x083c31d4 on the parent, then
/// rotate_right @ 0x083c3228 on the grandparent; mirrored on the
/// right) — then parent black, grandparent red. The loop exits with
/// the root recolored black and the new node written at `result + 0`.
///
/// Deviations:
/// - The allocator never returns null in the original (`operator new`
///   throws, abort @ 0x08266abc), so the original has no null check;
///   with the test-only [`STRING_KEY_ALLOC_OPS`] stub this port writes
///   a null fresh node at `result + 0` and returns without touching
///   the tree (the stub's documented contract, the byte-keyed twin's
///   shape).
/// - The placement-new guard `node + 0x10 != null` around the pair
///   copy (`adds r0,r0,#0x10; beq`) can only fail for a node at
///   0xfffffff0 and is dropped, like the byte-keyed twin.
/// - The original takes the key pair as a fifth argument on the stack
///   (ARM AAPCS r0-r3 + stack); the port takes it as an ordinary fifth
///   parameter. The original also passes dead extra register arguments
///   to one rotation call (r2-r5 garbage @ 0x083c3584); dropped.
/// - The string comparator is a real function, so unlike the byte-
///   keyed twin (which inlines a one-instruction byte compare) it is
///   reached through the `#[inline(never)]` [`pair_string_less`]
///   front-end to preserve the original's `bl` boundary; the stateless
///   comparator object's address (map+0x19) is passed along and
///   ignored, exactly as the original passes it.
/// - The original zeroes two dead stack scratch words before the
///   comparator call (`str r7,[sp,#0]/[sp,#4]` @ 0x083c3474-78);
///   dropped.
///
/// # Safety
/// `result` must point at a writable word, `map` at a live container
/// matching the scouted [`StringKeyTree`] layout, `parent` at a live
/// node (or the header), and `key` at a readable 8-byte pair whose
/// string word is a live `basic_string` object. The installed
/// `allocate_node` must honour the 0x083c311c contract (fresh node:
/// color 0, links null) or return null to abort.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_key_tree_insert_node(
    result: *mut *mut u8,
    map: *mut StringKeyMap,
    insert_position: *mut u8,
    parent: *mut u8,
    key: *const StringKeyPair,
) {
    let tree = map.cast::<StringKeyTree>();
    // Reads the fn-pointer field directly rather than through a
    // whole-table read (the timer_schedule_shim gotcha).
    let allocate_node =
        core::ptr::addr_of!(STRING_KEY_ALLOC_OPS.allocate_node).read_volatile();
    let node = allocate_node(map);
    if node.is_null() {
        // Unreachable in the original (operator new throws); only the
        // documented stub lands here.
        result.write(core::ptr::null_mut());
        return;
    }
    let fresh = node;
    // Copy-construct the pair: COW-share the key string, then the one
    // mapped-value word.
    pair_string_copy_ctor(
        core::ptr::addr_of_mut!((*node).key.key),
        core::ptr::addr_of!((*key).key),
    );
    (*node).key.value = (*key).value;
    (*tree).node_count = (*tree).node_count.wrapping_add(1);

    let header = (*tree).header;
    let parent_node = parent.cast::<StringKeyTreeNode>();
    let mut link_left = parent_node == header || !insert_position.is_null();
    if !link_left {
        link_left = pair_string_less(
            core::ptr::addr_of!((*tree).comparator),
            core::ptr::addr_of!((*key).key),
            core::ptr::addr_of!((*parent_node).key.key),
        ) != 0;
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
                    string_key_tree_rotate_left(tree, parent);
                    node = parent;
                }
                let parent = (*node).parent;
                (*parent).color = 1;
                let grandparent = (*parent).parent;
                (*grandparent).color = 0;
                string_key_tree_rotate_right(tree, grandparent);
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
                    string_key_tree_rotate_right(tree, parent);
                    node = parent;
                }
                let parent = (*node).parent;
                (*parent).color = 1;
                let grandparent = (*parent).parent;
                (*grandparent).color = 0;
                string_key_tree_rotate_left(tree, grandparent);
            }
        }
    }
    (*(*header).parent).color = 1;
    result.write(fresh.cast::<u8>());
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

    /// A container wired to `header`, node count 0.
    fn test_tree(header: *mut StringKeyTreeNode) -> StringKeyTree {
        StringKeyTree {
            _opaque: [0; core::mem::size_of::<StringKeyNodePool>()],
            header,
            node_count: 0,
            multi_insert: 0,
            comparator: 0,
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

    // --- string_key_tree_insert_node (@ 0x083c3408) -------------------

    struct AllocOpsGuard;

    impl AllocOpsGuard {
        fn install(ops: StringKeyAllocOps) -> Self {
            unsafe {
                core::ptr::addr_of_mut!(STRING_KEY_ALLOC_OPS).write_volatile(ops);
            }
            AllocOpsGuard
        }
    }

    impl Drop for AllocOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(STRING_KEY_ALLOC_OPS).write_volatile(
                    StringKeyAllocOps {
                        allocate_node: missing_allocate_node,
                    },
                );
            }
        }
    }

    /// Key-string storage for the insert tests: a leaked COW string
    /// "a<byte>" standing on its own rep (refcount 0 = sole owner), so
    /// ordering follows the second byte. The copy constructor shares
    /// the rep, bumping the refcount per linked node; nothing ever
    /// releases, which is fine for test-owned (leaked) storage.
    fn key_string(second: u8) -> *mut u8 {
        let fake = std::boxed::Box::new(FakeString {
            rep: StringRep {
                refcount: 0,
                capacity: 7,
                length: 2,
            },
            data: [b'a', second, 0, 0, 0, 0, 0, 0],
        });
        let raw = std::boxed::Box::into_raw(fake);
        unsafe { core::ptr::addr_of_mut!((*raw).data).cast::<u8>() }
    }

    /// Lexicographic string less-than through the ported comparator.
    unsafe fn key_less(a: *mut u8, b: *mut u8) -> bool {
        cxx_string_less(core::ptr::null(), &a, &b) != 0
    }

    /// Three-way string order for sorting expected key sequences.
    fn string_order(a: &*mut u8, b: &*mut u8) -> core::cmp::Ordering {
        unsafe {
            if key_less(*a, *b) {
                core::cmp::Ordering::Less
            } else if key_less(*b, *a) {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        }
    }

    /// Arena backing the mock allocator; boxes stay put while a test's
    /// tree is live and are freed by `free_arena`.
    static mut ARENA: Vec<*mut StringKeyTreeNode> = Vec::new();

    /// Mock for the pool allocator @ 0x083c311c: hands out a fresh
    /// node honouring its contract — color 0 (red), links null, pair
    /// uninitialised (zeroed here; nothing reads it before the copy).
    unsafe extern "C" fn arena_allocate_node(
        _map: *mut StringKeyMap,
    ) -> *mut StringKeyTreeNode {
        let node = std::boxed::Box::into_raw(std::boxed::Box::new(test_node()));
        (*node).color = 0; // red
        (*core::ptr::addr_of_mut!(ARENA)).push(node);
        node
    }

    fn install_arena_allocator() -> AllocOpsGuard {
        AllocOpsGuard::install(StringKeyAllocOps {
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

    /// Red-black + BST + count validator for a tree under `header`:
    /// BST ordering by strict string-key bounds (through the ported
    /// comparator), no red node (0) with a red child, equal black
    /// height on every null path, and exactly `expected` nodes.
    /// Returns the sorted in-order key pointers.
    unsafe fn validate_tree(
        header: *mut StringKeyTreeNode,
        expected: usize,
    ) -> Vec<*mut u8> {
        fn walk(
            node: *mut StringKeyTreeNode,
            lo: Option<*mut u8>,
            hi: Option<*mut u8>,
            keys: &mut Vec<*mut u8>,
            count: &mut usize,
        ) -> usize {
            if node.is_null() {
                return 1; // null leaves are black
            }
            unsafe {
                let key = (*node).key.key;
                if let Some(lo) = lo {
                    assert!(key_less(lo, key), "BST lower bound violated");
                }
                if let Some(hi) = hi {
                    assert!(key_less(key, hi), "BST upper bound violated");
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

    /// The header's leftmost/rightmost pointers track the extremes
    /// (`keys` is the sorted in-order sequence).
    unsafe fn validate_extremes(
        header: *mut StringKeyTreeNode,
        keys: &[*mut u8],
    ) {
        let min = *keys.first().unwrap();
        let max = *keys.last().unwrap();
        assert_eq!((*(*header).left).key.key, min, "leftmost");
        assert_eq!((*(*header).right).key.key, max, "rightmost");
    }

    /// An empty tree: root null, leftmost and rightmost pointing at
    /// the header itself (the libstdc++ empty shape).
    unsafe fn make_empty_tree(
        header: *mut StringKeyTreeNode,
    ) -> StringKeyTree {
        (*header).left = header;
        (*header).right = header;
        test_tree(header)
    }

    /// Calls the port directly (the `_M_insert` contract): fresh node
    /// pointer at result+0. The pair carries the key string and a
    /// zeroed value word, like the lookup builds.
    unsafe fn run_insert_node(
        tree: *mut StringKeyTree,
        insert_position: *mut u8,
        parent: *mut StringKeyTreeNode,
        key: *mut u8,
    ) -> *mut u8 {
        let pair = StringKeyPair { key, value: 0 };
        let mut fresh: *mut u8 = core::ptr::null_mut();
        string_key_tree_insert_node(
            &mut fresh,
            tree.cast::<StringKeyMap>(),
            insert_position,
            parent.cast::<u8>(),
            &pair,
        );
        fresh
    }

    /// With the allocator stub the port reports a null fresh node and
    /// leaves the tree completely untouched.
    #[test]
    fn insert_node_alloc_stub_reports_null_and_untouched_tree() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = AllocOpsGuard::install(StringKeyAllocOps {
            allocate_node: missing_allocate_node,
        });
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let fresh =
                run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, key_string(5));
            assert_eq!(fresh, core::ptr::null_mut());
            assert_eq!((*header_ptr).parent, core::ptr::null_mut());
            assert_eq!(tree.node_count, 0);
        }
    }

    /// First node of an empty tree (parent == header): linked as root,
    /// leftmost and rightmost, recolored black, count bumped, result
    /// carries the node — and the pair is copy-constructed: the key
    /// string word is the COW share (same data pointer, refcount
    /// bumped) and the value word is copied.
    #[test]
    fn insert_node_first_insert_becomes_black_root() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let key = key_string(5);
            let pair = StringKeyPair {
                key,
                value: 0x5a5a5a5a,
            };
            let mut fresh: *mut u8 = core::ptr::null_mut();
            string_key_tree_insert_node(
                &mut fresh,
                tree_ptr.cast::<StringKeyMap>(),
                core::ptr::null_mut(),
                header_ptr.cast::<u8>(),
                &pair,
            );
            assert!(!fresh.is_null());
            let node = fresh.cast::<StringKeyTreeNode>();
            assert_eq!((*header_ptr).parent, node); // root
            assert_eq!((*header_ptr).left, node); // leftmost
            assert_eq!((*header_ptr).right, node); // rightmost
            assert_eq!((*node).parent, header_ptr);
            assert_eq!((*node).color, 1); // root recolored black
            // The pair copy: COW share plus the value word.
            assert_eq!((*node).key.key, key);
            assert_eq!((*node).key.value, 0x5a5a5a5a);
            let rep = (key as *mut StringRep).sub(1);
            assert_eq!((*rep).refcount, 1); // the share bumped it
            assert_eq!(tree.node_count, 1);
            assert_eq!(validate_tree(header_ptr, 1), [key]);
            validate_extremes(header_ptr, &[key]);
        }
        free_arena();
    }

    /// Comparator-driven left link (insert_position == 0, key less
    /// than parent's): the node becomes the parent's left child and
    /// the leftmost pointer follows the old leftmost.
    #[test]
    fn insert_node_left_link_updates_leftmost() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let k7 = key_string(7);
            let k3 = key_string(3);
            let root = run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, k7)
                .cast::<StringKeyTreeNode>();
            let fresh = run_insert_node(tree_ptr, core::ptr::null_mut(), root, k3)
                .cast::<StringKeyTreeNode>();
            assert_eq!((*root).left, fresh);
            assert_eq!((*fresh).parent, root);
            assert_eq!((*header_ptr).left, fresh); // new leftmost
            assert_eq!((*header_ptr).right, root); // rightmost unchanged
            assert_eq!(tree.node_count, 2);
            assert_eq!(validate_tree(header_ptr, 2), [k3, k7]);
            validate_extremes(header_ptr, &[k3, k7]);
        }
        free_arena();
    }

    /// Comparator-driven right link: right child plus rightmost
    /// follow-up.
    #[test]
    fn insert_node_right_link_updates_rightmost() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let k7 = key_string(7);
            let k9 = key_string(9);
            let root = run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, k7)
                .cast::<StringKeyTreeNode>();
            let fresh = run_insert_node(tree_ptr, core::ptr::null_mut(), root, k9)
                .cast::<StringKeyTreeNode>();
            assert_eq!((*root).right, fresh);
            assert_eq!((*header_ptr).right, fresh); // new rightmost
            assert_eq!((*header_ptr).left, root); // leftmost unchanged
            assert_eq!(validate_tree(header_ptr, 2), [k7, k9]);
            validate_extremes(header_ptr, &[k7, k9]);
        }
        free_arena();
    }

    /// A nonzero insert_position forces the left link even when the
    /// key compares greater than the parent's (multimap equal-key
    /// path).
    #[test]
    fn insert_node_insert_position_forces_left_link() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let k7 = key_string(7);
            let k9 = key_string(9);
            let root = run_insert_node(tree_ptr, core::ptr::null_mut(), header_ptr, k7)
                .cast::<StringKeyTreeNode>();
            let mut nonzero: u8 = 1;
            let fresh = run_insert_node(tree_ptr, &mut nonzero, root, k9)
                .cast::<StringKeyTreeNode>();
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
    fn insert_node_rebalance_keeps_red_black_invariants() {
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

                let mut inserted: Vec<*mut u8> = Vec::new();
                for (i, k) in order.iter().enumerate() {
                    let key = key_string(*k);
                    // Descend like the insert-unique caller does to
                    // find the link parent (keeps this test honest
                    // about the _M_insert contract: parent + position).
                    let mut parent = header_ptr;
                    let mut node = (*header_ptr).parent;
                    while !node.is_null() {
                        parent = node;
                        node = if key_less(key, (*node).key.key) {
                            (*node).left
                        } else {
                            (*node).right
                        };
                    }
                    let fresh =
                        run_insert_node(tree_ptr, core::ptr::null_mut(), parent, key);
                    assert!(!fresh.is_null());
                    assert_eq!(tree.node_count as usize, i + 1);
                    inserted.push(key);
                    let keys = validate_tree(header_ptr, i + 1);
                    let mut sorted = inserted.clone();
                    sorted.sort_by(string_order);
                    assert_eq!(keys, sorted);
                    validate_extremes(header_ptr, &sorted);
                }
            }
        }
        free_arena();
        assert!(unsafe { (*core::ptr::addr_of!(ARENA)).is_empty() });
    }

    // --- string_key_tree_insert_unique (@ 0x083c327c) ----------------

    /// Calls the port directly (the insert-unique contract): node
    /// pointer at result+0, inserted-flag byte at result+4. The pair
    /// carries the key string and a zeroed value word, like the lookup
    /// builds.
    unsafe fn run_insert_unique(
        tree: *mut StringKeyTree,
        key: *mut u8,
    ) -> StringKeyInsertResult {
        let pair = StringKeyPair { key, value: 0 };
        let mut result = StringKeyInsertResult {
            node: core::ptr::null_mut(),
            inserted: 0xaa,
        };
        string_key_tree_insert_unique(
            &mut result,
            tree.cast::<StringKeyMap>(),
            &pair,
        );
        result
    }

    /// The COW share count of a key string's rep (how many copies hold
    /// it — one per node the key was linked into).
    unsafe fn share_count(key: *mut u8) -> i32 {
        (*(key as *mut StringRep).sub(1)).refcount
    }

    /// Empty tree (root null, leftmost/rightmost == header): the
    /// begin() test hits immediately and the fresh node is linked under
    /// the header as root/leftmost/rightmost, flagged 1 — a real
    /// pool-node insertion through the ported `_M_insert` chain, COW
    /// share and all.
    #[test]
    fn insert_unique_empty_tree_inserts_under_header() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let key = key_string(5);
            let result = run_insert_unique(tree_ptr, key);
            assert_eq!(result.inserted, 1);
            let node = result.node.cast::<StringKeyTreeNode>();
            assert!(!node.is_null());
            assert_eq!((*header_ptr).parent, node); // root
            assert_eq!((*header_ptr).left, node); // leftmost
            assert_eq!((*header_ptr).right, node); // rightmost
            assert_eq!((*node).key.key, key); // COW share
            assert_eq!(share_count(key), 1);
            assert_eq!(tree.node_count, 1);
            assert_eq!(validate_tree(header_ptr, 1), [key]);
            validate_extremes(header_ptr, &[key]);
        }
        free_arena();
    }

    /// Single-node tree, same key: the descent goes right (equal keys
    /// are not less), the reverse compare fails too, so the existing
    /// node comes back with the flag clear — no allocation, no new COW
    /// share, count untouched.
    #[test]
    fn insert_unique_existing_key_returns_node_flag_clear() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let key = key_string(7);
            let first = run_insert_unique(tree_ptr, key);
            assert_eq!(first.inserted, 1);
            assert_eq!(share_count(key), 1);

            let second = run_insert_unique(tree_ptr, key);
            assert_eq!(second.inserted, 0);
            assert_eq!(second.node, first.node);
            assert_eq!(share_count(key), 1); // found: no new share
            assert_eq!(tree.node_count, 1);
            assert_eq!(validate_tree(header_ptr, 1), [key]);
        }
        free_arena();
    }

    /// Single-node tree, smaller key: left descent, position is the
    /// leftmost (begin) node, so the fresh node links right away under
    /// it and the leftmost pointer follows.
    #[test]
    fn insert_unique_new_minimum_inserts_at_begin() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let k7 = key_string(7);
            let k3 = key_string(3);
            let root = run_insert_unique(tree_ptr, k7)
                .node
                .cast::<StringKeyTreeNode>();
            let result = run_insert_unique(tree_ptr, k3);
            assert_eq!(result.inserted, 1);
            let fresh = result.node.cast::<StringKeyTreeNode>();
            assert_eq!((*root).left, fresh);
            assert_eq!((*header_ptr).left, fresh); // new leftmost
            assert_eq!((*header_ptr).right, root); // rightmost unchanged
            assert_eq!(validate_tree(header_ptr, 2), [k3, k7]);
            validate_extremes(header_ptr, &[k3, k7]);
        }
        free_arena();
    }

    /// Single-node tree, larger key: right descent, the candidate's
    /// key compares less than the new key, so a fresh node links under
    /// it and the rightmost pointer follows.
    #[test]
    fn insert_unique_new_maximum_inserts_after_right_descent() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let k7 = key_string(7);
            let k9 = key_string(9);
            let root = run_insert_unique(tree_ptr, k7)
                .node
                .cast::<StringKeyTreeNode>();
            let result = run_insert_unique(tree_ptr, k9);
            assert_eq!(result.inserted, 1);
            let fresh = result.node.cast::<StringKeyTreeNode>();
            assert_eq!((*root).right, fresh);
            assert_eq!((*header_ptr).right, fresh); // new rightmost
            assert_eq!((*header_ptr).left, root); // leftmost unchanged
            assert_eq!(validate_tree(header_ptr, 2), [k7, k9]);
            validate_extremes(header_ptr, &[k7, k9]);
        }
        free_arena();
    }

    /// The predecessor path, insert case: the descent ends going left
    /// at a non-leftmost node, so the begin() test fails and the inline
    /// predecessor walk runs; the predecessor's key compares less than
    /// the new key, so a fresh node links, flagged 1. Tree keys 30, 10,
    /// 20, 5 (inserted in that order): key 25 descends right of 20 and
    /// left of 30, whose predecessor is 20.
    #[test]
    fn insert_unique_left_descent_past_begin_walks_predecessor() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let keys: Vec<*mut u8> =
                [30u8, 10, 20, 5].iter().map(|&k| key_string(k)).collect();
            for &key in &keys {
                assert_eq!(run_insert_unique(tree_ptr, key).inserted, 1);
            }
            let k25 = key_string(25);
            let result = run_insert_unique(tree_ptr, k25);
            assert_eq!(result.inserted, 1);
            let fresh = result.node.cast::<StringKeyTreeNode>();
            assert_eq!((*fresh).key.key, k25);
            assert_eq!(tree.node_count, 5);
            let mut sorted = keys.clone();
            sorted.push(k25);
            sorted.sort_by(string_order);
            assert_eq!(validate_tree(header_ptr, 5), sorted);
            validate_extremes(header_ptr, &sorted);
        }
        free_arena();
    }

    /// The predecessor path, found case: same descent shape, but the
    /// new key duplicates the predecessor's key — key 20 descends right
    /// of itself (equal is not less) and left of 30, whose predecessor
    /// is 20 — so the existing node comes back with the flag clear and
    /// the tree untouched.
    #[test]
    fn insert_unique_predecessor_duplicate_returns_found() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let keys: Vec<*mut u8> =
                [30u8, 10, 20, 5].iter().map(|&k| key_string(k)).collect();
            let mut nodes: Vec<*mut u8> = Vec::new();
            for &key in &keys {
                nodes.push(run_insert_unique(tree_ptr, key).node);
            }
            let k20 = keys[2];
            let result = run_insert_unique(tree_ptr, k20);
            assert_eq!(result.inserted, 0);
            assert_eq!(result.node, nodes[2]);
            assert_eq!(share_count(k20), 1); // found: no new share
            assert_eq!(tree.node_count, 4);
            let mut sorted = keys.clone();
            sorted.sort_by(string_order);
            assert_eq!(validate_tree(header_ptr, 4), sorted);
        }
        free_arena();
    }

    /// The multi-insert byte set (multimap semantics): the uniqueness
    /// test is skipped and a duplicate key still links a fresh node,
    /// flagged 1 — count grows, the key's COW share count grows with
    /// each link.
    #[test]
    fn insert_unique_multi_insert_flag_skips_uniqueness() {
        let _lock = OPS_LOCK.lock().unwrap();
        let _guard = install_arena_allocator();
        unsafe {
            let mut header = test_header();
            let header_ptr = core::ptr::addr_of_mut!(header);
            let mut tree = make_empty_tree(header_ptr);
            tree.multi_insert = 1;
            let tree_ptr = core::ptr::addr_of_mut!(tree);

            let key = key_string(7);
            let first = run_insert_unique(tree_ptr, key);
            let second = run_insert_unique(tree_ptr, key);
            assert_eq!(first.inserted, 1);
            assert_eq!(second.inserted, 1);
            assert!(!second.node.is_null());
            assert!(second.node != first.node);
            assert_eq!(tree.node_count, 2);
            assert_eq!(share_count(key), 2); // one share per link
        }
        free_arena();
    }

    /// Behavioural parity against a reference model: three key orders
    /// over unique keys — ascending, descending, and a deterministic
    /// zigzag — each insert validated for the flag, the count and the
    /// full red-black/BST/extremes contract; then every key is
    /// re-inserted in reverse order, expecting the found path: flag
    /// clear, the very node the first pass linked, count and share
    /// counts unchanged.
    #[test]
    fn insert_unique_insert_then_find_matches_reference() {
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

                let mut keys: Vec<*mut u8> = Vec::new();
                let mut nodes: Vec<*mut u8> = Vec::new();
                for (i, k) in order.iter().enumerate() {
                    let key = key_string(*k);
                    let result = run_insert_unique(tree_ptr, key);
                    assert_eq!(result.inserted, 1, "first pass inserts");
                    assert!(!result.node.is_null());
                    assert_eq!(tree.node_count as usize, i + 1);
                    keys.push(key);
                    nodes.push(result.node);
                    let mut sorted = keys.clone();
                    sorted.sort_by(string_order);
                    assert_eq!(validate_tree(header_ptr, i + 1), sorted);
                    validate_extremes(header_ptr, &sorted);
                }
                // Second pass, reverse order: every key is found.
                for (i, &key) in keys.iter().enumerate().rev() {
                    let result = run_insert_unique(tree_ptr, key);
                    assert_eq!(result.inserted, 0, "second pass finds");
                    assert_eq!(result.node, nodes[i], "the same node");
                    assert_eq!(share_count(key), 1, "no new share");
                    assert_eq!(tree.node_count as usize, keys.len());
                }
            }
        }
        free_arena();
        assert!(unsafe { (*core::ptr::addr_of!(ARENA)).is_empty() });
    }
}
