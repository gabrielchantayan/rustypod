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
//! leaves, inlined into the port; only `_M_insert` @ 0x083b8844 (476
//! bytes, with its own allocator/rotation dependencies) is not ported
//! and rides the [`BYTE_KEY_TREE_OPS`] dispatch slot.
//!
//! Deviations:
//! - The pair's three padding bytes at +1..+4 are zeroed; the original
//!   leaves them as uninitialised stack. Nothing observes them (the
//!   comparator reads only the key byte; the node copy's pad word is
//!   never read back).
//! - 0x083b867c is dispatched through [`BYTE_KEY_MAP_OPS`], whose
//!   shipped default is the port [`byte_key_tree_insert_unique`] in
//!   this module; the find's tests still install stubs/mocks through
//!   the slot. With the default slot and the default `BYTE_KEY_TREE_OPS`
//!   stub (no node linker wired), an insertion reports a null fresh
//!   node and the find returns 0x14 — install `BYTE_KEY_TREE_OPS`
//!   before real use.
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
/// the port below, which with the default `BYTE_KEY_TREE_OPS` stub
/// reports a null fresh node on insertion — the returned pointer is
/// then 0x14 and must not be dereferenced.
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
    /// +0..+0x10: allocator/base subobject — unmodeled.
    pub _opaque: [u8; 0x10],
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

/// Indirect dispatch for the not-yet-ported node linker `_M_insert` @
/// 0x083b8844 (476 bytes; allocates a node @ 0x083b7f40, copies the
/// pair, links it under `parent` and rebalances via the rotations @
/// 0x083b8090 / 0x083b80e4). The `PairHeaderOps` precedent in
/// `cxx/pair_header.rs`.
#[derive(Clone, Copy)]
pub struct ByteKeyTreeOps {
    /// `_M_insert` @ 0x083b8844(result, map, insert_position, parent,
    /// key): links a fresh node carrying `key` under `parent` (as its
    /// left child when `insert_position` is nonzero, else by comparing
    /// the key pair against `parent`'s), rebalances, and writes the new
    /// node pointer at `result + 0`. This port always calls it with
    /// `insert_position == 0`, matching the original (r2 = the null
    /// child the descent stopped at).
    pub insert_node: unsafe extern "C" fn(
        result: *mut *mut u8,
        map: *mut ByteKeyMap,
        insert_position: *mut u8,
        parent: *mut u8,
        key: *const ByteKeyPair,
    ),
}

/// Default stub: no node linker wired, so report a null fresh node —
/// an insert then stores null at result+0 with the flag set, and the
/// find returns 0x14. On real hardware BYTE_KEY_TREE_OPS must be
/// installed (by the ported 0x083b8844) before an insertion can run.
unsafe extern "C" fn missing_insert_node(
    result: *mut *mut u8,
    _map: *mut ByteKeyMap,
    _insert_position: *mut u8,
    _parent: *mut u8,
    _key: *const ByteKeyPair,
) {
    result.write(core::ptr::null_mut());
}

/// The active node-linker slot. Defaults to the documented stub above;
/// replaced by host tests (mocks) and eventually by the ported
/// 0x083b8844. Written once at init on target; tests serialize access.
pub static mut BYTE_KEY_TREE_OPS: ByteKeyTreeOps = ByteKeyTreeOps {
    insert_node: missing_insert_node,
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
/// - `_M_insert` @ 0x083b8844 is not yet ported and is dispatched
///   through the [`BYTE_KEY_TREE_OPS`] slot (default stub reports a
///   null fresh node — see its doc).
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
            _opaque: [0; 0x10],
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

        static mut MINI_NODE: [u8; 0x30] = [0; 0x30];

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
}
